//! # smtpd
//!
//! `smtpd` is an asynchronous, extensible SMTP server library built on top of `tokio`.
//! Inspired by [smtpd](https://github.com/mhale/smtpd).
//! It provides flexible support for authentication, TLS, and custom handling
//! of SMTP commands.
//!
//! ## Features
//! - Asynchronous SMTP server using Tokio.
//! - Supports authentication mechanisms: [`AuthMach::Plain`], [`AuthMach::Login`], [`AuthMach::CramMD5`].
//! - TLS support (STARTTLS and implicit TLS) with optional `native-tls` (feature `native-tls-backend`) or `rustls` (feature `rustls-backend`) backend.
//! - Customizable handlers for AUTH, RCPT, and DATA commands via the Handler struct's [`SmtpHandler::handle_auth`], [`SmtpHandler::handle_email`], and [`SmtpHandler::handle_rcpt`] method
//! - Configurable limits for message size and recipients.
//!
//! ## Example
//! ```no_run
//! use smtpd::{async_trait, start_server, SmtpConfig, AuthMach};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), std::io::Error> {
//!     let config = SmtpConfig {
//!         bind_addr: "127.0.0.1:2525".to_string(),
//!         require_auth: true,
//!         auth_machs: vec![AuthMach::Plain, AuthMach::Login],
//!         ..Default::default()
//!     };
//!
//!     let factory = MyHandlerFactory {};
//!
//!     start_server(config, factory).await?;
//!     Ok(())
//! }
//!
//! struct MyHandler {}
//!
//! #[async_trait]
//! impl smtpd::SmtpHandler for MyHandler {
//!     async fn handle_auth(
//!         &mut self,
//!         _session: &smtpd::Session,
//!         data: smtpd::AuthData,
//!     ) -> Result<smtpd::Response, smtpd::Error> {
//!         let (username, password, _) = data.data();
//!
//!         if username == "abc" && password == "efg" {
//!             return Ok(smtpd::Response::Default);
//!         }
//!
//!         Err(smtpd::Error::Abort)
//!     }
//!
//!     async fn handle_rcpt(
//!         &mut self,
//!         _session: &smtpd::Session,
//!         to: &str,
//!     ) -> Result<smtpd::Response, smtpd::Error> {
//!         // allow recipients only from gmail
//!         if to.ends_with("gmail.com") {
//!             return Ok(smtpd::Response::Default);
//!         }
//!
//!         Err(smtpd::Error::Abort)
//!     }
//! }
//!
//! struct MyHandlerFactory;
//!
//! impl smtpd::SmtpHandlerFactory for MyHandlerFactory {
//!     type Handler = MyHandler;
//!
//!     fn new_handler(&self, _session: &smtpd::Session) -> Self::Handler {
//!         MyHandler {}
//!     }
//! }
//! ```
//!
//! ## Modules
//! - `session`: Represents a client session.
//! - `handler`: Defines traits for handling SMTP commands.
//! - `tls`: TLS configuration and provider utilities.
//! - `stream`: Connection stream abstraction with read/write helpers.
//! - `utils`: Parsing and helper functions for SMTP commands.

use std::sync::Arc;
use tokio::net::TcpListener;
use trust_dns_resolver::TokioAsyncResolver;
use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};
use trust_dns_resolver::system_conf::read_system_conf;

use crate::core::ConnectionStream;
pub use crate::core::SmtpConfig;
pub use crate::core::auth::{AuthData, AuthMach};
pub use crate::core::handler::{SmtpHandler, SmtpHandlerFactory};
pub use crate::core::response::Response;
pub use crate::core::response_error::{Error, Result};
pub use crate::core::session::Session;
use crate::core::stream::StreamController;
pub use crate::core::tls::TlsConfig;
pub use crate::core::tls::TlsMode;
#[cfg(any(feature = "native-tls-backend", feature = "rustls-backend"))]
use crate::core::tls::TlsProvider;
use crate::handler::handle_client;
pub use async_trait::async_trait;

#[cfg(feature = "native-tls-backend")]
pub use native_tls::Identity;

#[cfg(feature = "rustls-backend")]
pub use rustls::ServerConfig;

mod constants;
mod core;
mod handler;
mod utils;

/// Starts an SMTP server with the provided configuration and handler factory.
///
/// This is the recommended entry point for running the SMTP server. Internally, it constructs
/// an [`SmtpServer`] instance and begins listening for incoming connections.
///
/// # Example
///
/// ```no_run
/// use smtpd::{async_trait, start_server, SmtpConfig, AuthMach, SmtpHandler, SmtpHandlerFactory};
///
/// #[tokio::main]
/// async fn main() -> Result<(), std::io::Error> {
///     let config = SmtpConfig {
///         bind_addr: "127.0.0.1:2525".to_string(),
///         require_auth: true,
///         auth_machs: vec![AuthMach::Plain, AuthMach::Login],
///         ..Default::default()
///     };
///
///     let factory = MyHandlerFactory {};
///
///     println!("Starting SMTP server on {}", config.bind_addr);
///     start_server(config, factory).await?;
///
///     Ok(())
/// }
///
/// struct MyHandler{}
///
/// #[async_trait]
/// impl SmtpHandler for MyHandler{}
///
/// struct MyHandlerFactory{}
/// impl SmtpHandlerFactory for MyHandlerFactory {
///     type Handler = MyHandler;
///
///     fn new_handler(&self, _session: &smtpd::Session) -> Self::Handler {
///         MyHandler{}
///     }
/// }
/// ```
pub async fn start_server<T: SmtpHandlerFactory + Send + Sync + 'static>(
    config: SmtpConfig,
    handler: T,
) -> std::result::Result<(), std::io::Error> {
    let server = SmtpServer::new(config, handler);
    server.listen_and_serve().await
}

/// The core SMTP server struct.
///
/// This struct represents the foundation of the SMTP server. While it is possible to
/// construct an `SmtpServer` instance manually and call its methods directly, the recommended
/// approach is to use the [`start_server`] helper function. This function will internally
/// create the server and invoke [`SmtpServer::listen_and_serve`] for you.
pub struct SmtpServer<T: SmtpHandlerFactory + Send + Sync + 'static> {
    config: SmtpConfig,
    handler: Arc<T>,
}

impl<T: SmtpHandlerFactory + Send + Sync + 'static> SmtpServer<T> {
    pub fn new(config: SmtpConfig, handler: T) -> Self {
        Self {
            config,
            handler: Arc::new(handler),
        }
    }

    /// Entry point: dispatch based on TLS mode
    pub async fn listen_and_serve(self) -> std::result::Result<(), std::io::Error> {
        match &self.config.tls_mode {
            #[cfg(any(feature = "native-tls-backend", feature = "rustls-backend"))]
            TlsMode::Implicit(_) => self.serve_tls().await,
            _ => self.serve_plain().await,
        }
    }

    /// Plain TCP listener (STARTTLS optional handling done per session)
    async fn serve_plain(self) -> std::result::Result<(), std::io::Error> {
        let listener = TcpListener::bind(&self.config.bind_addr).await?;
        println!("SMTP server listening on {}", self.config.bind_addr);

        let config = Arc::new(self.config);
        let handler = Arc::clone(&self.handler);

        let (resolver_config, opts) = read_system_conf()
            .unwrap_or_else(|_| (ResolverConfig::default(), ResolverOpts::default()));
        let resolver = Arc::new(TokioAsyncResolver::tokio(resolver_config, opts));

        #[cfg(any(feature = "native-tls-backend", feature = "rustls-backend"))]
        let tls_provider: Option<Arc<TlsProvider>> = config
            .tls_mode
            .config()
            .and_then(|cnf| cnf.try_into().ok())
            .map(Arc::new);

        loop {
            let (stream, peer_addr) = listener.accept().await?;
            println!("New connection from {}", peer_addr);

            let config = Arc::clone(&config);
            let handler = Arc::clone(&handler);
            let resolver = Arc::clone(&resolver);

            #[cfg(any(feature = "native-tls-backend", feature = "rustls-backend"))]
            let provider = tls_provider.clone();

            let controller = StreamController::new(ConnectionStream::Tcp(stream), config.timeout);

            tokio::spawn(async move {
                if let Err(e) = handle_client(
                    controller,
                    peer_addr,
                    config,
                    handler,
                    resolver,
                    #[cfg(any(feature = "native-tls-backend", feature = "rustls-backend"))]
                    provider,
                )
                .await
                {
                    eprintln!("Error handling client {}: {}", peer_addr, e);
                }
            });
        }
    }

    /// Fully TLS listener (implicit TLS) — feature-gated
    #[cfg(any(feature = "native-tls-backend", feature = "rustls-backend"))]
    async fn serve_tls(self) -> std::result::Result<(), std::io::Error> {
        use std::sync::Arc;
        use tokio::net::TcpListener;

        let config = Arc::new(self.config);

        let tls_config = {
            let mode = &config.tls_mode;
            mode.config().expect("Direct TLS must have a TLS config")
        };

        // Bind TCP listener
        let listener = TcpListener::bind(&config.bind_addr).await?;
        println!("SMTP TLS server listening on {}", config.bind_addr);

        let handler = Arc::clone(&self.handler);

        let (resolver_config, opts) = read_system_conf().unwrap();
        let resolver = Arc::new(TokioAsyncResolver::tokio(resolver_config, opts));

        let tls_provider: Arc<TlsProvider> = tls_config
            .try_into()
            .ok()
            .map(Arc::new)
            .expect("Failed initializing tls provider");

        loop {
            let (stream, peer_addr) = listener.accept().await?;
            println!("New TLS connection from {}", peer_addr);

            let stream = tls_provider
                .accept(stream)
                .await
                .expect("Failed tls handshake.");

            let config = Arc::clone(&config);
            let handler = Arc::clone(&handler);
            let resolver = Arc::clone(&resolver);

            tokio::spawn(async move {
                // Upgrade TCP to TLS based on feature

                use crate::handler::handle_client;
                if let Err(e) = handle_client(
                    StreamController::new(stream, config.timeout),
                    peer_addr,
                    config,
                    handler,
                    resolver,
                    None,
                )
                .await
                {
                    eprintln!("Error handling TLS client {}: {}", peer_addr, e);
                }
            });
        }
    }
}
