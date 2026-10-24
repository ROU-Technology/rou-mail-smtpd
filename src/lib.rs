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
//! - Customizable handlers for AUTH, RCPT, and DATA commands via the Handler struct's [`SmtpHandler::handle_auth`], [`SmtpHandler::handle_data_end`], and [`SmtpHandler::handle_rcpt`] method
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
//!         _session: &smtpd::Session<'_>,
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
//!         _session: &smtpd::Session<'_>,
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
//!     fn new_handler(&self, _session: &smtpd::Session<'_>) -> Self::Handler {
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

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
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
#[cfg(any(feature = "native-tls-backend", feature = "rustls-backend"))]
use crate::core::tls::TlsProvider;
pub use crate::core::tls::{TlsConfig, TlsMode};
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

/// Decrements the active count for one peer IP when the admitted session ends.
/// Entries are removed at zero so spoofed/rotating clients cannot grow the map
/// beyond the finite global admission limit.
struct IpSlot {
    counts: Arc<Mutex<HashMap<IpAddr, usize>>>,
    ip: IpAddr,
}

impl Drop for IpSlot {
    fn drop(&mut self) {
        if let Ok(mut counts) = self.counts.lock() {
            if let Some(active) = counts.get_mut(&self.ip) {
                if *active <= 1 {
                    counts.remove(&self.ip);
                } else {
                    *active -= 1;
                }
            }
        }
    }
}

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
///     fn new_handler(&self, _session: &smtpd::Session<'_>) -> Self::Handler {
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

    /// Bind the configured listener. Use serve_until with an existing listener for tests/operations.
    pub async fn listen_and_serve(self) -> std::io::Result<()> {
        self.config.validate()?;
        let listener = TcpListener::bind(&self.config.bind_addr).await?;
        self.serve_until(listener, std::future::pending()).await
    }

    /// Stop admission on shutdown, allow a finite drain, then cancel remaining sessions.
    pub async fn serve_until<F: std::future::Future<Output = ()>>(
        self,
        listener: TcpListener,
        shutdown: F,
    ) -> std::io::Result<()> {
        self.config.validate()?;
        let config = Arc::new(self.config);
        let (dns, opts) = read_system_conf()
            .unwrap_or_else(|_| (ResolverConfig::default(), ResolverOpts::default()));
        let resolver = Arc::new(TokioAsyncResolver::tokio(dns, opts));
        let connections = Arc::new(tokio::sync::Semaphore::new(config.max_connections));
        let per_ip: Arc<Mutex<HashMap<IpAddr, usize>>> = Arc::new(Mutex::new(HashMap::new()));
        #[cfg(any(feature = "native-tls-backend", feature = "rustls-backend"))]
        let handshakes = Arc::new(tokio::sync::Semaphore::new(config.max_tls_handshakes));
        #[cfg(any(feature = "native-tls-backend", feature = "rustls-backend"))]
        let provider: Option<Arc<TlsProvider>> = match config.tls_mode.config() {
            Some(value) => Some(Arc::new(value.try_into().map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "Invalid TLS configuration",
                )
            })?)),
            None => None,
        };
        let mut tasks = tokio::task::JoinSet::new();
        tokio::pin!(shutdown);
        loop {
            tokio::select! {
                _ = &mut shutdown => break,
                _ = tasks.join_next(), if !tasks.is_empty() => {},
                incoming = listener.accept() => {
                    let (stream, peer) = incoming?;
                    if tasks.len() >= config.max_connections { drop(stream); continue; }
                    let Ok(permit) = connections.clone().try_acquire_owned() else { drop(stream); continue; };
                    let ip = peer.ip();
                    {
                        let mut counts = per_ip.lock().unwrap_or_else(|e| e.into_inner());
                        let active = counts.entry(ip).or_insert(0);
                        if *active >= config.max_connections_per_ip {
                            if *active == 0 { counts.remove(&ip); }
                            drop(counts);
                            drop(permit);
                            drop(stream);
                            continue;
                        }
                        *active += 1;
                    }
                    let ip_slot = IpSlot { counts: per_ip.clone(), ip };
                    let config = config.clone();
                    let factory = self.handler.clone();
                    let resolver = resolver.clone();
                    #[cfg(any(feature = "native-tls-backend", feature = "rustls-backend"))]
                    let provider = provider.clone();
                    #[cfg(any(feature = "native-tls-backend", feature = "rustls-backend"))]
                    let handshakes = handshakes.clone();
                    tasks.spawn(async move {
                        let _permit = permit;
                        let _ip_slot = ip_slot;
                        let lifetime = config.connection_timeout;
                        let _ = tokio::time::timeout(lifetime, async move {
                            #[cfg(any(feature = "native-tls-backend", feature = "rustls-backend"))]
                            let stream = if config.tls_mode.is_direct_tls() {
                                let Ok(_handshake) = handshakes.clone().try_acquire_owned() else { return; };
                                let Some(tls) = provider.as_ref() else { return; };
                                match tokio::time::timeout(config.timeout, tls.accept(stream)).await {
                                    Ok(Ok(secured)) => secured,
                                    _ => return,
                                }
                            } else { ConnectionStream::Tcp(stream) };
                            #[cfg(not(any(feature = "native-tls-backend", feature = "rustls-backend")))]
                            let stream = ConnectionStream::Tcp(stream);
                            let controller = StreamController::new(stream, config.timeout);
                            let _ = handle_client(controller, peer, config, factory, resolver,
                                #[cfg(any(feature = "native-tls-backend", feature = "rustls-backend"))]
                                provider,
                                #[cfg(any(feature = "native-tls-backend", feature = "rustls-backend"))]
                                handshakes,
                            ).await;
                        }).await;
                    });
                }
            }
        }
        drop(listener);
        if tokio::time::timeout(config.shutdown_timeout, async {
            while tasks.join_next().await.is_some() {}
        })
        .await
        .is_err()
        {
            tasks.abort_all();
            while tasks.join_next().await.is_some() {}
        }
        Ok(())
    }
}
