use crate::core::auth::AuthMach;
use crate::core::tls::TlsMode;
use std::pin::Pin;
use std::task::Poll;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;

pub mod auth;
pub mod error;
pub mod handler;
pub mod response;
pub mod response_error;
pub mod session;
pub mod stream;
pub mod tls;

/// SMTP Server Configuration
///
/// Defines the core configuration options for the SMTP server.  
/// These settings control the server’s behavior across all incoming connections and  
/// are accessible later via the [`Session`]'s `smtp_config` property.
///
/// # Example
///
/// ```no_run
/// use smtpd::{async_trait, Session, SmtpHandler, SmtpHandlerFactory, SmtpConfig, AuthMach, start_server};
///
/// #[tokio::main]
/// async fn main() -> Result<(), Box<dyn std::error::Error>> {
///     let config = SmtpConfig {
///         bind_addr: "127.0.0.1:2525".to_string(),
///         require_auth: true,
///         auth_machs: vec![AuthMach::Plain, AuthMach::Login],
///         ..Default::default()
///     };
///
///     let factory = MyHandlerFactory;
///     start_server(config, factory).await?;
///     Ok(())
/// }
///
/// struct MyHandler;
///
/// #[async_trait]
/// impl SmtpHandler for MyHandler{}
///
/// struct MyHandlerFactory;
///
/// impl SmtpHandlerFactory for MyHandlerFactory {
///     type Handler = MyHandler;
///
///     fn new_handler(&self, _session: &Session) -> Self::Handler {
///         MyHandler
///     }
/// }
/// ```
///
/// # Fields
///
/// - **`hostname`** — Hostname of the server. Defaults to the system hostname.
/// - **`appname`** — Application name used in server greetings and responses. Defaults to `"smtpd-rs"`.
/// - **`bind_addr`** — TCP address to bind and listen on.  
///   Defaults to `":25"` (all interfaces, port 25) if empty.
/// - **`tls_mode`** — TLS behavior mode for the server.  
///   See [`TlsMode`] for supported options (e.g., `Disabled`, `Explicit`, `Required`, `Implicit`).
/// - **`max_message_size`** — Maximum allowed message size in bytes.  
///   If `None`, message size limits are not enforced.
/// - **`max_recipients`** — Maximum number of recipients per message.  
///   Defaults to **100**, as recommended by RFC 5321.
/// - **`timeout`** — Timeout duration for individual read/write operations  
///   (not the total connection duration).
/// - **`auth_machs`** — List of allowed authentication mechanisms.  
///   Supported values: `LOGIN`, `PLAIN`, `CRAM-MD5`.  
///   Enabling `LOGIN` and `PLAIN` reduces strict RFC 4954 compliance.  
///   Leave empty to disable authentication entirely.
///   The server will never advertise any auth mechanism without specifying this field.
/// - **`require_auth`** — Whether authentication is required for every command  
///   except `AUTH`, `EHLO`, `HELO`, `NOOP`, `RSET`, or `QUIT`, per RFC 4954.
/// - **`disable_reverse_dns`** — Disables reverse DNS lookups.  
///   When enabled, unknown clients will be reported as `"unknown"` in logs and responses.
/// - **`x_client_allowed`** — List of IP addresses allowed to use the `XCLIENT` extension.  
///   If `None`, the extension is disabled.
#[derive(Debug, Clone)]
pub struct SmtpConfig {
    /// Hostname of the server. Defaults to the system hostname.
    pub hostname: String,

    /// Application name of the server. Defaults to `"smtpd-rs"`.
    pub appname: String,

    /// TCP address to listen on. Defaults to `":25"` (all interfaces, port 25) if empty.
    pub bind_addr: String,

    /// TLS mode for the server. See [`TlsMode`] for details.
    pub tls_mode: TlsMode,

    /// Maximum allowed message size in bytes.
    pub max_message_size: Option<usize>,

    /// Maximum number of recipients per message. Defaults to 100.
    pub max_recipients: usize,

    /// Timeout duration for individual read/write operations.
    pub timeout: Duration,

    /// List of allowed authentication mechanisms. Supported: LOGIN, PLAIN, CRAM-MD5.
    pub auth_machs: Vec<AuthMach>,

    /// Require authentication for all commands except AUTH, EHLO, HELO, NOOP, RSET, or QUIT.
    pub require_auth: bool,

    /// Disable reverse DNS lookups (unknown clients will appear as "unknown").
    pub disable_reverse_dns: bool,

    /// List of IPs allowed to use the XCLIENT extension.
    pub x_client_allowed: Option<Vec<String>>,
}

impl Default for SmtpConfig {
    fn default() -> Self {
        let hostname = hostname::get()
            .map(|s| s.into_string().unwrap_or_default())
            .unwrap_or("unknown".into());

        Self {
            bind_addr: "127.0.0.1:25".to_string(),
            appname: "smtpd-rs".to_string(),
            hostname,
            max_message_size: Some(10 * 1024 * 1024), // 10MB
            timeout: Duration::from_secs(300),        // 5M
            max_recipients: 100,
            auth_machs: vec![],
            require_auth: false,
            disable_reverse_dns: false,
            x_client_allowed: None,
            tls_mode: TlsMode::Disabled,
        }
    }
}

/// Represents a unified network stream used by the SMTP server.
///
/// This enum abstracts over different stream types (plain TCP or TLS),
/// allowing the server to handle secure and non-secure connections seamlessly
/// without breaking the type system.
///
/// Variants correspond to the active connection mode:
/// - [`Tcp`] — a plain TCP connection.
/// - [`NativeTls`] — a TLS connection using `tokio-native-tls`.
/// - [`Rustls`] — a TLS connection using `tokio-rustls`.
pub(crate) enum ConnectionStream {
    Tcp(TcpStream),
    #[cfg(feature = "native-tls-backend")]
    NativeTls(tokio_native_tls::TlsStream<TcpStream>),
    #[cfg(feature = "rustls-backend")]
    Rustls(tokio_rustls::server::TlsStream<TcpStream>),
}

impl AsyncRead for ConnectionStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match &mut *self {
            ConnectionStream::Tcp(stream) => Pin::new(stream).poll_read(cx, buf),
            #[cfg(feature = "native-tls-backend")]
            ConnectionStream::NativeTls(stream) => Pin::new(stream).poll_read(cx, buf),
            #[cfg(feature = "rustls-backend")]
            ConnectionStream::Rustls(stream) => Pin::new(stream).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for ConnectionStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match &mut *self {
            ConnectionStream::Tcp(stream) => Pin::new(stream).poll_write(cx, buf),
            #[cfg(feature = "native-tls-backend")]
            ConnectionStream::NativeTls(stream) => Pin::new(stream).poll_write(cx, buf),
            #[cfg(feature = "rustls-backend")]
            ConnectionStream::Rustls(stream) => Pin::new(stream).poll_write(cx, buf),
        }
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        match &mut *self {
            ConnectionStream::Tcp(stream) => Pin::new(stream).poll_flush(cx),
            #[cfg(feature = "native-tls-backend")]
            ConnectionStream::NativeTls(stream) => Pin::new(stream).poll_flush(cx),
            #[cfg(feature = "rustls-backend")]
            ConnectionStream::Rustls(stream) => Pin::new(stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        match &mut *self {
            ConnectionStream::Tcp(stream) => Pin::new(stream).poll_shutdown(cx),
            #[cfg(feature = "native-tls-backend")]
            ConnectionStream::NativeTls(stream) => Pin::new(stream).poll_shutdown(cx),
            #[cfg(feature = "rustls-backend")]
            ConnectionStream::Rustls(stream) => Pin::new(stream).poll_shutdown(cx),
        }
    }
}

impl Unpin for ConnectionStream {}

impl ConnectionStream {
    #[cfg(any(feature = "native-tls-backend", feature = "rustls-backend"))]
    pub fn is_tls(&self) -> bool {
        match self {
            #[cfg(feature = "native-tls-backend")]
            Self::NativeTls(_) => true,
            #[cfg(feature = "rustls-backend")]
            Self::Rustls(_) => true,
            Self::Tcp(_) => false,
        }
    }
}
