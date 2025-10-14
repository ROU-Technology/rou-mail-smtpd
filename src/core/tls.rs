use std::fmt::Debug;

#[cfg(any(feature = "native-tls-backend", feature = "rustls-backend"))]
use tokio::net::TcpStream;

#[cfg(any(feature = "native-tls-backend", feature = "rustls-backend"))]
use crate::{
    Response,
    core::{ConnectionStream, error::Error},
};

/// Represents the TLS configuration for the SMTP server.
///
/// The exact variant depends on the enabled feature:
/// - `native-tls-backend`: uses `native_tls::Identity`
/// - `rustls-backend`: uses `rustls::ServerConfig`
///
/// This crate re-exports `Identity` and `ServerConfig` depending on the feature,
/// so consumers do not need to install them separately.
///
/// # Examples
///
/// Using `native-tls-backend`:
/// ```no_run
/// use smtpd::{TlsConfig, TlsMode, SmtpConfig, AuthMach};
///
/// # #[cfg(feature = "native-tls-backend")]
/// # {
///     let der: Vec<u8> = vec![];
///     let identity = smtpd::Identity::from_pkcs12(der.as_slice(), "password").unwrap();
///     let tls_config = TlsConfig::NativeTls(identity);
///
///     let _config = SmtpConfig {
///         bind_addr: "127.0.0.1:2525".to_string(),
///         require_auth: true,
///         tls_mode: TlsMode::Required(tls_config),
///         auth_machs: vec![AuthMach::Plain, AuthMach::Login],
///         ..Default::default()
///     };
/// # }
/// ```
///
/// Using rustls-backend:
/// ```no_run
/// use smtpd::{TlsConfig, TlsMode, SmtpConfig, AuthMach};
///
/// # #[cfg(feature = "rustls-backend")]
/// # {
///     let rustls_config = smtpd::ServerConfig::default();
///     let tls_config = TlsConfig::Rustls(rustls_config);
///
///     let config = SmtpConfig {
///         bind_addr: "127.0.0.1:2525".to_string(),
///         require_auth: true,
///         tls_mode: TlsMode::Required(tls_config),
///         auth_machs: vec![AuthMach::Plain, AuthMach::Login],
///         ..Default::default()
///     };
/// # }
/// ```
#[derive(Clone)]
pub enum TlsConfig {
    #[cfg(feature = "native-tls-backend")]
    NativeTls(native_tls::Identity),

    #[cfg(feature = "rustls-backend")]
    Rustls(rustls::ServerConfig),
}

impl core::fmt::Debug for TlsConfig {
    fn fmt(&self, _f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            #[cfg(feature = "native-tls-backend")]
            Self::NativeTls(_) => write!(_f, "TlsConfig::NativeTls(<identity>)"),

            #[cfg(feature = "rustls-backend")]
            Self::Rustls(_) => write!(_f, "TlsConfig::Rustls(<config>)"),

            #[allow(unreachable_patterns)]
            _ => Err(core::fmt::Error),
        }
    }
}

/// Internal TLS acceptor wrapper used to avoid rebuilding the acceptor
/// for each incoming connection. The acceptor is created once from a
/// [`TlsConfig`] and reused.
///
/// This ensures better performance and proper TLS handshakes per connection.
#[cfg(any(feature = "native-tls-backend", feature = "rustls-backend"))]
#[derive(Clone)]
pub(crate) enum TlsProvider {
    #[cfg(feature = "native-tls-backend")]
    NativeTls(tokio_native_tls::TlsAcceptor),

    #[cfg(feature = "rustls-backend")]
    Rustls(tokio_rustls::TlsAcceptor),
}

#[cfg(any(feature = "native-tls-backend", feature = "rustls-backend"))]
impl core::fmt::Debug for TlsProvider {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            #[cfg(feature = "native-tls-backend")]
            Self::NativeTls(_) => f.write_str("TlsProvider::NativeTls"),
            #[cfg(feature = "rustls-backend")]
            Self::Rustls(_) => f.write_str("TlsProvider::Rustls"),
        }
    }
}

#[cfg(any(feature = "native-tls-backend", feature = "rustls-backend"))]
impl TryFrom<&TlsConfig> for TlsProvider {
    type Error = Error;

    fn try_from(value: &TlsConfig) -> Result<Self, Self::Error> {
        match value {
            #[cfg(feature = "native-tls-backend")]
            TlsConfig::NativeTls(identity) => {
                use tokio_native_tls::{TlsAcceptor, native_tls};
                let acceptor = native_tls::TlsAcceptor::builder(identity.clone()).build()?;
                Ok(Self::NativeTls(TlsAcceptor::from(acceptor)))
            }

            #[cfg(feature = "rustls-backend")]
            TlsConfig::Rustls(config) => {
                use std::sync::Arc;
                use tokio_rustls::TlsAcceptor;
                Ok(Self::Rustls(TlsAcceptor::from(Arc::new(config.clone()))))
            }

            #[allow(unreachable_patterns)]
            _ => Err(Error::Response(Response::not_implemented())),
        }
    }
}

#[cfg(any(feature = "native-tls-backend", feature = "rustls-backend"))]
impl TlsProvider {
    /// Performs a TLS handshake on the given TCP stream, returning a
    /// `ConnectionStream` with the negotiated TLS connection.
    pub async fn accept(&self, stream: TcpStream) -> Result<ConnectionStream, Error> {
        match self {
            #[cfg(feature = "native-tls-backend")]
            Self::NativeTls(acceptor) => {
                Ok(ConnectionStream::NativeTls(acceptor.accept(stream).await?))
            }

            #[cfg(feature = "rustls-backend")]
            Self::Rustls(acceptor) => Ok(ConnectionStream::Rustls(acceptor.accept(stream).await?)),
        }
    }
}
/// Specifies the TLS mode for the SMTP server.
///
/// This enum controls how TLS is applied to connections. Depending on the variant, TLS
/// may be disabled, optional, required, or always-on (implicit).  
///
/// # Examples
///
/// ```no_run
/// # #[cfg(feature = "native-tls-backend")]
/// # {
/// use smtpd::{TlsMode, TlsConfig, Identity};
///
/// // Explicit TLS (STARTTLS supported but optional)
/// let der: Vec<u8> = vec![];
/// let identity = smtpd::Identity::from_pkcs12(der.as_slice(), "password").unwrap();
/// let tls_config = TlsConfig::NativeTls(identity);
/// 
/// // opportunistic tls
/// let mode = TlsMode::Explicit(tls_config.clone());
///
/// // Required TLS (STARTTLS mandatory)
/// let required_mode = TlsMode::Required(tls_config.clone());
///
/// // Implicit TLS (SMTPS style)
/// let implicit_mode = TlsMode::Implicit(tls_config);
/// # }
/// ```
#[derive(Debug, Clone, Default)]
pub enum TlsMode {
    /// No TLS support.
    #[default]
    Disabled,

    /// Explicit TLS (STARTTLS supported but optional)
    #[cfg(any(feature = "native-tls-backend", feature = "rustls-backend"))]
    Explicit(TlsConfig),

    /// Required TLS via STARTTLS (all commands except NOOP, EHLO, STARTTLS, QUIT must use TLS)
    #[cfg(any(feature = "native-tls-backend", feature = "rustls-backend"))]
    Required(TlsConfig),

    /// Implicit TLS (always TLS, e.g., SMTPS on port 465)
    #[cfg(any(feature = "native-tls-backend", feature = "rustls-backend"))]
    Implicit(TlsConfig),
}

impl TlsMode {
    /// Returns true if this mode involves TLS at all.
    #[cfg(any(feature = "native-tls-backend", feature = "rustls-backend"))]
    pub fn has_tls(&self) -> bool {
        matches!(
            self,
            Self::Explicit(_) | Self::Required(_) | Self::Implicit(_)
        )
    }

    /// Returns a reference to the TLS configuration if TLS is enabled.
    #[cfg(any(feature = "native-tls-backend", feature = "rustls-backend"))]
    pub fn config(&self) -> Option<&TlsConfig> {
        match self {
            Self::Explicit(cfg) | Self::Required(cfg) | Self::Implicit(cfg) => Some(cfg),
            _ => None,
        }
    }

    /// Returns true if TLS is enabled immediately upon connection (Direct TLS / SMTPS).
    #[cfg(any(feature = "native-tls-backend", feature = "rustls-backend"))]
    pub fn is_direct_tls(&self) -> bool {
        match self {
            Self::Implicit(_) => true,
            _ => false,
        }
    }

    /// Returns true if the client may initiate TLS via STARTTLS (Explicit or Required).
    #[cfg(any(feature = "native-tls-backend", feature = "rustls-backend"))]
    pub fn allows_starttls(&self) -> bool {
        match self {
            Self::Explicit(_) | Self::Required(_) => true,
            _ => false,
        }
    }

    /// Returns true if TLS is mandatory for all commands (Required TLS mode).
    #[cfg(any(feature = "native-tls-backend", feature = "rustls-backend"))]
    pub fn tls_mandatory(&self) -> bool {
        match self {
            Self::Required(_) => true,
            _ => false,
        }
    }
}
