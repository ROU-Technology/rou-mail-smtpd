use std::fmt::Display;

use tokio::time::error::Elapsed;

use crate::Response;

/// Represents the core error type used throughout the SMTP server.
///
/// This enum encapsulates all error cases that may occur during server operation,
/// including network I/O failures, timeouts, and protocol-level issues.
///
/// Some variants (such as [`Response`]) are intended to be reported to the client
/// — these are automatically written to the stream before the connection is closed,
/// typically through a `try_into<Response>` conversion.  
/// Other variants are propagated internally for logging or custom error handling
/// within the server or user-defined handlers.
///
/// # Variants
///
/// - [`Io`] — Represents a standard I/O error during read or write operations.
/// - [`InvalidLineEnding`] — Encountered when a client sends malformed line endings (non–`\r\n`).
/// - [`MaxSizeExceeded`] — Message size exceeds the configured maximum.
/// - [`UnrecognizedAuthMach`] — The client attempted an unsupported authentication mechanism.
/// - [`InvalidTLSConfiguration`] — TLS configuration was invalid or incomplete.
/// - [`Response`] — A protocol-level error intended to be sent back to the client.
/// - [`DecodeErr`] — Base64 decoding failed during AUTH negotiation.
/// - [`Timeout`] — A read or write operation timed out.
/// - [`NativeTlsErr`] *(feature = "native-tls-backend")* — Error from the `native-tls` backend.
///
/// # Example
///
/// ```rust
/// use smtpd::{Error, Response};
///
/// fn example() -> Result<(), Error> {
///     // Return a protocol response error
///     Err(Error::Response(Response::bad_sequence("Invalid command order")))
/// }
/// ```
#[derive(Debug)]
pub(crate) enum Error {
    Io,
    Handler(crate::Error),
    InvalidLineEnding,
    MaxSizeExceeded {
        limit: usize,
    },
    UnrecognizedAuthMach,
    Response(Response),
    DecodeErr(base64::DecodeError),
    Timeout,
    #[cfg(feature = "native-tls-backend")]
    NativeTlsErr,
}

impl TryInto<Response> for Error {
    type Error = Error;

    fn try_into(self) -> Result<Response, Self::Error> {
        match self {
            Self::Handler(crate::Error::Response(res)) => Ok(res),
            Self::Handler(crate::Error::Abort) => Err(Self::Io),
            Self::InvalidLineEnding => Ok(Response::syntax_error("Invalid line ending")),
            Self::DecodeErr(e) => Ok(Response::syntax_error(format!(
                "Invalid base64 encoding: {e}"
            ))),
            Self::MaxSizeExceeded { limit } => Ok(Response::new(
                552,
                format!("Size limit {limit} exceeded"),
                Some("5.3.4".into()),
            )),
            Self::Response(res) => Ok(res),
            Self::Timeout => Ok(Response::Raw(
                "421 4.4.2 ESMTP Service closing transmission channel after timeout exceeded"
                    .into(),
            )),
            _ => Err(self),
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(_: std::io::Error) -> Self {
        Self::Io
    }
}

impl From<base64::DecodeError> for Error {
    fn from(value: base64::DecodeError) -> Self {
        Self::DecodeErr(value)
    }
}

impl From<Elapsed> for Error {
    fn from(_: Elapsed) -> Self {
        Error::Timeout
    }
}

#[cfg(feature = "native-tls-backend")]
impl From<native_tls::Error> for Error {
    fn from(_: native_tls::Error) -> Self {
        Error::NativeTlsErr
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}
impl std::error::Error for Error {}
