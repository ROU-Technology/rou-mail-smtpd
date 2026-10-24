use std::fmt::Display;

use crate::{core::error::Error, utils};

/// Represents the supported SMTP authentication mechanisms.
///
/// These variants correspond to the authentication methods
/// that the server can advertise and handle during the SMTP session.
///
/// Currently supported mechanisms:
/// - [`Plain`] — AUTH PLAIN as defined in [RFC 4616].
/// - [`Login`] — AUTH LOGIN (non-standard but widely supported).
/// - [`CramMD5`] — AUTH CRAM-MD5 as defined in [RFC 2195].
///
/// [RFC 4616]: https://datatracker.ietf.org/doc/html/rfc4616
/// [RFC 2195]: https://datatracker.ietf.org/doc/html/rfc2195
#[derive(Debug, Clone, PartialEq)]
pub enum AuthMach {
    Plain,
    Login,
    CramMD5,
}

impl Display for AuthMach {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::Plain => "PLAIN",
                Self::Login => "LOGIN",
                Self::CramMD5 => "CRAM-MD5",
            }
        )
    }
}

impl AuthMach {
    pub(crate) fn from_str(line: &str) -> Result<(Self, Option<&str>), Error> {
        let (mach, credentials) = utils::parser::parse_cmd(line);

        match mach.as_str() {
            "PLAIN" => Ok((Self::Plain, credentials)),
            "LOGIN" => Ok((Self::Login, credentials)),
            "CRAM-MD5" => Ok((Self::CramMD5, credentials)),
            _ => Err(Error::UnrecognizedAuthMach),
        }
    }
}

/// Represents the parsed authentication data provided by the client.
///
/// This enum encapsulates the appropriate data structure for each supported
/// authentication mechanism. It is typically constructed internally by the
/// SMTP server when the client issues an `AUTH` command.
///
/// Passed to the [`SmtpHandler::handle_auth`](crate::core::handler::SmtpHandler::handle_auth) method.
///
/// # Example
///
/// ```
/// use smtpd::{async_trait, SmtpHandler, Session, AuthData, Result, Response, Error};
///
/// struct MyHandler;
///
/// #[async_trait]
/// impl SmtpHandler for MyHandler {
///     async fn handle_auth(
///         &mut self,
///         _session: &Session<'_>,
///         data: AuthData,
///     ) -> Result {
///         let (username, password, _) = data.data();
///
///         if username == "abc" && password == "efg" {
///             return Ok(Response::Default);
///         }
///
///         Err(Error::Abort)
///     }
/// }
/// ```
///
/// # Variants
///
/// - [`Plain`] — Represents AUTH PLAIN credentials.
/// - [`Login`] — Represents AUTH LOGIN credentials.
/// - [`CramMD5`] — Represents AUTH CRAM-MD5 credentials, including the shared challenge.
#[derive(Debug, Clone)]
pub enum AuthData {
    Plain {
        username: String,
        password: String,
    },
    Login {
        username: String,
        password: String,
    },
    CramMD5 {
        username: String,
        password: String,
        shared: String,
    },
}

impl AuthData {
    pub fn data(&self) -> (&str, &str, Option<&str>) {
        match self {
            Self::Login { username, password } | Self::Plain { username, password } => {
                (username, password, None)
            }
            Self::CramMD5 {
                username,
                password,
                shared,
            } => (username, password, Some(shared)),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn displays_auth_mach_variants_correctly() {
        let variants = [AuthMach::Plain, AuthMach::Login, AuthMach::CramMD5];
        let expected = ["PLAIN", "LOGIN", "CRAM-MD5"];

        let actual: Vec<_> = variants.iter().map(ToString::to_string).collect();
        assert_eq!(actual, expected);
    }

    #[test]
    fn extracts_correct_auth_mach_from_str() {
        let tests: HashMap<&str, (AuthMach, Option<&str>)> = HashMap::from([
            ("LOGIN", (AuthMach::Login, None)),
            ("PLAIN", (AuthMach::Plain, None)),
            ("LOGIN username", (AuthMach::Login, Some("username"))),
            ("plain username", (AuthMach::Plain, Some("username"))),
            ("CRAM-MD5", (AuthMach::CramMD5, None)),
        ]);

        for (input, (expected_variant, expected_arg)) in tests {
            let result = AuthMach::from_str(input);
            assert!(result.is_ok(), "Expected Some(..) for input: {}", input);

            let (variant, arg) = result.unwrap();
            assert_eq!(
                variant, expected_variant,
                "Variant mismatch for input: {}",
                input
            );
            assert_eq!(arg, expected_arg, "Argument mismatch for input: {}", input);
        }

        let result = AuthMach::from_str("");
        assert!(result.is_err());
    }
}
