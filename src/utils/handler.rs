use std::{net::IpAddr, time::{Duration, SystemTime, UNIX_EPOCH}};

use base64::engine::general_purpose;
use base64::Engine;
use tokio::time::timeout;
use trust_dns_resolver::TokioAsyncResolver;

use crate::{core::{error::Error, stream::StreamController}, utils::parser::{parse_b64_line, parse_mail_from, parse_rcpt_to, parse_size}, AuthData, AuthMach, Response, Session};

/// Internal helper to validate a STARTTLS command request.
///
/// This function **does not perform any I/O**. It only checks whether the client
/// is allowed to initiate the STARTTLS command based on the current session and
/// server configuration.
///
/// # Parameters
/// - `args`: Optional arguments provided with the STARTTLS command. Any non-empty
///   argument will result in a syntax error.
/// - `controller`: Reference to the [`StreamController`] of the current connection.
///   Used to check whether the session is already TLS-secured.
/// - `session`: Reference to the current [`Session`], used to inspect server TLS configuration.
///
/// # Returns
/// - `Ok(())` if the client is allowed to initiate STARTTLS.
/// - `Err(Error::Response(...))` if:
///   - The command includes unexpected arguments (syntax error)
///   - The connection is already TLS-secured (bad sequence)
///   - TLS is not configured or STARTTLS is not allowed (not implemented)
///
/// # Notes
/// - This function is called internally during command processing before attempting
///   to upgrade the connection to TLS.
pub fn handle_start_tls_cmd<'a>(
    args: Option<&str>,
    controller: &StreamController,
    session: &Session<'a>,
) -> std::result::Result<(), Error> {
    // Reject if arguments are provided
    if args.is_some_and(|s| !s.is_empty()) {
        return Err(Error::Response(Response::syntax_error(
            "Syntax error (no parameters allowed)",
        )));
    }

    // Reject if already in TLS
    if controller.is_tls {
        return Err(Error::Response(Response::bad_sequence(
            "Already in TLS mode",
        )));
    }

    // Check if TLS is configured
    if session.smtp_config.tls_mode.allows_starttls() {
        return Ok(());
    }

    Err(Error::Response(Response::not_implemented()))
}

/// Internal helper to extract authentication data from the client.
///
/// This function validates whether the client is allowed to initiate the AUTH command,
/// checks the requested authentication mechanism, and reads the credentials according
/// to the selected mechanism (PLAIN, LOGIN, or CRAM-MD5).
///
/// # Parameters
/// - `args`: Optional argument passed with the AUTH command, usually the authentication mechanism name.
/// - `session`: Mutable reference to the current [`Session`]. Used to check session state and TLS requirements.
/// - `controller`: Mutable reference to the [`StreamController`] of the current connection. Used to read/write to the client.
///
/// # Returns
/// Returns an [`AuthData`] variant containing the parsed authentication credentials.
///
/// # Errors
/// Returns [`Error::Response`] with appropriate [`Response`] in the following cases:
/// - TLS is required but the connection is not secured (`"Must issue a STARTTLS command first"`).
/// - The client is already authenticated (`"Bad sequence of commands (already authenticated for this session)"`).
/// - AUTH command is issued during an ongoing mail transaction (`"AUTH not permitted during mail transaction"`).
/// - Missing or malformed AUTH arguments (`"501 5.5.4 Malformed AUTH input"`).
/// - Unsupported or unrecognized authentication mechanism (`"504 5.5.4 Unrecognized authentication type"`).
/// - Parsing errors or invalid credential format (`"Syntax error (unable to parse)"` or `"Authentication cancelled"`).
/// - Authentication failed after parsing credentials (`"Authentication credentials invalid"`).
pub async fn get_auth_data<'a>(
    args: Option<&str>,
    session: &mut Session<'a>,
    controller: &mut StreamController,
) -> std::result::Result<AuthData, Error> {
    if session.smtp_config.tls_mode.tls_mandatory() && !controller.is_tls {
        return Err(Error::Response(Response::reject(
            "Must issue a STARTTLS command first",
        )));
    }

    if session.authenticated {
        return Err(Error::Response(Response::bad_sequence(
            "Bad sequence of commands (already authenticated for this session)",
        )));
    }

    if session.got_from || !session.to.is_empty() {
        return Err(Error::Response(Response::bad_sequence(
            "Bad sequence of commands (AUTH not permitted during mail transaction)",
        )));
    }

    if args.is_none() || args.is_some_and(|a| a.is_empty()) {
        return Err(Error::Response(Response::Raw(
            "501 5.5.4 Malformed AUTH input (argument required)".into(),
        )));
    }

    let res = AuthMach::from_str(&args.unwrap_or_default());
    if res.is_err() {
        return Err(Error::Response(Response::new(
            504,
            "Unrecognized authentication type",
            Some("5.5.4".into()),
        )));
    }

    let (mach, line) = res.unwrap();
    if !session.smtp_config.auth_machs.contains(&mach) {
        return Err(Error::Response(Response::Raw(
            "504 5.5.4 Unrecognized authentication type".into(),
        )));
    }

    let mut line = line.unwrap_or_default().to_string();
    let data: Option<AuthData>;

    match mach {
        AuthMach::Plain => {
            if line.is_empty() {
                controller
                    .write_response(&Response::new(334, " ", None))
                    .await?;

                line.clear();
                controller.read_line_trimmed(&mut line).await?;
            }

            let parsed_data = parse_b64_line(&line)?;

            let parts: Vec<&[u8]> = parsed_data.split(|&b| b == 0).collect();

            if parts.len() != 3 {
                return Err(Error::Response(Response::syntax_error(
                    "Syntax error (unable to parse)",
                )));
            }

            data = Some(AuthData::Plain {
                username: String::from_utf8_lossy(parts[1]).to_string(),
                password: String::from_utf8_lossy(parts[2]).to_string(),
            });
        }
        AuthMach::Login => {
            if line.is_empty() {
                let encoded = general_purpose::STANDARD.encode("Username:");
                controller
                    .write_response(&Response::new(334, encoded, None))
                    .await?;

                line.clear();
                controller.read_line_trimmed(&mut line).await?;
            }

            let username = parse_b64_line(&line)?;

            let encoded = general_purpose::STANDARD.encode("Password:");
            controller
                .write_response(&Response::new(334, encoded, None))
                .await?;

            line.clear();
            controller.read_line_trimmed(&mut line).await?;

            let password = parse_b64_line(&line)?;

            data = Some(AuthData::Login {
                username: String::from_utf8_lossy(&username).to_string(),
                password: String::from_utf8_lossy(&password).to_string(),
            });
        }
        AuthMach::CramMD5 => {
            let shared = format!(
                "<{}.{}@{}>",
                std::process::id(),
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_nanos(),
                session.smtp_config.hostname
            );

            let encoded = general_purpose::STANDARD.encode(&shared);
            controller
                .write_response(&Response::new(334, encoded, None))
                .await?;

            line.clear();
            controller.read_line_trimmed(&mut line).await?;

            if line == "*" {
                return Err(Error::Response(Response::syntax_error(
                    "Authentication cancelled",
                )));
            }

            let buf = parse_b64_line(&line)?;
            let fields: Vec<&[u8]> = buf.split(|&b| b == b' ').collect();

            if fields.len() < 2 {
                return Err(Error::Response(Response::syntax_error(
                    "Syntax error (unable to parse)",
                )));
            }

            data = Some(AuthData::CramMD5 {
                username: String::from_utf8_lossy(fields[0]).to_string(),
                password: String::from_utf8_lossy(fields[1]).to_string(),
                shared,
            });
        }
    };

    if data.is_none() {
        return Err(Error::Response(Response::new(
            535,
            "Authentication credentials invalid",
            Some("5.7.8".into()),
        )));
    }

    Ok(data.unwrap())
}

/// Internal helper to handle the `MAIL` command.
///
/// This function validates the MAIL command parameters, enforces TLS and authentication
/// requirements, checks the `SIZE` parameter (if provided), and updates the session state.
///
/// # Parameters
/// - `args`: Optional argument passed with the MAIL command, usually `"FROM:<address> [parameters]"`.
/// - `session`: Mutable reference to the current [`Session`]. Used to validate and update session state.
/// - `controller`: Mutable reference to the [`StreamController`] for reading/writing responses.
///
/// # Behavior
/// - Rejects the command if TLS is required but not active.
/// - Rejects if authentication is required but the client is not authenticated.
/// - Parses the `FROM` address and optional parameters; rejects if malformed.
/// - Validates the `SIZE` parameter, if present, against server configuration.
/// - Updates the session's `from`, `got_from`, and clears the recipients list (`to`).
/// - Sends a `250 Ok` response on success.
///
/// # Errors
/// Returns [`Error::Response`] with appropriate [`Response`] in the following cases:
/// - TLS is mandatory but not active (`"Must issue a STARTTLS command first"`).
/// - Authentication is required but not completed (`"Authentication required"`).
/// - Malformed FROM argument (`"Syntax error in FROM parameter"`).
/// - Invalid SIZE parameter (`"Invalid SIZE parameter"`).
/// - Message exceeds configured maximum size (`"Max size limit (<max_size>) exceeded"`).
///
pub async fn handle_mail_cmd<'a>(
    args: Option<&str>,
    session: &mut Session<'a>,
    controller: &mut StreamController,
) -> std::result::Result<(), Error> {
    // Enforce TLS if required
    if session.smtp_config.tls_mode.tls_mandatory() && !controller.is_tls {
        return Err(Error::Response(Response::reject(
            "Must issue a STARTTLS command first",
        )));
    }

    // Enforce authentication if required
    if session.smtp_config.require_auth && !session.authenticated {
        return Err(Error::Response(Response::reject(
            "Authentication required",
        )));
    }

    // Parse MAIL FROM argument
    let (from, params) = parse_mail_from(args.unwrap_or_default())
        .ok_or_else(|| {
            Error::Response(Response::syntax_error("Syntax error in FROM parameter"))
        })?;

    // Validate SIZE parameter, if provided
    let size = params
        .as_ref()
        .filter(|p| !p.is_empty())
        .map(|p| parse_size(p.as_str()))
        .flatten();

    if params.is_some() && size.is_none() {
        return Err(Error::Response(Response::syntax_error(
            "Invalid SIZE parameter",
        )));
    }

    if let Some(max_size) = session.smtp_config.max_message_size {
        if let Some(s) = size {
            if s > max_size {
                return Err(Error::Response(Response::new(
                    552,
                    format!("Max size limit ({max_size}) exceeded"),
                    Some("5.3.4".into()),
                )));
            }
        }
    }

    // Update session state
    session.from = from.to_string();
    session.got_from = true;
    session.to.clear();

    // Send success response
    controller.write_response(&Response::ok("Ok")).await?;
    Ok(())
}

/// Internal helper to extract the recipient address from the RCPT command argument.
///
/// This function validates the session state, enforces TLS and authentication requirements,
/// checks the MAIL command has been issued, and ensures the recipient limit is not exceeded.
///
/// # Parameters
/// - `args`: Optional argument passed with the RCPT command, usually `"TO:<address> [parameters]"`.
/// - `session`: Mutable reference to the current [`Session`].
///
/// # Behavior
/// - Rejects if TLS is mandatory but not active.
/// - Rejects if authentication is required but not yet completed.
/// - Rejects if MAIL command has not been issued yet (`got_from` is false).
/// - Rejects if adding the recipient would exceed `max_recipients` limit.
/// - Parses the recipient address from the command argument.
///
/// # Errors
/// Returns [`Error::Response`] with an appropriate [`Response`] in the following cases:
/// - TLS is mandatory but not active (`"Must issue a STARTTLS command first"`).
/// - Authentication is required but not completed (`"Authentication required"`).
/// - MAIL command not yet issued (`"Bad sequence of commands (MAIL required before RCPT)"`).
/// - Max recipient limit exceeded (`"Max recipient limit exceeded"`).
/// - Malformed TO argument (`"Syntax error in parameters or arguments (invalid TO parameter)"`).
pub async fn extract_rcpt_from_arg<'a>(
    args: Option<&str>,
    session: &mut Session<'a>,
) -> std::result::Result<String, Error> {
    // Enforce TLS if required
    if session.smtp_config.tls_mode.tls_mandatory() && !session.tls {
        return Err(Error::Response(Response::reject(
            "Must issue a STARTTLS command first",
        )));
    }

    // Enforce authentication if required
    if session.smtp_config.require_auth && !session.authenticated {
        return Err(Error::Response(Response::reject(
            "Authentication required",
        )));
    }

    // Ensure MAIL command has been issued
    if !session.got_from {
        return Err(Error::Response(Response::bad_sequence(
            "Bad sequence of commands (MAIL required before RCPT)",
        )));
    }

    // Enforce max recipient limit
    if session.to.len() >= session.smtp_config.max_recipients {
        return Err(Error::Response(Response::new(
            452,
            "Max recipient limit exceeded",
            Some("4.5.3".into()),
        )));
    }

    // Parse the recipient address
    let to = parse_rcpt_to(&args.unwrap_or_default()).ok_or_else(|| {
        Error::Response(Response::syntax_error(
            "Syntax error in parameters or arguments (invalid TO parameter)",
        ))
    })?;

    Ok(to.to_string())
}

/// Internal helper to read the message body after the DATA command.
///
/// This function validates the session state, enforces TLS and authentication requirements,
/// ensures that MAIL and at least one RCPT command have been successfully processed,
/// prompts the client to start sending mail data, and reads the message until the
/// terminating line (`.<CRLF>`).
///
/// # Parameters
/// - `session`: Mutable reference to the current [`Session`].
/// - `controller`: Mutable reference to the [`StreamController`] handling read/write.
///
/// # Returns
/// Returns the raw message data as a `Vec<u8>`.
///
/// # Errors
/// Returns [`Error::Response`] with an appropriate [`Response`] if:
/// - TLS is required but not active.
/// - Authentication is required but not completed.
/// - MAIL or RCPT commands have not yet been issued.
pub async fn extract_mail_data<'a>(
    session: &mut Session<'a>,
    controller: &mut StreamController,
) -> std::result::Result<Vec<u8>, Error> {
    // Enforce TLS if required
    if session.smtp_config.tls_mode.tls_mandatory() && !controller.is_tls {
        return Err(Error::Response(Response::reject(
            "Must issue a STARTTLS command first",
        )));
    }

    // Enforce authentication if required
    if session.smtp_config.require_auth && !session.authenticated {
        return Err(Error::Response(Response::reject(
            "Authentication required",
        )));
    }

    // Ensure MAIL & RCPT commands have been issued
    if !session.got_from || session.to.is_empty() {
        return Err(Error::Response(Response::bad_sequence(
            "Bad sequence of commands (MAIL & RCPT required before DATA)",
        )));
    }

    // Prompt client to start sending the message body
    controller
        .write_line("354 Start mail input; end with <CR><LF>.<CR><LF>")
        .await?;

    // Read the message data with optional maximum size limit
    let data = controller
        .read_mail_data(session.smtp_config.max_message_size)
        .await?;

    Ok(data)
}

/// Performs a reverse DNS lookup for the given IP address using the provided resolver.
/// Returns the first resolved hostname as a `String`, or `"unknown"` if the lookup fails or times out.
///
/// # Parameters
/// - `ip`: The IP address to resolve.
/// - `resolver`: A reference to a `TokioAsyncResolver` instance.
///
/// # Returns
/// A `String` representing the resolved hostname, or `"unknown"` if lookup fails.
pub async fn get_remote_host(ip: IpAddr, resolver: &TokioAsyncResolver) -> String {
    const TIMEOUT: Duration = Duration::from_secs(30);

    match timeout(TIMEOUT, resolver.reverse_lookup(ip)).await {
        Ok(Ok(lookup)) => lookup
            .iter()
            .next()
            .map(|n| n.to_utf8())
            .unwrap_or_else(|| "unknown".to_string()),
        _ => "unknown".to_string(),
    }
}
