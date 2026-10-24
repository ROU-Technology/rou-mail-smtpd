use trust_dns_resolver::TokioAsyncResolver;

#[cfg(any(feature = "native-tls-backend", feature = "rustls-backend"))]
use crate::core::ConnectionStream;
use crate::core::error::Error as CoreError;
use crate::core::stream::StreamController;
#[cfg(any(feature = "native-tls-backend", feature = "rustls-backend"))]
use crate::core::tls::TlsProvider;
#[cfg(any(feature = "native-tls-backend", feature = "rustls-backend"))]
use crate::utils::handler::handle_start_tls_cmd;
use crate::utils::handler::{
    extract_rcpt_from_arg, get_auth_data, get_remote_host, handle_mail_cmd, validate_data,
};
use crate::utils::parser::parse_cmd;
use crate::{Error, Response, SmtpConfig, SmtpHandler, SmtpHandlerFactory};
use std::fmt::Write;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;

/// Handles a single SMTP client connection.
///
/// This internal function manages all aspects of the client session:
/// - Reads commands from the client and parses them
/// - Writes responses to the client
/// - Invokes the appropriate [`SmtpHandler`] methods for AUTH, MAIL, RCPT, DATA, etc.
/// - Applies TLS negotiation if required by the server configuration
///
/// This function is called for each accepted connection and runs within a dedicated
/// Tokio task.
///
/// # Parameters
/// - `controller`: The [`StreamController`] for reading from and writing to the connection.
/// - `addr`: The socket address of the connected client.
/// - `config`: Shared SMTP server configuration (`SmtpConfig`).
/// - `handler_factory`: Factory for creating per-session handler instances.
/// - `resolver`: DNS resolver used for reverse lookups and MX resolution.
/// - `provider` (optional, TLS-only): TLS acceptor used for upgrading TCP streams to TLS.
///
/// # Returns
/// Returns `Ok(())` on successful handling of the session, or a [`CoreError`] if any
/// internal error occurs.
///
/// # Notes
/// - This function is async and designed to be spawned in a Tokio task per connection.
/// - TLS negotiation (STARTTLS or implicit TLS) is applied automatically if `provider` is `Some`.
/// - All authentication and mail commands are delegated to the handler returned by
///   `handler_factory.new_handler(session)`.
pub async fn handle_client<T: SmtpHandlerFactory + Send + Sync + 'static>(
    mut controller: StreamController,
    addr: SocketAddr,
    config: Arc<SmtpConfig>,
    handler_factory: Arc<T>,
    resolver: Arc<TokioAsyncResolver>,
    #[cfg(any(feature = "native-tls-backend", feature = "rustls-backend"))] provider: Option<
        Arc<TlsProvider>,
    >,
    #[cfg(any(feature = "native-tls-backend", feature = "rustls-backend"))] handshakes: Arc<
        tokio::sync::Semaphore,
    >,
) -> std::result::Result<(), CoreError> {
    let remote_host = if !config.disable_reverse_dns {
        get_remote_host(addr.ip(), &resolver, config.timeout).await
    } else {
        "unknown".to_string()
    };

    let mut session = crate::Session::new(
        &config,
        addr.ip().to_string(),
        remote_host.clone(),
        #[cfg(any(feature = "native-tls-backend", feature = "rustls-backend"))]
        controller.is_tls,
    );
    let mut handler = handler_factory.new_handler(&session);
    controller.set_line_limit(config.max_line_bytes);

    // Send greeting
    controller
        .write_line(format!(
            "220 {} {} ESMTP Service ready",
            config.hostname, config.appname
        ))
        .await?;

    let mut buffer = String::new();

    // Main command loop
    loop {
        buffer.clear();

        // Read command with timeout
        match controller.read_line_trimmed(&mut buffer).await {
            Ok(()) => {
                let (command, args) = parse_cmd(&buffer.trim());

                match command.as_str() {
                    "STARTTLS" => {
                        #[cfg(any(feature = "native-tls-backend", feature = "rustls-backend"))]
                        match handle_start_tls_cmd(args, &controller, &session) {
                            Ok(()) => {
                                if provider.is_none() {
                                    return Err(CoreError::Io);
                                }
                                let Ok(_handshake) = handshakes.clone().try_acquire_owned() else {
                                    controller
                                        .write_line("454 4.7.0 TLS capacity unavailable")
                                        .await?;
                                    continue;
                                };
                                // Inform client we’re ready
                                controller.write_line("220 Ready to start TLS").await?;

                                let stream: ConnectionStream = controller.into();

                                let stream = match stream {
                                    ConnectionStream::Tcp(stream) => match provider.as_ref() {
                                        Some(p) => {
                                            tokio::time::timeout(config.timeout, p.accept(stream))
                                                .await??
                                        }
                                        None => ConnectionStream::Tcp(stream),
                                    },
                                    _ => stream,
                                };

                                controller =
                                    StreamController::new(stream, session.smtp_config.timeout);

                                // RFC 3207 specifies that the server must discard any prior knowledge obtained from the client.
                                session = crate::Session::new(
                                    &config,
                                    addr.ip().to_string(),
                                    remote_host.clone(),
                                    true,
                                );
                                handler = handler_factory.new_handler(&session);
                                controller.set_line_limit(config.max_line_bytes);
                            }
                            Err(e) => {
                                let res: Response = e.try_into()?;
                                controller.write_response(&res).await?;
                                // A refused STARTTLS (syntax, already encrypted or
                                // unsupported) leaves the current session intact.
                                continue;
                            }
                        };

                        #[cfg(not(any(
                            feature = "native-tls-backend",
                            feature = "rustls-backend"
                        )))]
                        {
                            controller
                                .write_response(&Response::not_implemented())
                                .await?;
                            break;
                        }
                    }
                    "QUIT" => {
                        controller
                            .write_response(&Response::Raw(
                                format!(
                                    "221 2.0.0 {} {} ESMTP Service closing transmission channel",
                                    session.smtp_config.hostname, session.smtp_config.appname
                                )
                                .into(),
                            ))
                            .await?;
                        break;
                    }
                    "HELO" => {
                        // RFC 2821 section 4.1.4 specifies that HELO has the same effect as RSET, so reset for HELO too.
                        reset_transaction(&mut session, &mut handler).await?;
                        session.remote_name = args.unwrap_or_default().to_string();

                        controller
                            .write_response(&Response::ok(format!(
                                "{} greets {}",
                                session.smtp_config.hostname, session.remote_name
                            )))
                            .await?;
                    }
                    "EHLO" => {
                        // RFC 2821 section 4.1.4 specifies that EHLO has the same effect as RSET.
                        reset_transaction(&mut session, &mut handler).await?;
                        session.remote_name = args.unwrap_or_default().to_string();

                        let mut message = String::with_capacity(256);

                        // Hostname + greeting
                        writeln!(
                            message,
                            "250-{} greets {}",
                            session.smtp_config.hostname, session.remote_name
                        )
                        .unwrap();

                        // RFC 1870: "SIZE 0" means no limit
                        writeln!(message, "250-SIZE {}", session.smtp_config.max_message_size)
                            .unwrap();

                        // STARTTLS if enabled
                        #[cfg(any(feature = "native-tls-backend", feature = "rustls-backend"))]
                        if session.smtp_config.tls_mode.allows_starttls() && !controller.is_tls {
                            writeln!(message, "250-STARTTLS").unwrap();
                        }

                        // AUTH if mechanisms exist
                        if !session.smtp_config.auth_machs.is_empty() && {
                            #[cfg(any(feature = "native-tls-backend", feature = "rustls-backend"))]
                            {
                                controller.is_tls
                            }
                            #[cfg(not(any(
                                feature = "native-tls-backend",
                                feature = "rustls-backend"
                            )))]
                            {
                                false
                            }
                        } {
                            let joined = session
                                .smtp_config
                                .auth_machs
                                .iter()
                                .map(|m| m.to_string())
                                .collect::<Vec<_>>()
                                .join(" ");

                            writeln!(message, "250-AUTH {}", joined).unwrap();
                        }

                        // Final line must not have "-"
                        message.push_str("250 ENHANCEDSTATUSCODES");

                        controller.write_line(message.replace("\n", "\r\n")).await?;
                    }
                    "NOOP" => {
                        controller.write_response(&Response::ok("OK")).await?;
                    }
                    "RSET" => {
                        #[cfg(any(feature = "native-tls-backend", feature = "rustls-backend"))]
                        if session.smtp_config.tls_mode.tls_mandatory() && !controller.is_tls {
                            controller
                                .write_line("530 5.7.0 Must issue a STARTTLS command first")
                                .await?;
                            break;
                        }
                        reset_transaction(&mut session, &mut handler).await?;
                        controller.write_response(&Response::ok("OK")).await?;
                    }
                    "AUTH" => {
                        #[cfg(any(feature = "native-tls-backend", feature = "rustls-backend"))]
                        let secure = controller.is_tls;
                        #[cfg(not(any(
                            feature = "native-tls-backend",
                            feature = "rustls-backend"
                        )))]
                        let secure = false;
                        if !secure {
                            controller
                                .write_line("538 5.7.11 Encryption required")
                                .await?;
                            continue;
                        }
                        match get_auth_data(args, &mut session, &mut controller).await {
                            Ok(auth_data) => {
                                match handler.handle_auth(&session, auth_data).await {
                                    Ok(res) => {
                                        session.authenticated = true;
                                        controller
                                            .write_response(&if res.is_default() {
                                                Response::auth_successful()
                                            } else {
                                                res
                                            })
                                            .await?;
                                    }
                                    Err(e) => {
                                        controller
                                            .write_response(&match e {
                                                Error::Response(res) if !res.is_default() => res,
                                                _ => Response::Raw(
                                                    "535 5.7.8 Authentication credentials invalid"
                                                        .into(),
                                                ),
                                            })
                                            .await?;
                                        break;
                                    }
                                };
                            }
                            Err(err) => {
                                let res: Response = err.try_into()?;
                                controller.write_response(&res).await?;
                                break;
                            }
                        };
                    }
                    "DATA" => {
                        let result = tokio::time::timeout(config.transaction_timeout, async {
                            if args.is_some_and(|a| !a.is_empty()) {
                                return Err(CoreError::Response(Response::syntax_error(
                                    "DATA takes no arguments",
                                )));
                            }
                            validate_data(&session)?;
                            handler
                                .handle_data_start(&session)
                                .await
                                .map_err(CoreError::Handler)?;
                            controller
                                .write_line("354 End data with <CRLF>.<CRLF>")
                                .await?;
                            controller
                                .stream_mail_data(config.max_message_size, &session, &mut handler)
                                .await?;
                            handler
                                .handle_data_end(&session)
                                .await
                                .map_err(CoreError::Handler)
                        })
                        .await;
                        match result {
                            Ok(Ok(response)) => {
                                controller
                                    .write_response(&if response.is_default() {
                                        Response::ok("Accepted")
                                    } else {
                                        response
                                    })
                                    .await?;
                                reset_transaction(&mut session, &mut handler).await?;
                            }
                            failed => {
                                let _ = tokio::time::timeout(
                                    config.timeout,
                                    handler.handle_data_abort(&session),
                                )
                                .await;
                                reset_transaction(&mut session, &mut handler).await?;
                                let error = match failed {
                                    Ok(Err(e)) => e,
                                    Err(_) => CoreError::Timeout,
                                    _ => unreachable!(),
                                };
                                let close = matches!(error, CoreError::Timeout | CoreError::Io);
                                let response: Response = match error.try_into() {
                                    Ok(response) => response,
                                    Err(_) => break,
                                };
                                controller.write_response(&response).await?;
                                if close {
                                    break;
                                }
                            }
                        }
                    }
                    "XCLIENT" => {
                        // XCLIENT rewrites trusted peer metadata. Never acknowledge it
                        // when the extension is unconfigured, the peer is outside the
                        // allowlist or a mail transaction is already open.
                        if session.smtp_config.x_client_allowed.is_none() {
                            controller
                                .write_response(&Response::not_implemented())
                                .await?;
                            continue;
                        }
                        if !session.x_client_trust {
                            controller
                                .write_response(&Response::new(
                                    550,
                                    "XCLIENT not permitted for this peer",
                                    Some("5.7.1".into()),
                                ))
                                .await?;
                            continue;
                        }
                        if session.got_from || !session.to.is_empty() {
                            controller
                                .write_response(&Response::bad_sequence(
                                    "XCLIENT not permitted during a mail transaction",
                                ))
                                .await?;
                            continue;
                        }

                        session.x_client = args.unwrap_or_default().to_string();

                        if session.x_client_trust {
                            for item in session.x_client.split_whitespace() {
                                if let Some((k, v)) = item.trim().split_once("=") {
                                    if k.eq_ignore_ascii_case("ADDR")
                                        && std::net::IpAddr::from_str(v).is_ok()
                                    {
                                        session.x_client_addr.clear();
                                        session.x_client_addr.push_str(v);
                                    }

                                    if k.eq_ignore_ascii_case("NAME")
                                        && !v.is_empty()
                                        && !v.eq_ignore_ascii_case("[UNAVAILABLE]")
                                    {
                                        session.x_client_name.clear();
                                        session.x_client_name.push_str(v);
                                    }
                                }
                            }

                            if session.x_client_addr.len() > 7 {
                                session.remote_ip = session.x_client_addr.to_owned();

                                if session.x_client_name.len() > 4 {
                                    session.remote_host = session.x_client_name.to_owned();
                                } else {
                                    if let Ok(ip) = IpAddr::from_str(&session.remote_ip) {
                                        session.remote_host = get_remote_host(
                                            ip,
                                            &resolver,
                                            session.smtp_config.timeout,
                                        )
                                        .await;
                                    } else {
                                        session.remote_host = "unknown".to_string();
                                    }
                                }
                            }
                        }

                        controller.write_response(&Response::ok("Ok")).await?;
                    }
                    "HELP" | "VRFY" | "EXPN" => {
                        controller
                            .write_response(&Response::not_implemented())
                            .await?;
                    }
                    "MAIL" => {
                        reset_transaction(&mut session, &mut handler).await?;
                        if let Err(err) = handle_mail_cmd(args, &mut session, &mut controller).await
                        {
                            let res: Response = err.try_into()?;
                            controller.write_response(&res).await?;
                        }
                    }
                    "RCPT" => {
                        match extract_rcpt_from_arg(args, &mut session).await {
                            Ok(to) => {
                                match handler.handle_rcpt(&session, &to).await {
                                    Ok(res) => {
                                        session.to.push(to);

                                        controller
                                            .write_response(&if res.is_default() {
                                                Response::Raw("250 2.1.5 Ok".into())
                                            } else {
                                                res
                                            })
                                            .await?;
                                    }
                                    Err(e) => {
                                        // A refused recipient is a per-recipient result:
                                        // keep the transaction and connection usable for
                                        // later RCPT commands. Only an explicit abort or an
                                        // unwritable response closes the session.
                                        let response = match e {
                                            Error::Abort => break,
                                            Error::Response(res) if !res.is_default() => res,
                                            _ => Response::Raw("550 5.1.0 Requested action not taken: mailbox unavailable".into()),
                                        };
                                        controller.write_response(&response).await?;
                                    }
                                };
                            }

                            Err(err) => {
                                let res: Response = err.try_into()?;
                                controller.write_response(&res).await?;
                                // A malformed or over-limit RCPT leaves the already
                                // accepted envelope available for a corrected command.
                            }
                        };
                    }
                    _ => {
                        // See RFC 5321 section 4.2.4 for usage of 500 & 502 response codes.
                        controller
                            .write_response(&Response::Raw(
                                "500 5.5.2 Syntax error, command unrecognized".into(),
                            ))
                            .await?;
                    }
                }
            }
            Err(e) => {
                eprintln!("Error: {e}");
                let res: Response = e.try_into()?;
                controller.write_response(&res).await?;
                break;
            }
        }
    }

    Ok(())
}

async fn reset_transaction<H: SmtpHandler>(
    session: &mut crate::Session<'_>,
    handler: &mut H,
) -> Result<(), CoreError> {
    tokio::time::timeout(session.smtp_config.timeout, handler.handle_reset(session))
        .await?
        .map_err(CoreError::Handler)?;
    session.reset();
    Ok(())
}
