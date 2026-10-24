use smtpd::{
    Error, Response, Session, SmtpConfig, SmtpHandler, SmtpHandlerFactory, SmtpServer, async_trait,
};
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream},
    sync::oneshot,
};

#[derive(Default)]
struct Observed {
    chunks: Vec<Vec<u8>>,
    envelopes: Vec<(String, Vec<String>)>,
    peers: Vec<(String, String)>,
    finishes: usize,
    aborts: usize,
    reset_envelopes: Vec<Vec<String>>,
}
#[derive(Clone)]
struct Factory {
    state: Arc<Mutex<Observed>>,
    refuse_commit: bool,
    stall_chunk: bool,
}
struct Handler(Factory);
impl SmtpHandlerFactory for Factory {
    type Handler = Handler;
    fn new_handler(&self, _: &Session<'_>) -> Handler {
        Handler(self.clone())
    }
}
#[async_trait]
impl SmtpHandler for Handler {
    async fn handle_rcpt(&mut self, _: &Session<'_>, _: &str) -> smtpd::Result {
        Ok(Response::default())
    }
    async fn handle_reset(&mut self, session: &Session<'_>) -> Result<(), Error> {
        self.0
            .state
            .lock()
            .unwrap()
            .reset_envelopes
            .push(session.to.clone());
        Ok(())
    }
    async fn handle_data_start(&mut self, s: &Session<'_>) -> Result<(), Error> {
        let mut state = self.0.state.lock().unwrap();
        state.envelopes.push((s.from.clone(), s.to.clone()));
        state
            .peers
            .push((s.remote_ip.clone(), s.remote_host.clone()));
        Ok(())
    }
    async fn handle_data_chunk(&mut self, _: &Session<'_>, bytes: &[u8]) -> Result<(), Error> {
        if self.0.stall_chunk {
            std::future::pending::<()>().await;
        }
        self.0.state.lock().unwrap().chunks.push(bytes.to_vec());
        Ok(())
    }
    async fn handle_data_end(&mut self, _: &Session<'_>) -> smtpd::Result {
        self.0.state.lock().unwrap().finishes += 1;
        if self.0.refuse_commit {
            return Err(Error::Response(Response::new(
                451,
                "Commit unavailable",
                None,
            )));
        }
        Ok(Response::ok("Durably accepted"))
    }
    async fn handle_data_abort(&mut self, _: &Session<'_>) {
        self.0.state.lock().unwrap().aborts += 1;
    }
}
async fn start(
    mut config: SmtpConfig,
    refuse_commit: bool,
    stall_chunk: bool,
) -> (
    u16,
    oneshot::Sender<()>,
    tokio::task::JoinHandle<std::io::Result<()>>,
    Arc<Mutex<Observed>>,
) {
    config.disable_reverse_dns = true;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let state = Arc::new(Mutex::new(Observed::default()));
    let factory = Factory {
        state: state.clone(),
        refuse_commit,
        stall_chunk,
    };
    let (stop, signal) = oneshot::channel();
    let task = tokio::spawn(
        SmtpServer::new(config, factory).serve_until(listener, async {
            let _ = signal.await;
        }),
    );
    (port, stop, task, state)
}
async fn connect(port: u16) -> BufReader<TcpStream> {
    let mut client = BufReader::new(TcpStream::connect(("127.0.0.1", port)).await.unwrap());
    assert!(reply(&mut client).await.starts_with("220 "));
    client
}
async fn reply(client: &mut BufReader<TcpStream>) -> String {
    let mut all = String::new();
    loop {
        let mut line = String::new();
        tokio::time::timeout(Duration::from_secs(2), client.read_line(&mut line))
            .await
            .unwrap()
            .unwrap();
        assert!(!line.is_empty(), "unexpected EOF: {all}");
        assert!(
            line.ends_with("\r\n"),
            "SMTP response must use CRLF: {line:?}"
        );
        let more = line.as_bytes().get(3) == Some(&b'-');
        all.push_str(&line);
        if !more {
            return all;
        }
    }
}
async fn command(client: &mut BufReader<TcpStream>, command: &[u8]) -> String {
    client.get_mut().write_all(command).await.unwrap();
    reply(client).await
}
async fn envelope(client: &mut BufReader<TcpStream>) {
    let ehlo = command(client, b"EHLO sender.example\r\n").await;
    assert!(ehlo.starts_with("250-"));
    assert!(!ehlo.contains("AUTH"));
    assert!(!ehlo.contains("STARTTLS"));
    assert!(
        command(client, b"MAIL FROM:<>\r\n")
            .await
            .starts_with("250")
    );
    assert!(
        command(client, b"RCPT TO:<receiver@example.org>\r\n")
            .await
            .starts_with("250")
    );
}

#[tokio::test]
async fn streams_exact_bytes_and_resets_each_transaction() {
    let (port, stop, task, state) = start(SmtpConfig::default(), false, false).await;
    let mut client = connect(port).await;
    envelope(&mut client).await;
    assert!(command(&mut client, b"DATA\r\n").await.starts_with("354"));
    assert!(
        command(&mut client, b"Subject: exact\r\n\r\n..binary\xff\r\n.\r\n")
            .await
            .starts_with("250")
    );
    assert!(
        command(&mut client, b"RCPT TO:<stale@example.org>\r\n")
            .await
            .starts_with("503")
    );
    drop(client);
    let observed = state.lock().unwrap();
    assert_eq!(
        observed.chunks.concat(),
        b"Subject: exact\r\n\r\n.binary\xff\r\n"
    );
    assert_eq!(observed.finishes, 1);
    assert_eq!(
        observed.envelopes,
        [(String::new(), vec!["receiver@example.org".into()])]
    );
    drop(observed);
    stop.send(()).unwrap();
    task.await.unwrap().unwrap();
}

#[tokio::test]
async fn failed_durable_commit_never_gets_success_reply() {
    let (port, stop, task, state) = start(SmtpConfig::default(), true, false).await;
    let mut client = connect(port).await;
    envelope(&mut client).await;
    assert!(command(&mut client, b"DATA\r\n").await.starts_with("354"));
    assert!(
        command(&mut client, b"body\r\n.\r\n")
            .await
            .starts_with("451")
    );
    assert_eq!(state.lock().unwrap().aborts, 1);
    drop(client);
    stop.send(()).unwrap();
    task.await.unwrap().unwrap();
}

#[tokio::test]
async fn enforces_total_message_limit_and_never_finalises() {
    let config = SmtpConfig {
        max_message_size: 4,
        ..Default::default()
    };
    let (port, stop, task, state) = start(config, false, false).await;
    let mut client = connect(port).await;
    envelope(&mut client).await;
    assert!(command(&mut client, b"DATA\r\n").await.starts_with("354"));
    assert!(
        !command(&mut client, b"hello\r\n.\r\n")
            .await
            .starts_with("250")
    );
    assert_eq!(state.lock().unwrap().finishes, 0);
    assert_eq!(state.lock().unwrap().aborts, 1);
    drop(client);
    stop.send(()).unwrap();
    task.await.unwrap().unwrap();
}

#[tokio::test]
async fn callback_deadline_aborts_without_acceptance() {
    let config = SmtpConfig {
        transaction_timeout: Duration::from_millis(80),
        ..Default::default()
    };
    let (port, stop, task, state) = start(config, false, true).await;
    let mut client = connect(port).await;
    envelope(&mut client).await;
    assert!(command(&mut client, b"DATA\r\n").await.starts_with("354"));
    assert!(
        command(&mut client, b"body\r\n.\r\n")
            .await
            .starts_with("421")
    );
    assert_eq!(state.lock().unwrap().finishes, 0);
    assert_eq!(state.lock().unwrap().aborts, 1);
    drop(client);
    stop.send(()).unwrap();
    task.await.unwrap().unwrap();
}

#[tokio::test]
async fn rejected_second_mail_clears_old_envelope() {
    let (port, stop, task, state) = start(SmtpConfig::default(), false, false).await;
    let mut client = connect(port).await;
    envelope(&mut client).await;
    assert!(
        command(&mut client, b"MAIL garbage\r\n")
            .await
            .starts_with("501")
    );
    assert!(command(&mut client, b"DATA\r\n").await.starts_with("503"));
    assert!(state.lock().unwrap().chunks.is_empty());
    drop(client);
    stop.send(()).unwrap();
    task.await.unwrap().unwrap();
}

#[tokio::test]
async fn malformed_data_is_rejected_without_newline_repair() {
    let (port, stop, task, state) = start(SmtpConfig::default(), false, false).await;
    let mut client = connect(port).await;
    envelope(&mut client).await;
    assert!(command(&mut client, b"DATA\r\n").await.starts_with("354"));
    assert!(
        command(&mut client, b"tampered\n.\r\n")
            .await
            .starts_with("501")
    );
    assert_eq!(state.lock().unwrap().finishes, 0);
    drop(client);
    stop.send(()).unwrap();
    task.await.unwrap().unwrap();
}

#[tokio::test]
async fn finite_shutdown_cancels_idle_connections() {
    let config = SmtpConfig {
        shutdown_timeout: Duration::from_millis(50),
        ..Default::default()
    };
    let (port, stop, task, _) = start(config, false, false).await;
    let _client = connect(port).await;
    stop.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(1), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn connection_capacity_is_bounded_and_other_sessions_remain_usable() {
    use tokio::io::AsyncReadExt;
    let config = SmtpConfig {
        max_connections: 2,
        max_connections_per_ip: 2,
        max_tls_handshakes: 2,
        ..Default::default()
    };
    let (port, stop, task, _) = start(config, false, false).await;
    let mut first = connect(port).await;
    let second = connect(port).await;
    let mut excess = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let mut byte = [0];
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(1), excess.read(&mut byte))
            .await
            .unwrap()
            .unwrap(),
        0
    );
    assert!(command(&mut first, b"NOOP\r\n").await.starts_with("250"));
    drop(first);
    drop(second);
    drop(excess);
    stop.send(()).unwrap();
    task.await.unwrap().unwrap();
}

#[tokio::test]
async fn no_unwired_handler_can_accept_a_recipient() {
    struct Unwired;
    #[async_trait]
    impl SmtpHandler for Unwired {}
    struct UnwiredFactory;
    impl SmtpHandlerFactory for UnwiredFactory {
        type Handler = Unwired;
        fn new_handler(&self, _: &Session<'_>) -> Unwired {
            Unwired
        }
    }
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let (stop, signal) = oneshot::channel();
    let config = SmtpConfig {
        disable_reverse_dns: true,
        ..Default::default()
    };
    let task = tokio::spawn(
        SmtpServer::new(config, UnwiredFactory).serve_until(listener, async {
            let _ = signal.await;
        }),
    );
    let mut client = connect(port).await;
    assert!(
        command(&mut client, b"EHLO test.example\r\n")
            .await
            .starts_with("250")
    );
    assert!(
        command(&mut client, b"MAIL FROM:<>\r\n")
            .await
            .starts_with("250")
    );
    assert!(
        command(&mut client, b"RCPT TO:<test@example.org>\r\n")
            .await
            .starts_with("502")
    );
    drop(client);
    stop.send(()).unwrap();
    task.await.unwrap().unwrap();
}

#[cfg(feature = "rustls-backend")]
#[tokio::test]
async fn invalid_and_stalled_tls_clients_cannot_stop_listener() {
    use tokio::io::AsyncReadExt;
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let rcgen::CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(signing_key.serialize_der().into());
    let tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert.der().clone()], key)
        .unwrap();
    let config = SmtpConfig {
        tls_mode: smtpd::TlsMode::Implicit(smtpd::TlsConfig::Rustls(tls)),
        max_connections: 4,
        max_connections_per_ip: 4,
        max_tls_handshakes: 3,
        timeout: Duration::from_secs(2),
        ..Default::default()
    };
    let (port, stop, task, _) = start(config, false, false).await;
    let stalled = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let mut invalid = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    invalid.write_all(b"not TLS\r\n").await.unwrap();
    let mut byte = [0];
    let _ = tokio::time::timeout(Duration::from_secs(1), invalid.read(&mut byte))
        .await
        .unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert.der().clone()).unwrap();
    let client_config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let client = tokio_rustls::TlsConnector::from(Arc::new(client_config));
    let stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let secured = tokio::time::timeout(
        Duration::from_secs(1),
        client.connect("localhost".try_into().unwrap(), stream),
    )
    .await
    .unwrap()
    .unwrap();
    let mut reader = BufReader::new(secured);
    let mut line = String::new();
    reader.read_line(&mut line).await.unwrap();
    assert!(line.starts_with("220 "));
    reader
        .get_mut()
        .write_all(b"EHLO tls.example\r\n")
        .await
        .unwrap();
    let mut capabilities = String::new();
    loop {
        line.clear();
        reader.read_line(&mut line).await.unwrap();
        let more = line.as_bytes().get(3) == Some(&b'-');
        capabilities.push_str(&line);
        if !more {
            break;
        }
    }
    assert!(
        !capabilities.contains("STARTTLS"),
        "TLS session cannot offer another TLS upgrade"
    );
    assert!(!task.is_finished());
    drop(reader);
    drop(stalled);
    drop(invalid);
    stop.send(()).unwrap();
    task.await.unwrap().unwrap();
}

#[tokio::test]
async fn refuses_zero_or_contradictory_budgets_before_listening() {
    for config in [
        SmtpConfig {
            max_connections: usize::MAX,
            ..Default::default()
        },
        SmtpConfig {
            connection_timeout: Duration::MAX,
            ..Default::default()
        },
        SmtpConfig {
            max_message_size: 0,
            ..Default::default()
        },
        SmtpConfig {
            max_line_bytes: 0,
            ..Default::default()
        },
        SmtpConfig {
            max_connections: 0,
            ..Default::default()
        },
        SmtpConfig {
            max_connections_per_ip: 0,
            ..Default::default()
        },
        SmtpConfig {
            max_connections: 2,
            max_connections_per_ip: 3,
            ..Default::default()
        },
        SmtpConfig {
            require_auth: true,
            auth_machs: vec![],
            ..Default::default()
        },
        SmtpConfig {
            max_tls_handshakes: 129,
            ..Default::default()
        },
    ] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let factory = Factory {
            state: Default::default(),
            refuse_commit: false,
            stall_chunk: false,
        };
        let result = SmtpServer::new(config, factory)
            .serve_until(listener, std::future::pending())
            .await;
        assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::InvalidInput);
    }
}

#[tokio::test]
async fn rset_notifies_handler_and_discards_previous_recipients() {
    let (port, stop, task, state) = start(SmtpConfig::default(), false, false).await;
    let mut client = connect(port).await;
    envelope(&mut client).await;
    assert!(command(&mut client, b"RSET\r\n").await.starts_with("250"));
    assert!(
        state
            .lock()
            .unwrap()
            .reset_envelopes
            .contains(&vec!["receiver@example.org".to_string()])
    );
    assert!(command(&mut client, b"DATA\r\n").await.starts_with("503"));
    assert_eq!(state.lock().unwrap().finishes, 0);
    drop(client);
    stop.send(()).unwrap();
    task.await.unwrap().unwrap();
}

#[cfg(feature = "rustls-backend")]
#[tokio::test]
async fn starttls_discards_envelope_and_only_advertises_auth_after_encryption() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let rcgen::CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(signing_key.serialize_der().into());
    let tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert.der().clone()], key)
        .unwrap();
    let config = SmtpConfig {
        tls_mode: smtpd::TlsMode::Explicit(smtpd::TlsConfig::Rustls(tls)),
        auth_machs: vec![smtpd::AuthMach::Plain],
        ..Default::default()
    };
    let (port, stop, task, state) = start(config, false, false).await;
    let mut plain = connect(port).await;
    let caps = command(&mut plain, b"EHLO plain.example\r\n").await;
    assert!(caps.contains("STARTTLS"));
    assert!(!caps.contains("AUTH"));
    assert!(
        command(&mut plain, b"AUTH PLAIN AHVzZXIAc2VjcmV0\r\n")
            .await
            .starts_with("538")
    );
    assert!(
        command(&mut plain, b"MAIL FROM:<>\r\n")
            .await
            .starts_with("250")
    );
    assert!(
        command(&mut plain, b"RCPT TO:<old@example.org>\r\n")
            .await
            .starts_with("250")
    );
    assert!(
        command(&mut plain, b"STARTTLS\r\n")
            .await
            .starts_with("220")
    );
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert.der().clone()).unwrap();
    let client_config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));
    let secured = connector
        .connect("localhost".try_into().unwrap(), plain.into_inner())
        .await
        .unwrap();
    let mut secured = BufReader::new(secured);
    secured
        .get_mut()
        .write_all(b"EHLO secure.example\r\n")
        .await
        .unwrap();
    let mut capabilities = String::new();
    loop {
        let mut line = String::new();
        secured.read_line(&mut line).await.unwrap();
        let more = line.as_bytes().get(3) == Some(&b'-');
        capabilities.push_str(&line);
        if !more {
            break;
        }
    }
    assert!(capabilities.contains("AUTH PLAIN"));
    assert!(!capabilities.contains("STARTTLS"));
    secured.get_mut().write_all(b"STARTTLS\r\n").await.unwrap();
    let mut repeated = String::new();
    secured.read_line(&mut repeated).await.unwrap();
    assert!(repeated.starts_with("503"));
    secured.get_mut().write_all(b"NOOP\r\n").await.unwrap();
    let mut noop = String::new();
    secured.read_line(&mut noop).await.unwrap();
    assert!(noop.starts_with("250"));
    secured.get_mut().write_all(b"DATA\r\n").await.unwrap();
    let mut refusal = String::new();
    secured.read_line(&mut refusal).await.unwrap();
    assert!(refusal.starts_with("503"));
    assert_eq!(state.lock().unwrap().finishes, 0);
    drop(secured);
    stop.send(()).unwrap();
    task.await.unwrap().unwrap();
}

#[tokio::test]
async fn per_ip_admission_is_bounded_and_released() {
    use tokio::io::AsyncReadExt;
    let config = SmtpConfig {
        max_connections: 4,
        max_connections_per_ip: 1,
        max_tls_handshakes: 4,
        ..Default::default()
    };
    let (port, stop, task, _) = start(config, false, false).await;
    let first = connect(port).await;
    let mut excess = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let mut byte = [0];
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(1), excess.read(&mut byte))
            .await
            .unwrap()
            .unwrap(),
        0,
        "a second connection from the same peer must be refused"
    );
    drop(first);
    let mut admitted = None;
    for _ in 0..50 {
        tokio::time::sleep(Duration::from_millis(10)).await;
        if let Ok(stream) = TcpStream::connect(("127.0.0.1", port)).await {
            let mut reader = BufReader::new(stream);
            let mut greeting = String::new();
            if tokio::time::timeout(Duration::from_millis(200), reader.read_line(&mut greeting))
                .await
                .is_ok()
                && greeting.starts_with("220 ")
            {
                admitted = Some(reader);
                break;
            }
        }
    }
    let mut admitted = admitted.expect("peer slot must be released when the session ends");
    assert!(command(&mut admitted, b"NOOP\r\n").await.starts_with("250"));
    drop(admitted);
    drop(excess);
    stop.send(()).unwrap();
    task.await.unwrap().unwrap();
}

#[tokio::test]
async fn data_chunks_are_delivered_before_the_terminator() {
    let (port, stop, task, state) = start(SmtpConfig::default(), false, false).await;
    let mut client = connect(port).await;
    envelope(&mut client).await;
    assert!(command(&mut client, b"DATA\r\n").await.starts_with("354"));
    client
        .get_mut()
        .write_all(b"first-chunk\r\n")
        .await
        .unwrap();
    let mut seen = false;
    for _ in 0..100 {
        tokio::time::sleep(Duration::from_millis(5)).await;
        if state.lock().unwrap().chunks.concat() == b"first-chunk\r\n" {
            seen = true;
            break;
        }
    }
    assert!(
        seen,
        "DATA must stream to the sink without buffering the whole message"
    );
    assert!(command(&mut client, b".\r\n").await.starts_with("250"));
    assert_eq!(state.lock().unwrap().finishes, 1);
    drop(client);
    stop.send(()).unwrap();
    task.await.unwrap().unwrap();
}

#[tokio::test]
async fn oversized_command_line_is_refused_before_growth() {
    let config = SmtpConfig {
        max_line_bytes: 64,
        ..Default::default()
    };
    let (port, stop, task, _) = start(config, false, false).await;
    let mut client = connect(port).await;
    let mut command_line = b"MAIL FROM:<".to_vec();
    command_line.extend(std::iter::repeat(b'x').take(256));
    command_line.extend_from_slice(b">\r\n");
    assert!(command(&mut client, &command_line).await.starts_with("552"));
    let mut fresh = connect(port).await;
    assert!(command(&mut fresh, b"NOOP\r\n").await.starts_with("250"));
    drop(client);
    drop(fresh);
    stop.send(()).unwrap();
    task.await.unwrap().unwrap();
}

#[tokio::test]
async fn oversized_data_line_aborts_without_finalising() {
    let config = SmtpConfig {
        max_line_bytes: 32,
        max_message_size: 1024,
        ..Default::default()
    };
    let (port, stop, task, state) = start(config, false, false).await;
    let mut client = connect(port).await;
    envelope(&mut client).await;
    assert!(command(&mut client, b"DATA\r\n").await.starts_with("354"));
    let mut line = vec![b'y'; 100];
    line.extend_from_slice(b"\r\n.\r\n");
    assert!(!command(&mut client, &line).await.starts_with("250"));
    assert_eq!(state.lock().unwrap().finishes, 0);
    assert_eq!(state.lock().unwrap().aborts, 1);
    drop(client);
    stop.send(()).unwrap();
    task.await.unwrap().unwrap();
}

#[tokio::test]
async fn xclient_is_refused_when_unconfigured_or_untrusted() {
    let (port, stop, task, _) = start(SmtpConfig::default(), false, false).await;
    let mut client = connect(port).await;
    assert!(
        command(&mut client, b"EHLO x.example\r\n")
            .await
            .starts_with("250")
    );
    assert!(
        command(&mut client, b"XCLIENT ADDR=203.0.113.9\r\n")
            .await
            .starts_with("502")
    );
    drop(client);
    stop.send(()).unwrap();
    task.await.unwrap().unwrap();

    let config = SmtpConfig {
        x_client_allowed: Some(vec!["10.0.0.1".into()]),
        ..Default::default()
    };
    let (port, stop, task, _) = start(config, false, false).await;
    let mut client = connect(port).await;
    assert!(
        command(&mut client, b"EHLO x.example\r\n")
            .await
            .starts_with("250")
    );
    assert!(
        command(&mut client, b"XCLIENT ADDR=203.0.113.9\r\n")
            .await
            .starts_with("550")
    );
    assert!(
        command(&mut client, b"MAIL FROM:<>\r\n")
            .await
            .starts_with("250")
    );
    drop(client);
    stop.send(()).unwrap();
    task.await.unwrap().unwrap();
}

#[tokio::test]
async fn trusted_xclient_applies_peer_metadata_only_before_a_transaction() {
    let config = SmtpConfig {
        x_client_allowed: Some(vec!["127.0.0.1".into()]),
        ..Default::default()
    };
    let (port, stop, task, state) = start(config, false, false).await;
    let mut client = connect(port).await;
    assert!(
        command(&mut client, b"EHLO x.example\r\n")
            .await
            .starts_with("250")
    );
    assert!(
        command(
            &mut client,
            b"XCLIENT ADDR=203.0.113.9 NAME=mail.example\r\n"
        )
        .await
        .starts_with("250")
    );
    assert!(
        command(&mut client, b"MAIL FROM:<sender@example.org>\r\n")
            .await
            .starts_with("250")
    );
    assert!(
        command(&mut client, b"XCLIENT ADDR=198.51.100.1\r\n")
            .await
            .starts_with("503")
    );
    assert!(
        command(&mut client, b"RCPT TO:<receiver@example.org>\r\n")
            .await
            .starts_with("250")
    );
    assert!(command(&mut client, b"DATA\r\n").await.starts_with("354"));
    assert!(
        command(&mut client, b"body\r\n.\r\n")
            .await
            .starts_with("250")
    );
    let observed = state.lock().unwrap();
    assert_eq!(
        observed.peers,
        [("203.0.113.9".to_string(), "mail.example".to_string())]
    );
    drop(observed);
    drop(client);
    stop.send(()).unwrap();
    task.await.unwrap().unwrap();
}

#[tokio::test]
async fn refused_recipient_does_not_close_the_transaction() {
    struct Selective;
    #[async_trait]
    impl SmtpHandler for Selective {
        async fn handle_rcpt(&mut self, _: &Session<'_>, to: &str) -> smtpd::Result {
            if to == "unknown@example.org" {
                Err(Error::Response(Response::new(
                    550,
                    "No such mailbox",
                    Some("5.1.1".into()),
                )))
            } else {
                Ok(Response::default())
            }
        }
        async fn handle_data_start(&mut self, _: &Session<'_>) -> Result<(), Error> {
            Ok(())
        }
        async fn handle_data_chunk(&mut self, _: &Session<'_>, _: &[u8]) -> Result<(), Error> {
            Ok(())
        }
        async fn handle_data_end(&mut self, _: &Session<'_>) -> smtpd::Result {
            Ok(Response::ok("Accepted"))
        }
    }
    struct SelectiveFactory;
    impl SmtpHandlerFactory for SelectiveFactory {
        type Handler = Selective;
        fn new_handler(&self, _: &Session<'_>) -> Selective {
            Selective
        }
    }
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let (stop, signal) = oneshot::channel();
    let config = SmtpConfig {
        disable_reverse_dns: true,
        ..Default::default()
    };
    let task = tokio::spawn(SmtpServer::new(config, SelectiveFactory).serve_until(
        listener,
        async {
            let _ = signal.await;
        },
    ));
    let mut client = connect(port).await;
    assert!(
        command(&mut client, b"EHLO test.example\r\n")
            .await
            .starts_with("250")
    );
    assert!(
        command(&mut client, b"MAIL FROM:<>\r\n")
            .await
            .starts_with("250")
    );
    assert!(
        command(&mut client, b"RCPT TO:<unknown@example.org>\r\n")
            .await
            .starts_with("550")
    );
    assert!(
        command(&mut client, b"RCPT TO:<known@example.org>\r\n")
            .await
            .starts_with("250")
    );
    assert!(command(&mut client, b"DATA\r\n").await.starts_with("354"));
    assert!(
        command(&mut client, b"body\r\n.\r\n")
            .await
            .starts_with("250")
    );
    drop(client);
    stop.send(()).unwrap();
    task.await.unwrap().unwrap();
}

#[tokio::test]
async fn temporary_data_failure_resets_and_allows_a_retry() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    struct Retrying(Arc<AtomicUsize>);
    #[async_trait]
    impl SmtpHandler for Retrying {
        async fn handle_rcpt(&mut self, _: &Session<'_>, _: &str) -> smtpd::Result {
            Ok(Response::default())
        }
        async fn handle_data_start(&mut self, _: &Session<'_>) -> Result<(), Error> {
            Ok(())
        }
        async fn handle_data_chunk(&mut self, _: &Session<'_>, _: &[u8]) -> Result<(), Error> {
            Ok(())
        }
        async fn handle_data_end(&mut self, _: &Session<'_>) -> smtpd::Result {
            if self.0.fetch_add(1, Ordering::SeqCst) == 0 {
                Err(Error::Response(Response::new(
                    451,
                    "Storage temporarily unavailable",
                    Some("4.3.0".into()),
                )))
            } else {
                Ok(Response::ok("Accepted"))
            }
        }
    }
    struct RetryingFactory(Arc<AtomicUsize>);
    impl SmtpHandlerFactory for RetryingFactory {
        type Handler = Retrying;
        fn new_handler(&self, _: &Session<'_>) -> Retrying {
            Retrying(self.0.clone())
        }
    }
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let (stop, signal) = oneshot::channel();
    let config = SmtpConfig {
        disable_reverse_dns: true,
        ..Default::default()
    };
    let attempts = Arc::new(AtomicUsize::new(0));
    let task = tokio::spawn(
        SmtpServer::new(config, RetryingFactory(attempts.clone())).serve_until(listener, async {
            let _ = signal.await;
        }),
    );
    let mut client = connect(port).await;
    envelope(&mut client).await;
    assert!(command(&mut client, b"DATA\r\n").await.starts_with("354"));
    assert!(
        command(&mut client, b"first\r\n.\r\n")
            .await
            .starts_with("451")
    );
    assert!(
        command(&mut client, b"MAIL FROM:<>\r\n")
            .await
            .starts_with("250")
    );
    assert!(
        command(&mut client, b"RCPT TO:<receiver@example.org>\r\n")
            .await
            .starts_with("250")
    );
    assert!(command(&mut client, b"DATA\r\n").await.starts_with("354"));
    assert!(
        command(&mut client, b"second\r\n.\r\n")
            .await
            .starts_with("250")
    );
    assert_eq!(attempts.load(Ordering::SeqCst), 2);
    drop(client);
    stop.send(()).unwrap();
    task.await.unwrap().unwrap();
}
