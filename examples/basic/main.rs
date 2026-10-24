use smtpd::AuthMach;

#[tokio::main]
async fn main() -> Result<(), std::io::Error> {
    let config = smtpd::SmtpConfig {
        bind_addr: "127.0.0.1:2525".to_string(),
        require_auth: true,
        auth_machs: vec![AuthMach::Plain, AuthMach::Login],
        ..Default::default()
    };

    let factory = MyHandlerFactory {};

    println!("Starting SMTP server on {}", config.bind_addr);
    smtpd::start_server(config, factory).await?;

    Ok(())
}

struct MyHandler {}

#[smtpd::async_trait]
impl smtpd::SmtpHandler for MyHandler {
    async fn handle_auth(
        &mut self,
        _session: &smtpd::Session<'_>,
        data: smtpd::AuthData,
    ) -> Result<smtpd::Response, smtpd::Error> {
        let (username, password, _) = data.data();

        if username == "abc" && password == "efg" {
            return Ok(smtpd::Response::Default);
        }

        Err(smtpd::Error::Abort)
    }

    async fn handle_rcpt(
        &mut self,
        _session: &smtpd::Session<'_>,
        to: &str,
    ) -> Result<smtpd::Response, smtpd::Error> {
        // allow recipients only from gmail
        if to.ends_with("gmail.com") {
            return Ok(smtpd::Response::Default);
        }

        Err(smtpd::Error::Abort)
    }
}

struct MyHandlerFactory;

impl smtpd::SmtpHandlerFactory for MyHandlerFactory {
    type Handler = MyHandler;

    fn new_handler(&self, _session: &smtpd::Session<'_>) -> Self::Handler {
        MyHandler {}
    }
}
