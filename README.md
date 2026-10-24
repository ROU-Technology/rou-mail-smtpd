# smtpd

> ⚠️ **BETA** — Use with caution, API may change

`smtpd` is an asynchronous, extensible SMTP server library built on top of `tokio`.
Inspired by [smtpd](https://github.com/mhale/smtpd).
It provides flexible support for authentication, TLS, and custom handling
of SMTP commands.

### Features
- Asynchronous SMTP server using Tokio.
- Supports authentication mechanisms: [`AuthMach::Plain`], [`AuthMach::Login`], [`AuthMach::CramMD5`].
- TLS support (STARTTLS and implicit TLS) with optional `native-tls` (feature `native-tls-backend`) or `rustls` (feature `rustls-backend`) backend.
- Customizable handlers for AUTH, RCPT, and DATA commands via the Handler struct's [`SmtpHandler::handle_auth`], [`SmtpHandler::handle_email`], and [`SmtpHandler::handle_rcpt`] method
- Configurable limits for message size and recipients.

### Example
```rust
use smtpd::{async_trait, start_server, SmtpConfig, AuthMach};

#[tokio::main]
async fn main() -> Result<(), std::io::Error> {
    let config = SmtpConfig {
        bind_addr: "127.0.0.1:2525".to_string(),
        require_auth: true,
        auth_machs: vec![AuthMach::Plain, AuthMach::Login],
        ..Default::default()
    };

    let factory = MyHandlerFactory {};

    start_server(config, factory).await?;
    Ok(())
}

struct MyHandler {}

#[async_trait]
impl smtpd::SmtpHandler for MyHandler {
    async fn handle_auth(
        &mut self,
        _session: &smtpd::Session,
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
        _session: &smtpd::Session,
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

    fn new_handler(&self, _session: &smtpd::Session) -> Self::Handler {
        MyHandler {}
    }
}
```

### Modules
- `session`: Represents a client session.
- `handler`: Defines traits for handling SMTP commands.
- `tls`: TLS configuration and provider utilities.
- `stream`: Connection stream abstraction with read/write helpers.
- `utils`: Parsing and helper functions for SMTP commands.


## Complete cross-repository library coverage

Read [the complete supplied-library map](https://github.com/ROU-Technology/email/blob/codex/product-engine-alignment/docs/product-plan/advancements/library-integration-map.md) and [direct receiving contract](https://github.com/ROU-Technology/email/blob/codex/product-engine-alignment/docs/product-plan/advancements/direct-inbound-contract.md). Reference/later components retain detailed implementation plans and canonical issues. A dependency build does not complete these features.
