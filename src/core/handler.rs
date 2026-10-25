use crate::{AuthData, Error, Response, Result, Session};

/// Defines the async hook interface for handling key SMTP events:
/// authentication (`AUTH`), recipient validation (`RCPT TO`), and message delivery (`DATA`).
///
/// Implement this trait to define how your SMTP server should respond
/// to client commands during an SMTP session.
///
/// - The **AUTH** handler must be implemented explicitly; otherwise,
///   authentication requests will return `502 Not Implemented`.
/// - Recipient and DATA hooks refuse by default; implement durable acceptance explicitly.
///
/// # Example
///
/// ```no_run
/// use smtpd::{async_trait, SmtpHandler, SmtpHandlerFactory, Session, AuthData, Response, Error, Result};
///
/// struct MyHandler {
///     user_id: Option<usize>,
/// }
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
///         // Simulate authentication (could be a DB or API call)
///         if username == "abc" && password == "efg" {
///             self.user_id = Some(1);
///             return Ok(Response::default());
///         }
///
///         Err(Error::Response(Response::reject("Invalid credentials")))
///     }
///
///     async fn handle_rcpt(
///         &mut self,
///         _session: &Session<'_>,
///         to: &str,
///     ) -> Result {
///         if to.ends_with("gmail.com") {
///             Ok(Response::default())
///         } else {
///             Err(Error::Response(Response::reject(
///                 "Only Gmail addresses allowed",
///             )))
///         }
///     }
///
///     async fn handle_data_end(
///         &mut self,
///         _session: &Session<'_>,
///     ) -> Result {
///         Ok(Response::ok("Ok: queued as <message-id>"))
///     }
/// }
///
/// struct MyHandlerFactory;
///
/// impl SmtpHandlerFactory for MyHandlerFactory {
///     type Handler = MyHandler;
///
///     fn new_handler(&self, _session: &Session<'_>) -> Self::Handler {
///         MyHandler { user_id: None }
///     }
/// }
/// ```
///
/// ## Default Behavior
///
/// | Method | Default Response | Description |
/// |--------|------------------|--------------|
/// | [`handle_auth`](Self::handle_auth) | `502 Not Implemented` | Must be implemented explicitly. |
/// | [`handle_rcpt`](Self::handle_rcpt) | `502 Not Implemented` | Refuses unwired recipients. |
/// | [`handle_data_end`](Self::handle_data_end) | `502 Not Implemented` | Refuses unwired messages. |
///
///
/// ## How It Works
///
/// - The SMTP server creates a **new handler** for every client session using
///   an implementation of [`SmtpHandlerFactory`].
/// - This design ensures **per-connection isolation** — e.g., you can store
///   per-session state (like authenticated user data) safely inside the handler.
/// - All handler methods are **async**, so you can perform asynchronous tasks
///   like querying a database, performing DNS lookups, or calling external APIs.
///
///
/// ## Example Factory Relationship
///
/// ```no_run
/// use smtpd::{async_trait, SmtpHandlerFactory, SmtpHandler, Session};
///
/// struct MyHandler { user_id: Option<usize> }
///
/// #[async_trait]
/// impl SmtpHandler for MyHandler{}
///
/// struct MyFactory;
///
/// impl SmtpHandlerFactory for MyFactory {
///     type Handler = MyHandler;
///
///     fn new_handler(&self, _session: &Session<'_>) -> Self::Handler {
///         MyHandler { user_id: None }
///     }
/// }
/// ```
///
#[async_trait::async_trait]
pub trait SmtpHandler: Send + Sync {
    /// Handles the `AUTH` command.
    ///
    /// Return:
    /// - `Ok(Response::default())` to indicate successful authentication.
    /// - `Err(Error::Response(...))` to reject with a custom SMTP message.
    /// - `Err(Error::Abort)` to immediately terminate the connection.
    async fn handle_auth(&mut self, _: &Session<'_>, _: AuthData) -> Result {
        Err(Error::Response(Response::not_implemented()))
    }

    /// Handles the `RCPT TO` command.
    ///
    /// Return:
    /// - `Ok(Response::default())` to accept the recipient.
    /// - `Ok(Response::ok("Ok: queued as <message-id>"))` to include a message ID.
    /// - `Err(Error::Response(...))` to reject the recipient.
    async fn handle_rcpt(&mut self, _: &Session<'_>, _: &str) -> Result {
        Err(Error::Response(Response::not_implemented()))
    }

    /// Discard only per-transaction grants/sink state; preserve authenticated identity.
    /// Never delete an accepted or possibly committed original. Cancellation/process
    /// death may skip async hooks, so durable recovery cannot depend on this callback.
    async fn handle_reset(&mut self, _: &Session<'_>) -> std::result::Result<(), Error> {
        Ok(())
    }

    /// Allocate/authorise the caller's bounded sink before the server writes354.
    async fn handle_data_start(&mut self, _: &Session<'_>) -> std::result::Result<(), Error> {
        Err(Error::Response(Response::not_implemented()))
    }

    /// Consume one exact, dot-unstuffed chunk with backpressure. No retained borrow.
    async fn handle_data_chunk(
        &mut self,
        _: &Session<'_>,
        _: &[u8],
    ) -> std::result::Result<(), Error> {
        Err(Error::Response(Response::not_implemented()))
    }

    /// Failure cleanup only; never delete a possibly committed original.
    async fn handle_data_abort(&mut self, _: &Session<'_>) {}

    /// Handles the `DATA` command (email body).
    ///
    /// Return:
    /// - `Ok(Response::default())` to accept the message.
    /// - `Err(Error::Response(...))` to reject with a custom SMTP response.
    async fn handle_data_end(&mut self, _: &Session<'_>) -> Result {
        Err(Error::Response(Response::not_implemented()))
    }
}

/// Defines how new [`SmtpHandler`] instances are created per session.
///
/// Implement this trait to provide your custom handler factory.
/// Each connection gets its own handler instance for isolation and state management.
///
/// ```no_run
/// use smtpd::{async_trait, SmtpHandlerFactory, SmtpHandler, Session};
///
/// struct MyHandler;
///
/// #[async_trait]
/// impl SmtpHandler for MyHandler {}
///
/// struct MyFactory;
///
/// impl SmtpHandlerFactory for MyFactory {
///     type Handler = MyHandler;
///
///     fn new_handler(&self, _session: &Session<'_>) -> Self::Handler {
///         MyHandler
///     }
/// }
/// ```
pub trait SmtpHandlerFactory {
    type Handler: SmtpHandler + 'static;

    fn new_handler(&self, session: &Session<'_>) -> Self::Handler;
}
