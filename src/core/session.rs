use std::fmt::Debug;

/// Represents an active SMTP session.
///
/// A new `Session` is created for every accepted connection and persists for its lifetime.
/// Internally, it’s updated as commands (HELO, MAIL, RCPT, etc.) are processed.
///
/// Public handlers receive a reference to this session to inspect its state,
/// authentication status, or client metadata.
#[derive(Debug)]
pub struct Session<'a> {
    /// Indicates whether the session has been successfully authenticated.
    /// Set to `true` only when the `AUTH` handler returns an `Ok` variant.
    pub authenticated: bool,

    /// The sender address provided via the `MAIL FROM` command.
    pub from: String,

    /// All accepted recipients, collected from `RCPT TO` commands.
    /// Recipients are added only if the RCPT handler returns `Ok`.
    pub to: Vec<String>,

    /// Immutable reference to the SMTP configuration used by this session.
    pub smtp_config: &'a super::SmtpConfig,

    /// The remote host name, updated via the `HELO` or `EHLO` command.
    pub remote_name: String,

    /// Whether the client IP is trusted based on `SmtpConfig.x_client_allowed`.
    pub x_client_trust: bool,

    /// Raw `XCLIENT` command arguments (if provided).
    pub x_client: String,

    /// Parsed client IP from the `XCLIENT` argument.
    pub x_client_addr: String,

    /// Parsed client name from the `XCLIENT` argument.
    pub x_client_name: String,

    /// The peer IP address of the connection.
    /// Can be updated by the `XCLIENT` command if permitted.
    pub remote_ip: String,

    /// The resolved reverse DNS hostname of the peer,
    /// or `"unknown"` if reverse lookup is disabled or failed.
    pub remote_host: String,

    /// Indicates whether the connection is currently encrypted via TLS.
    #[cfg(any(feature = "native-tls-backend", feature = "rustls-backend"))]
    pub tls: bool,

    /// Tracks whether the session has received a valid `MAIL FROM` command.
    pub got_from: bool,
}

impl<'a> Session<'a> {
    /// Creates a new `Session` for the given client connection.
    ///
    /// Automatically evaluates whether the client IP is trusted
    /// based on the configuration.
    pub fn new(
        config: &'a super::SmtpConfig,
        remote_ip: String,
        remote_host: String,
        #[cfg(any(feature = "native-tls-backend", feature = "rustls-backend"))] is_tls: bool,
    ) -> Self {
        let x_client_trust = config
            .x_client_allowed
            .as_ref()
            .is_some_and(|ips| ips.contains(&remote_ip));

        Self {
            authenticated: false,
            #[cfg(any(feature = "native-tls-backend", feature = "rustls-backend"))]
            tls: is_tls,
            from: String::with_capacity(256),
            remote_name: String::with_capacity(256),
            smtp_config: config,
            to: Vec::new(),
            remote_host,
            remote_ip,
            x_client: String::new(),
            x_client_addr: String::new(),
            x_client_name: String::new(),
            x_client_trust,
            got_from: false,
        }
    }

    /// Resets per-message state (e.g., after a `RSET` command).
    ///
    /// This clears the sender and recipient data but keeps
    /// authentication and connection metadata intact.
    pub fn reset(&mut self) {
        self.from.clear();
        self.to.clear();
        self.got_from = false;
    }

    /// Returns `true` if the client is trusted via `XCLIENT` allowlist.
    #[inline]
    pub fn is_trusted(&self) -> bool {
        self.x_client_trust
    }

    /// Returns `true` if the current session is encrypted (TLS active).
    #[cfg(any(feature = "native-tls-backend", feature = "rustls-backend"))]
    #[inline]
    pub fn is_tls(&self) -> bool {
        self.tls
    }

    /// Returns `true` if the session is authenticated.
    #[inline]
    pub fn is_authenticated(&self) -> bool {
        self.authenticated
    }
}
