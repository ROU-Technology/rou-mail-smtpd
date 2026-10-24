use std::fmt;

use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader, BufWriter, ReadHalf, WriteHalf},
    time::timeout,
};

use crate::core::{ConnectionStream, error::Error};

/// Handles read/write operations on a `ConnectionStream`.
///
/// This struct wraps the split halves of a connection (reader and writer),
/// provides timeout support, and ensures proper line handling per SMTP protocol.
///
/// Constructed internally per accepted connection. Most read/write operations
/// are asynchronous and time-limited using the provided `timeout`.
pub(crate) struct StreamController {
    /// Buffered reader half of the connection.
    pub reader: BufReader<ReadHalf<ConnectionStream>>,

    /// Buffered writer half of the connection.
    pub writer: BufWriter<WriteHalf<ConnectionStream>>,

    /// Whether the connection is currently encrypted via TLS.
    #[cfg(any(feature = "native-tls-backend", feature = "rustls-backend"))]
    pub is_tls: bool,

    /// Timeout duration applied to each read/write operation.
    timeout: core::time::Duration,
    line_limit: usize,
}

impl Into<ConnectionStream> for StreamController {
    fn into(self) -> ConnectionStream {
        self.reader.into_inner().unsplit(self.writer.into_inner())
    }
}

impl StreamController {
    /// Creates a new `StreamController` from a `ConnectionStream`.
    ///
    /// Splits the stream into read and write halves, wraps them in buffered readers/writers,
    /// and stores the timeout for all I/O operations.
    pub fn new(stream: ConnectionStream, timeout: core::time::Duration) -> Self {
        #[cfg(any(feature = "native-tls-backend", feature = "rustls-backend"))]
        let is_tls = stream.is_tls();

        let (read_half, write_half) = tokio::io::split(stream);
        Self {
            reader: BufReader::new(read_half),
            writer: BufWriter::new(write_half),
            #[cfg(any(feature = "native-tls-backend", feature = "rustls-backend"))]
            is_tls,
            timeout,
            line_limit: 1001,
        }
    }

    /// Writes a single line to the connection, automatically appending `\r\n`.
    ///
    /// The operation is bounded by the session timeout.
    pub async fn write_line(&mut self, line: impl AsRef<str>) -> Result<(), Error> {
        timeout(
            self.timeout,
            self.writer.write_all(line.as_ref().as_bytes()),
        )
        .await??;
        timeout(self.timeout, self.writer.write_all(b"\r\n")).await??;
        timeout(self.timeout, self.writer.flush()).await??;
        Ok(())
    }

    /// Writes a displayable response to the connection.
    ///
    /// Converts the response to a string and delegates to `write_line`.
    pub async fn write_response(&mut self, res: &impl fmt::Display) -> Result<(), Error> {
        self.write_line(&res.to_string()).await
    }

    pub fn set_line_limit(&mut self, limit: usize) {
        self.line_limit = limit;
    }

    /// Read one strict CRLF line. Check the bound before growing the buffer.
    /// A single timeout covers the whole read, including a dripping sender.
    pub async fn read_line_crlf(&mut self, buffer: &mut Vec<u8>) -> Result<(), Error> {
        buffer.clear();
        let limit = self.line_limit;
        timeout(self.timeout, async {
            loop {
                let available = self.reader.fill_buf().await?;
                if available.is_empty() {
                    return Err(Error::Io);
                }
                let end = available.iter().position(|b| *b == b'\n');
                let take = end.map_or(available.len(), |i| i + 1);
                if take > limit.saturating_sub(buffer.len()) {
                    return Err(Error::MaxSizeExceeded { limit });
                }
                buffer.extend_from_slice(&available[..take]);
                self.reader.consume(take);
                if end.is_some() {
                    if !buffer.ends_with(b"\r\n") || buffer[..buffer.len() - 2].contains(&b'\r') {
                        return Err(Error::InvalidLineEnding);
                    }
                    return Ok(());
                }
            }
        })
        .await?
    }

    pub async fn read_line_trimmed(&mut self, target: &mut String) -> Result<(), Error> {
        let mut bytes = Vec::new();
        self.read_line_crlf(&mut bytes).await?;
        let line = std::str::from_utf8(&bytes).map_err(|_| Error::InvalidLineEnding)?;
        target.clear();
        target.push_str(line.trim());
        Ok(())
    }

    /// Bounded, backpressured DATA delivery; no full-message Vec or newline repair.
    pub async fn stream_mail_data<H: crate::SmtpHandler>(
        &mut self,
        max_size: usize,
        session: &crate::Session<'_>,
        handler: &mut H,
    ) -> Result<(), Error> {
        let mut line = Vec::new();
        let mut total = 0usize;
        loop {
            self.read_line_crlf(&mut line).await?;
            if line == b".\r\n" {
                return Ok(());
            }
            let chunk = if line.starts_with(b".") {
                &line[1..]
            } else {
                &line[..]
            };
            total = total
                .checked_add(chunk.len())
                .filter(|n| *n <= max_size)
                .ok_or(Error::MaxSizeExceeded { limit: max_size })?;
            handler
                .handle_data_chunk(session, chunk)
                .await
                .map_err(Error::Handler)?;
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::Response;

    use super::*;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    const TIMEOUT: Duration = Duration::from_secs(1);

    async fn create_tcp_pair() -> (ConnectionStream, ConnectionStream) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let client_fut = TcpStream::connect(addr);
        let server_fut = listener.accept();

        let (client, server) = tokio::join!(client_fut, server_fut);

        let (server, _) = server.unwrap();
        let client = client.unwrap();

        (ConnectionStream::Tcp(client), ConnectionStream::Tcp(server))
    }

    #[tokio::test]
    async fn write_line_with_crlf() {
        let (client_stream, server_stream) = create_tcp_pair().await;
        let mut controller = StreamController::new(server_stream, TIMEOUT);

        // Spawn a task that reads from client side
        let handle = tokio::spawn(async move {
            let mut buf = Vec::new();
            let mut client = client_stream;
            client.read_to_end(&mut buf).await.unwrap();
            buf
        });

        // Write a line
        controller.write_line("HELLO").await.unwrap();

        // Drop writer so client finishes reading
        drop(controller);

        let buf = handle.await.unwrap();
        assert_eq!(String::from_utf8_lossy(&buf), "HELLO\r\n");
    }

    #[tokio::test]
    async fn write_response() {
        let (client_stream, server_stream) = create_tcp_pair().await;
        let mut controller = StreamController::new(server_stream, TIMEOUT);

        // Spawn a task that reads from client side
        let handle = tokio::spawn(async move {
            let mut buf = Vec::new();
            let mut client = client_stream;
            client.read_to_end(&mut buf).await.unwrap();
            buf
        });

        // Write a response
        let response = Response::info("greetings");

        controller.write_response(&response).await.unwrap();

        // Drop writer so client finishes reading
        drop(controller);

        let buf = handle.await.unwrap();
        assert_eq!(String::from_utf8_lossy(&buf), response.to_string() + "\r\n");
    }

    #[tokio::test]
    async fn read_line_trimmed() {
        let (mut client_stream, server_stream) = create_tcp_pair().await;
        let mut controller = StreamController::new(server_stream, TIMEOUT);

        // Client sends data
        tokio::spawn(async move {
            client_stream.write_all(b"   ping   \r\n").await.unwrap();
        });

        let mut buf = String::new();
        controller.read_line_trimmed(&mut buf).await.unwrap();
        assert_eq!(buf, "ping");
    }

    #[tokio::test]
    async fn read_line_crlf() {
        let (mut client, server) = create_tcp_pair().await;
        let mut controller = StreamController::new(server, TIMEOUT);

        // send request
        tokio::spawn(async move { client.write_all(b"ping\r\n").await.unwrap() });

        let mut buf = vec![];
        controller.read_line_crlf(&mut buf).await.unwrap();

        assert_eq!(buf, b"ping\r\n");
    }

    #[tokio::test]
    async fn rejects_bare_lf_without_rewriting_bytes() {
        let (mut client, server) = create_tcp_pair().await;
        let mut controller = StreamController::new(server, TIMEOUT);
        client.write_all(b"ping\n").await.unwrap();
        let mut buf = vec![];
        assert!(matches!(
            controller.read_line_crlf(&mut buf).await,
            Err(Error::InvalidLineEnding)
        ));
        assert_eq!(buf, b"ping\n");
    }

    #[tokio::test]
    async fn bounds_unterminated_line_before_allocation() {
        let (mut client, server) = create_tcp_pair().await;
        let mut controller = StreamController::new(server, TIMEOUT);
        controller.set_line_limit(32);
        client.write_all(&[b'x'; 4096]).await.unwrap();
        let mut buf = vec![];
        assert!(matches!(
            controller.read_line_crlf(&mut buf).await,
            Err(Error::MaxSizeExceeded { limit: 32 })
        ));
        assert!(buf.len() <= 32);
    }

    #[tokio::test]
    async fn eof_is_terminal() {
        let (client, server) = create_tcp_pair().await;
        drop(client);
        let mut controller = StreamController::new(server, TIMEOUT);
        assert!(matches!(
            controller.read_line_crlf(&mut vec![]).await,
            Err(Error::Io)
        ));
    }
}
