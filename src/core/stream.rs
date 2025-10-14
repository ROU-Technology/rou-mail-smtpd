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

    /// Reads a line from the connection and trims leading and trailing whitespace.
    ///
    /// Timeout applies to the read operation.
    pub async fn read_line_trimmed(&mut self, dist: &mut String) -> Result<(), Error> {
        timeout(self.timeout, self.reader.read_line(dist)).await??;

        // Trim leading whitespace
        let start_len_diff = dist.len() - dist.trim_start().len();
        if start_len_diff > 0 {
            dist.drain(0..start_len_diff);
        }

        // Trim trailing whitespace
        let end_trimmed = dist.trim_end().len();
        if end_trimmed < dist.len() {
            dist.truncate(end_trimmed);
        }

        Ok(())
    }

    /// Reads a line from the connection, ensuring proper CRLF line ending.
    ///
    /// If the line ends with LF only, it converts it to CRLF.
    /// Returns `Error::InvalidLineEnding` for malformed lines.
    pub async fn read_line_crlf(&mut self, buffer: &mut Vec<u8>) -> Result<(), Error> {
        timeout(self.timeout, self.reader.read_until(b'\n', buffer)).await??;

        if buffer.ends_with(b"\r\n") {
            Ok(())
        } else if buffer.ends_with(b"\n") {
            // Convert LF to CRLF if needed
            buffer.pop(); // remove LF
            if buffer.ends_with(b"\r") {
                buffer.push(b'\n'); // already CR present, just append LF
                Ok(())
            } else {
                buffer.push(b'\r');
                buffer.push(b'\n');
                Ok(())
            }
        } else {
            Err(Error::InvalidLineEnding)
        }
    }

    /// Reads the data of an SMTP `DATA` command until a line containing only `.`.
    ///
    /// Handles dot-stuffing (lines starting with `.`) and enforces an optional maximum size.
    pub async fn read_mail_data(&mut self, max_size: Option<usize>) -> Result<Vec<u8>, Error> {
        let mut data = vec![];
        let mut line = vec![];
        let mut total_size = 0;

        loop {
            line.clear();
            self.read_line_crlf(&mut line).await?;

            // End of data marker
            if line == b".\r\n" {
                break;
            }

            // Handle dot-stuffing
            let processed_line = if line.starts_with(b".") {
                &line[1..]
            } else {
                &line
            };

            // Check max size
            if let Some(max) = max_size {
                if total_size + processed_line.len() > max {
                    return Err(Error::MaxSizeExceeded { limit: max });
                }
            }

            data.extend_from_slice(processed_line);
            total_size += processed_line.len();
        }

        Ok(data)
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
    async fn read_line_crlf_can_fix_broken_lf() {
        let (mut client, server) = create_tcp_pair().await;
        let mut controller = StreamController::new(server, TIMEOUT);

        // send request
        tokio::spawn(async move { client.write_all(b"ping\n").await.unwrap() });

        let mut buf = vec![];
        controller.read_line_crlf(&mut buf).await.unwrap();

        assert_eq!(buf, b"ping\r\n");
    }

    #[tokio::test]
    async fn read_mail_data() {
        let (mut client, server) = create_tcp_pair().await;
        let mut controller = StreamController::new(server, TIMEOUT);

        // send request
        tokio::spawn(async move {
            client.write_all(b"start\n").await.unwrap();
            client.write_all(b".end\n").await.unwrap();
            client.write_all(b".\n").await.unwrap()
        });

        let buf = controller.read_mail_data(Some(1024)).await.unwrap();

        assert_eq!(buf, b"start\r\nend\r\n");
    }

    #[tokio::test]
    async fn read_mail_data_max_size_err() {
        let (mut client, server) = create_tcp_pair().await;
        let mut controller = StreamController::new(server, TIMEOUT);

        // send request
        tokio::spawn(async move {
            client.write_all(b"start\n").await.unwrap();
            client.write_all(b".end\r\n").await.unwrap();
            client.write_all(b".\n").await.unwrap()
        });

        let res = controller.read_mail_data(Some(1)).await;

        assert!(res.is_err());
        assert!(matches!(
            res.err(),
            Some(Error::MaxSizeExceeded { limit: 1 })
        ));
    }

    #[tokio::test]
    async fn timeout() {
        let (mut client, server) = create_tcp_pair().await;
        let mut controller = StreamController::new(server, Duration::from_micros(0));

        tokio::spawn(async move {
            // Just keep the connection open but never write
            tokio::time::sleep(Duration::from_secs(5)).await;
            let _ = client.shutdown().await;
        });

        let res = controller.read_mail_data(Some(1)).await;

        assert!(res.is_err());
        assert!(matches!(res.err(), Some(Error::Timeout)));
    }
}
