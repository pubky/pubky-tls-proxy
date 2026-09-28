//! A stream wrapper that replays bytes which were already read from the inner stream.

use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Wraps a stream so that reads first return `prefix` and then continue with `inner`.
///
/// Traffic detection has to read the first bytes of a connection before we know where
/// to route it. Wrapping the connection in a `PrefixedStream` lets the TLS acceptor or
/// the backend see the connection as if nothing had been read yet.
/// Writes go straight to `inner`.
pub struct PrefixedStream<S> {
    prefix: Vec<u8>,
    prefix_bytes_returned: usize,
    inner: S,
}

impl<S> PrefixedStream<S> {
    pub fn new(prefix: Vec<u8>, inner: S) -> Self {
        Self {
            prefix,
            prefix_bytes_returned: 0,
            inner,
        }
    }

    fn unread_prefix(&self) -> &[u8] {
        &self.prefix[self.prefix_bytes_returned..]
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for PrefixedStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        let unread_prefix = this.unread_prefix();
        if unread_prefix.is_empty() {
            return Pin::new(&mut this.inner).poll_read(cx, buf);
        }

        let byte_count = unread_prefix.len().min(buf.remaining());
        buf.put_slice(&unread_prefix[..byte_count]);
        this.prefix_bytes_returned += byte_count;
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for PrefixedStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    #[tokio::test]
    async fn reads_prefix_before_inner_stream() {
        let inner: &[u8] = b" world";
        let mut stream = PrefixedStream::new(b"hello".to_vec(), inner);

        let mut received = String::new();
        stream.read_to_string(&mut received).await.unwrap();

        assert_eq!(received, "hello world");
    }
}
