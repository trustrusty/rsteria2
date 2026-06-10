use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::protocol::{TcpResponseParse, parse_tcp_response};

/// A proxied TCP connection over a QUIC bidirectional stream.
///
/// Implements [`AsyncRead`] + [`AsyncWrite`] so it drops straight into
/// `tokio::io::copy_bidirectional`.
///
/// Fast-open: [`crate::HysteriaClient::tcp_connect`] returns immediately after
/// writing the request, without blocking on the server's `TCPResponse`. The
/// response header is parsed and stripped lazily on the first `poll_read`, so
/// application data (e.g. an HTTP request) can flow out right away. This avoids
/// a round-trip stall — and, with servers that defer their response until they
/// have upstream data, a multi-second deadlock.
pub struct DuplexStream {
    send: quinn::SendStream,
    recv: quinn::RecvStream,
    response_done: bool,
    scratch: Vec<u8>,
    leftover: Vec<u8>,
    leftover_pos: usize,
}

impl DuplexStream {
    pub(crate) fn new(send: quinn::SendStream, recv: quinn::RecvStream) -> Self {
        Self {
            send,
            recv,
            response_done: false,
            scratch: Vec::new(),
            leftover: Vec::new(),
            leftover_pos: 0,
        }
    }

    /// Drive the TCPResponse header to completion (used when fast-open is off,
    /// so a server rejection surfaces from `tcp_connect` rather than first read).
    pub(crate) async fn establish(&mut self) -> io::Result<()> {
        std::future::poll_fn(|cx| Pin::new(&mut *self).poll_establish(cx)).await
    }

    /// Phase 1: consume the TCPResponse header before yielding any app data.
    fn poll_establish(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let me = &mut *self;
        while !me.response_done {
            match parse_tcp_response(&me.scratch) {
                TcpResponseParse::Done { ok, consumed } => {
                    if !ok {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::ConnectionRefused,
                            "hysteria2: server rejected tcp_connect",
                        )));
                    }
                    me.leftover = me.scratch.split_off(consumed);
                    me.scratch = Vec::new();
                    me.response_done = true;
                    break;
                }
                TcpResponseParse::Invalid => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "hysteria2: malformed TCPResponse (length guard exceeded)",
                    )));
                }
                TcpResponseParse::NeedMore => {
                    let mut tmp = [0u8; 512];
                    let mut rb = ReadBuf::new(&mut tmp);
                    match Pin::new(&mut me.recv).poll_read(cx, &mut rb) {
                        Poll::Ready(Ok(())) => {
                            let filled = rb.filled();
                            if filled.is_empty() {
                                return Poll::Ready(Err(io::Error::new(
                                    io::ErrorKind::UnexpectedEof,
                                    "hysteria2: stream closed before TCPResponse",
                                )));
                            }
                            me.scratch.extend_from_slice(filled);
                        }
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Pending => return Poll::Pending,
                    }
                }
            }
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncRead for DuplexStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // Phase 1: ensure the TCPResponse header has been consumed.
        if !self.response_done {
            match self.as_mut().poll_establish(cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        let me = &mut *self;

        // Phase 2: drain app data that arrived in the same batch as the header.
        if me.leftover_pos < me.leftover.len() {
            let rest = &me.leftover[me.leftover_pos..];
            let n = rest.len().min(buf.remaining());
            buf.put_slice(&rest[..n]);
            me.leftover_pos += n;
            return Poll::Ready(Ok(()));
        }

        // Phase 3: pass through.
        Pin::new(&mut me.recv).poll_read(cx, buf)
    }
}

impl AsyncWrite for DuplexStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.send)
            .poll_write(cx, buf)
            .map_err(io::Error::other)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.send).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.send).poll_shutdown(cx)
    }
}
