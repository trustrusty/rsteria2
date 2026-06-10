use std::sync::Arc;

use tokio::io::AsyncWriteExt;

use crate::{
    error::{Error, Result},
    protocol::encode_tcp_request,
    stream::DuplexStream,
    udp::{UdpSession, UdpSessionManager},
};

/// A connected Hysteria2 client. Cheap to share; open one proxied TCP
/// connection per [`tcp_connect`](Self::tcp_connect), or a UDP session per
/// [`udp`](Self::udp).
///
/// The client owns the underlying QUIC connection and closes it on drop, so any
/// [`DuplexStream`] or [`UdpSession`] it produced is invalidated once the client
/// (its last clone) is dropped — keep the client alive for as long as you use
/// its streams. The same applies when [`ReconnectableClient`] reconnects or is
/// invalidated.
///
/// [`ReconnectableClient`]: crate::ReconnectableClient
pub struct HysteriaClient {
    conn: quinn::Connection,
    // Held only to keep the endpoint's background event loop alive for the
    // lifetime of the connection (driving the UDP socket).
    _endpoint: quinn::Endpoint,
    fast_open: bool,
    server_rx: u64,
    udp_sm: Option<Arc<UdpSessionManager>>,
}

impl HysteriaClient {
    pub(crate) fn new(
        conn: quinn::Connection,
        endpoint: quinn::Endpoint,
        fast_open: bool,
        udp_enabled: bool,
        server_rx: u64,
    ) -> Self {
        let udp_sm = if udp_enabled {
            Some(UdpSessionManager::new(conn.clone()))
        } else {
            None
        };
        Self {
            conn,
            _endpoint: endpoint,
            fast_open,
            server_rx,
            udp_sm,
        }
    }

    /// Open a proxied TCP connection to `address` (`host:port`).
    ///
    /// With fast-open (the default), this returns as soon as the request is
    /// written; the server's `TCPResponse` is validated lazily on the first
    /// read of the returned [`DuplexStream`]. With fast-open disabled, the
    /// response is awaited here, so a server rejection surfaces immediately.
    pub async fn tcp_connect(&self, address: &str) -> Result<DuplexStream> {
        let (mut send, recv) = self.conn.open_bi().await?;
        send.write_all(&encode_tcp_request(address))
            .await
            .map_err(std::io::Error::other)?;
        send.flush().await.map_err(std::io::Error::other)?;
        let mut stream = DuplexStream::new(send, recv);
        if !self.fast_open {
            stream.establish().await?;
        }
        Ok(stream)
    }

    /// Open a new UDP relay session. Returns an error if the server did not
    /// advertise UDP support during authentication.
    pub fn udp(&self) -> Result<UdpSession> {
        match &self.udp_sm {
            Some(sm) => Ok(sm.new_session()),
            None => Err(Error::Protocol("UDP relay not enabled by server".into())),
        }
    }

    /// Whether the server advertised UDP relay support.
    pub fn udp_enabled(&self) -> bool {
        self.udp_sm.is_some()
    }

    /// The server's advertised receive rate in bytes/sec (0 = unlimited/auto).
    pub fn server_rx(&self) -> u64 {
        self.server_rx
    }

    /// The underlying QUIC connection (e.g. to check liveness).
    pub fn connection(&self) -> &quinn::Connection {
        &self.conn
    }
}

impl Drop for HysteriaClient {
    fn drop(&mut self) {
        // Promptly close the connection (Go's `Close` does `CloseWithError`).
        // This also unblocks the UDP `receive_loop`, which is parked on
        // `read_datagram()` holding its own `Connection` clone, so the task and
        // socket are released instead of lingering until the idle timeout.
        // `0x100` = HTTP/3 ErrCodeNoError, matching the Go client.
        self.conn.close(0x100u32.into(), b"");
    }
}
