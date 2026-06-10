//! UDP relay over QUIC unreliable datagrams (Go: core/client/udp.go +
//! the `udpIOImpl` in client.go).
//!
//! A single background task reads datagrams off the QUIC connection, parses
//! them into [`UdpMessage`]s and dispatches them to the owning session by
//! Session ID. Each [`UdpSession`] reassembles fragments locally and sends with
//! automatic fragmentation when a payload exceeds the current datagram limit.

use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicU32, Ordering},
        Arc, Mutex, Weak,
    },
};

use bytes::Bytes;
use rand::Rng;
use tokio::sync::mpsc;

use crate::{
    error::{Error, Result},
    protocol::{frag_udp_message, Defragger, UdpMessage, MAX_DATAGRAM_FRAME_SIZE, MAX_UDP_SIZE},
};

/// Routes inbound UDP datagrams to per-session channels.
pub(crate) struct UdpSessionManager {
    conn: quinn::Connection,
    sessions: Mutex<HashMap<u32, mpsc::UnboundedSender<UdpMessage>>>,
    next_id: AtomicU32,
}

impl UdpSessionManager {
    /// Spawn the receive loop and return the manager.
    pub(crate) fn new(conn: quinn::Connection) -> Arc<UdpSessionManager> {
        let mgr = Arc::new(UdpSessionManager {
            conn: conn.clone(),
            sessions: Mutex::new(HashMap::new()),
            next_id: AtomicU32::new(1),
        });
        let weak = Arc::downgrade(&mgr);
        tokio::spawn(receive_loop(conn, weak));
        mgr
    }

    /// Open a new UDP session with a fresh Session ID.
    pub(crate) fn new_session(self: &Arc<Self>) -> UdpSession {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = mpsc::unbounded_channel();
        self.sessions.lock().unwrap().insert(id, tx);
        UdpSession {
            id,
            conn: self.conn.clone(),
            rx,
            defrag: Defragger::default(),
            mgr: Arc::downgrade(self),
        }
    }

    fn dispatch(&self, msg: UdpMessage) {
        let sessions = self.sessions.lock().unwrap();
        if let Some(tx) = sessions.get(&msg.session_id) {
            // Unbounded: a slow reader grows memory rather than dropping, but a
            // dropped receiver just means the send fails harmlessly.
            let _ = tx.send(msg);
        }
        // Unknown session — ignore (Go does the same).
    }

    fn remove(&self, id: u32) {
        self.sessions.lock().unwrap().remove(&id);
    }
}

async fn receive_loop(conn: quinn::Connection, mgr: Weak<UdpSessionManager>) {
    loop {
        match conn.read_datagram().await {
            Ok(data) => {
                if let Some(msg) = UdpMessage::parse(&data) {
                    match mgr.upgrade() {
                        Some(m) => m.dispatch(msg),
                        None => return, // manager dropped
                    }
                }
                // Invalid datagram — skip, like Go.
            }
            Err(_) => return, // connection closed; senders drop, sessions see EOF
        }
    }
}

/// A UDP relay session. Send and receive datagrams to/from arbitrary
/// destination addresses through the proxy.
pub struct UdpSession {
    id: u32,
    conn: quinn::Connection,
    rx: mpsc::UnboundedReceiver<UdpMessage>,
    defrag: Defragger,
    mgr: Weak<UdpSessionManager>,
}

impl UdpSession {
    /// The Session ID assigned by the client.
    pub fn id(&self) -> u32 {
        self.id
    }

    /// Send `data` to `addr` (`host:port`) through the proxy, fragmenting if the
    /// payload exceeds the current QUIC datagram limit.
    pub fn send(&self, data: &[u8], addr: &str) -> Result<()> {
        let msg = UdpMessage {
            session_id: self.id,
            packet_id: 0,
            frag_id: 0,
            frag_count: 1,
            addr: addr.to_string(),
            data: data.to_vec(),
        };

        // Fast path: try to send unfragmented.
        let mut buf = vec![0u8; msg.size().max(MAX_UDP_SIZE)];
        if let Some(n) = msg.serialize(&mut buf) {
            match self.conn.send_datagram(Bytes::copy_from_slice(&buf[..n])) {
                Ok(()) => return Ok(()),
                Err(quinn::SendDatagramError::TooLarge) => { /* fall through to fragment */ }
                Err(e) => return Err(Error::Protocol(format!("send datagram: {e}"))),
            }
        }

        // Fragment to the current datagram limit and send each piece.
        let max = self
            .conn
            .max_datagram_size()
            .unwrap_or(MAX_DATAGRAM_FRAME_SIZE as usize);
        let mut frag = msg;
        frag.packet_id = rand::rng().random_range(1..=u16::MAX);
        for f in frag_udp_message(&frag, max) {
            let mut fbuf = vec![0u8; f.size()];
            if let Some(n) = f.serialize(&mut fbuf) {
                self.conn
                    .send_datagram(Bytes::copy_from_slice(&fbuf[..n]))
                    .map_err(|e| Error::Protocol(format!("send fragment: {e}")))?;
            }
        }
        Ok(())
    }

    /// Receive the next datagram, returning `(payload, source_addr)`.
    /// Returns an error once the session or connection is closed.
    pub async fn recv(&mut self) -> Result<(Vec<u8>, String)> {
        loop {
            let msg = self
                .rx
                .recv()
                .await
                .ok_or_else(|| Error::Protocol("udp session closed".into()))?;
            if let Some(full) = self.defrag.feed(msg) {
                return Ok((full.data, full.addr));
            }
            // Incomplete fragmented packet — wait for more.
        }
    }
}

impl Drop for UdpSession {
    fn drop(&mut self) {
        if let Some(mgr) = self.mgr.upgrade() {
            mgr.remove(self.id);
        }
    }
}
