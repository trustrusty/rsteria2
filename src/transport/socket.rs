//! A custom [`AsyncUdpSocket`] that layers Salamander obfuscation and/or UDP
//! port hopping underneath quinn, mirroring the Go `obfs` and `udphop`
//! `net.PacketConn` wrappers.
//!
//! Both features live at the datagram layer:
//! - **Obfuscation**: outbound packets are XOR-masked + salted; inbound packets
//!   are unmasked. Disables GSO/GRO so every datagram carries its own salt.
//! - **Port hopping**: outbound packets are redirected to a rotating port out
//!   of a configured range, and the *source* address of inbound packets is
//!   rewritten back to the canonical server address so quinn never perceives a
//!   path change (equivalent to Go's `DisablePathManager: true`).

use std::{
    fmt,
    io::{self, IoSliceMut},
    net::SocketAddr,
    pin::Pin,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
    task::{Context, Poll},
    time::Duration,
};

use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, UdpPoller};
use rand::Rng;

use super::obfs::Salamander;

/// Port-hopping parameters.
#[derive(Clone)]
pub struct HopConfig {
    /// Candidate server addresses (same IP, one per port in the range).
    pub addrs: Vec<SocketAddr>,
    /// Lower bound of the random hop interval.
    pub interval_min: Duration,
    /// Upper bound of the random hop interval (== min for a fixed interval).
    pub interval_max: Duration,
}

const SCRATCH_DATAGRAM: usize = 2048;

/// Socket wrapper applying obfuscation and/or port hopping.
pub struct ObfsHopSocket {
    inner: Arc<dyn AsyncUdpSocket>,
    obfs: Option<Salamander>,
    /// Rotating index into `hop_addrs`; `None` when port hopping is disabled.
    hop_index: Option<Arc<AtomicUsize>>,
    hop_addrs: Vec<SocketAddr>,
    /// The address quinn was told to dial — all inbound packets are reported as
    /// coming from here so path validation stays happy while we hop ports.
    canonical: SocketAddr,
    write_buf: Mutex<Vec<u8>>,
    /// Reused receive scratch for the obfuscation path (deobfuscate before
    /// handing plaintext to quinn), avoiding a per-poll allocation.
    recv_scratch: Mutex<(Vec<u8>, Vec<RecvMeta>)>,
    _hop_task: Option<tokio::task::JoinHandle<()>>,
}

impl Drop for ObfsHopSocket {
    fn drop(&mut self) {
        // Dropping a JoinHandle only detaches; abort so the hop loop stops.
        if let Some(task) = &self._hop_task {
            task.abort();
        }
    }
}

impl fmt::Debug for ObfsHopSocket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ObfsHopSocket")
            .field("obfs", &self.obfs.is_some())
            .field("hopping", &self.hop_index.is_some())
            .field("canonical", &self.canonical)
            .finish()
    }
}

impl ObfsHopSocket {
    /// Wrap quinn's inner socket. `canonical` is the address passed to
    /// `Endpoint::connect`. Returns `None` only if neither feature is requested
    /// (the caller should then use `inner` directly).
    pub fn new(
        inner: Arc<dyn AsyncUdpSocket>,
        canonical: SocketAddr,
        obfs: Option<Salamander>,
        hop: Option<HopConfig>,
    ) -> Option<Arc<ObfsHopSocket>> {
        if obfs.is_none() && hop.is_none() {
            return None;
        }
        let (hop_index, hop_addrs, hop_task) = match hop {
            Some(cfg) if cfg.addrs.len() > 1 => {
                let index = Arc::new(AtomicUsize::new(
                    rand::rng().random_range(0..cfg.addrs.len()),
                ));
                let task = spawn_hop_task(index.clone(), cfg.addrs.len(), cfg.interval_min, cfg.interval_max);
                (Some(index), cfg.addrs, Some(task))
            }
            // A single-port "range" needs no rotation; treat as no hopping.
            Some(cfg) => (None, cfg.addrs, None),
            None => (None, vec![canonical], None),
        };
        Some(Arc::new(ObfsHopSocket {
            inner,
            obfs,
            hop_index,
            hop_addrs,
            canonical,
            write_buf: Mutex::new(vec![0u8; SCRATCH_DATAGRAM]),
            recv_scratch: Mutex::new((Vec::new(), Vec::new())),
            _hop_task: hop_task,
        }))
    }

    /// The destination to send to right now (rotates when hopping).
    fn current_dest(&self) -> SocketAddr {
        match &self.hop_index {
            Some(idx) => self.hop_addrs[idx.load(Ordering::Relaxed) % self.hop_addrs.len()],
            None => self.canonical,
        }
    }
}

fn spawn_hop_task(
    index: Arc<AtomicUsize>,
    n: usize,
    min: Duration,
    max: Duration,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            let wait = if min >= max {
                min
            } else {
                let extra = rand::rng().random_range(0..=(max - min).as_millis() as u64);
                min + Duration::from_millis(extra)
            };
            tokio::time::sleep(wait).await;
            index.store(rand::rng().random_range(0..n), Ordering::Relaxed);
        }
    })
}

impl AsyncUdpSocket for ObfsHopSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        self.inner.clone().create_io_poller()
    }

    fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
        let dest = if self.hop_index.is_some() {
            self.current_dest()
        } else {
            transmit.destination
        };

        match &self.obfs {
            None => {
                // Port hopping only: just redirect the destination.
                let t = Transmit {
                    destination: dest,
                    ecn: transmit.ecn,
                    contents: transmit.contents,
                    segment_size: transmit.segment_size,
                    src_ip: transmit.src_ip,
                };
                self.inner.try_send(&t)
            }
            Some(obfs) => {
                // Obfuscation forces single datagrams (GSO is disabled), so
                // `segment_size` is always None here.
                let mut buf = self.write_buf.lock().unwrap();
                let n = obfs.obfuscate(transmit.contents, &mut buf);
                if n == 0 {
                    // Oversized for the scratch buffer — drop silently (matches
                    // Go, which would also not emit a malformed packet).
                    return Ok(());
                }
                let t = Transmit {
                    destination: dest,
                    ecn: transmit.ecn,
                    contents: &buf[..n],
                    segment_size: None,
                    src_ip: transmit.src_ip,
                };
                self.inner.try_send(&t)
            }
        }
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let rewrite_addr = self.hop_index.is_some();

        match &self.obfs {
            None => {
                // No obfuscation: receive straight into the caller's buffers,
                // then (when hopping) rewrite the source address.
                let n = match self.inner.poll_recv(cx, bufs, meta) {
                    Poll::Ready(Ok(n)) => n,
                    other => return other,
                };
                if rewrite_addr {
                    for m in meta.iter_mut().take(n) {
                        m.addr = self.canonical;
                    }
                }
                Poll::Ready(Ok(n))
            }
            Some(obfs) => {
                // Obfuscation: receive into reused scratch buffers, deobfuscate
                // into the caller's, dropping any packet that fails to unmask.
                let count = bufs.len();
                let mut guard = self.recv_scratch.lock().unwrap();
                let (scratch, tmp_meta) = &mut *guard;
                if scratch.len() < count * SCRATCH_DATAGRAM {
                    scratch.resize(count * SCRATCH_DATAGRAM, 0);
                }
                if tmp_meta.len() < count {
                    tmp_meta.resize(count, RecvMeta::default());
                }
                loop {
                    let mut tmp_bufs: Vec<IoSliceMut> = scratch[..count * SCRATCH_DATAGRAM]
                        .chunks_mut(SCRATCH_DATAGRAM)
                        .map(IoSliceMut::new)
                        .collect();

                    let n = match self.inner.poll_recv(cx, &mut tmp_bufs, &mut tmp_meta[..count]) {
                        Poll::Ready(Ok(n)) => n,
                        other => return other,
                    };
                    drop(tmp_bufs); // release the &mut borrow of `scratch`

                    let mut out = 0usize;
                    for k in 0..n {
                        let raw_end = tmp_meta[k].len;
                        let raw = &scratch[k * SCRATCH_DATAGRAM..k * SCRATCH_DATAGRAM + raw_end];
                        let plain_len = obfs.deobfuscate(raw, &mut bufs[out]);
                        if plain_len == 0 {
                            continue; // invalid packet — discard
                        }
                        meta[out] = RecvMeta {
                            addr: if rewrite_addr {
                                self.canonical
                            } else {
                                tmp_meta[k].addr
                            },
                            len: plain_len,
                            stride: plain_len,
                            ecn: tmp_meta[k].ecn,
                            dst_ip: tmp_meta[k].dst_ip,
                        };
                        out += 1;
                    }
                    if out > 0 {
                        return Poll::Ready(Ok(out));
                    }
                    // Every datagram was invalid — poll again.
                }
            }
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    fn max_transmit_segments(&self) -> usize {
        if self.obfs.is_some() {
            1
        } else {
            self.inner.max_transmit_segments()
        }
    }

    fn max_receive_segments(&self) -> usize {
        if self.obfs.is_some() {
            1
        } else {
            self.inner.max_receive_segments()
        }
    }

    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }
}
