use std::{
    net::SocketAddr,
    sync::{
        atomic::{AtomicBool, AtomicU64},
        Arc,
    },
};

use quinn::{
    congestion::BbrConfig, AsyncUdpSocket, ClientConfig, Endpoint, EndpointConfig, IdleTimeout,
    Runtime, TokioRuntime, TransportConfig, VarInt,
};

use crate::{
    brutal::SwitchableFactory,
    config::QuicParams,
    error::Result,
    obfs::Salamander,
    protocol::MAX_DATAGRAM_FRAME_SIZE,
    socket::{HopConfig, ObfsHopSocket},
};

/// Upload congestion control: a shared Brutal rate plus a flag that hands the
/// window to BBR (set when the server answers `CC-RX: auto`). `None` = BBR only.
pub(crate) type BrutalControl = (Arc<AtomicU64>, Arc<AtomicBool>);

/// Build a tuned transport config.
///
/// `brutal = Some((rate, use_bbr))` → a switchable Brutal/BBR controller;
/// `None` → BBR (adapts to the path, good default).
fn transport_config(brutal: Option<BrutalControl>, quic: &QuicParams) -> TransportConfig {
    let mut t = TransportConfig::default();

    t.keep_alive_interval(Some(quic.keep_alive_interval));
    t.max_idle_timeout(Some(
        IdleTimeout::try_from(quic.max_idle_timeout).expect("valid idle timeout"),
    ));
    t.initial_rtt(quic.initial_rtt);

    t.stream_receive_window(VarInt::from_u64(quic.stream_receive_window).unwrap_or(VarInt::MAX));
    t.receive_window(VarInt::from_u64(quic.connection_receive_window).unwrap_or(VarInt::MAX));

    if quic.disable_path_mtu_discovery {
        t.mtu_discovery_config(None);
    }

    // Enable QUIC unreliable datagrams for UDP relay (Go sets EnableDatagrams +
    // MaxDatagramFrameSize). A non-None receive buffer turns datagrams on.
    t.datagram_receive_buffer_size(Some(MAX_DATAGRAM_FRAME_SIZE as usize * 1024));
    t.datagram_send_buffer_size(MAX_DATAGRAM_FRAME_SIZE as usize * 1024);

    match brutal {
        Some((rate, use_bbr)) => {
            t.congestion_controller_factory(Arc::new(SwitchableFactory { rate, use_bbr }))
        }
        None => t.congestion_controller_factory(Arc::new(BbrConfig::default())),
    };

    t
}

/// Create a client QUIC endpoint bound to an ephemeral local UDP port.
///
/// `canonical` is the address quinn will dial; it doubles as the fixed peer
/// address presented to quinn when port hopping is active. When `obfs` and
/// `hop` are both `None`, the raw socket is used directly.
pub(crate) fn build_endpoint(
    crypto: Arc<rustls::ClientConfig>,
    brutal: Option<BrutalControl>,
    quic: &QuicParams,
    obfs: Option<Salamander>,
    hop: Option<HopConfig>,
    canonical: SocketAddr,
) -> Result<Endpoint> {
    let mut client_config = ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(crypto)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?,
    ));
    client_config.transport_config(Arc::new(transport_config(brutal, quic)));

    // Bind a local socket in the same address family as the server.
    let bind_addr = if canonical.is_ipv6() {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    };
    let std_sock = std::net::UdpSocket::bind(bind_addr)?;

    let runtime: Arc<dyn Runtime> = Arc::new(TokioRuntime);
    let inner = runtime.wrap_udp_socket(std_sock)?;

    let socket: Arc<dyn AsyncUdpSocket> =
        match ObfsHopSocket::new(inner.clone(), canonical, obfs, hop) {
            Some(wrapped) => wrapped,
            None => inner,
        };

    let mut endpoint =
        Endpoint::new_with_abstract_socket(EndpointConfig::default(), None, socket, runtime)?;
    endpoint.set_default_client_config(client_config);
    Ok(endpoint)
}
