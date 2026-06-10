use std::time::Duration;

/// QUIC transport tuning. [`Default`] reproduces the library's built-in values.
#[derive(Debug, Clone)]
pub struct QuicParams {
    /// Per-stream flow-control receive window, in bytes.
    pub stream_receive_window: u64,
    /// Whole-connection flow-control receive window, in bytes.
    pub connection_receive_window: u64,
    /// Idle timeout before the connection is torn down.
    pub max_idle_timeout: Duration,
    /// Keep-alive ping interval (keeps the connection warm between requests).
    pub keep_alive_interval: Duration,
    /// Initial RTT estimate used before the first measurement.
    pub initial_rtt: Duration,
    /// Disable QUIC Path MTU Discovery (Go `DisablePathMTUDiscovery`).
    pub disable_path_mtu_discovery: bool,
}

impl Default for QuicParams {
    fn default() -> Self {
        QuicParams {
            // Go defaults: 8MB stream window, 20MB (8MB * 5/2) connection window.
            stream_receive_window: 8 * 1024 * 1024,
            connection_receive_window: 8 * 1024 * 1024 * 5 / 2,
            max_idle_timeout: Duration::from_secs(30),
            keep_alive_interval: Duration::from_secs(10),
            initial_rtt: Duration::from_millis(100),
            disable_path_mtu_discovery: false,
        }
    }
}

/// Hysteria2 client configuration.
///
/// Construct with [`Default::default`] and override the fields you need:
/// ```
/// # use rsteria2::Config;
/// let cfg = Config {
///     server_addr: "example.com:443".into(),
///     auth: "password".into(),
///     ..Default::default()
/// };
/// ```
#[derive(Debug, Clone)]
pub struct Config {
    /// Server address, `host:port`. With port hopping, the port may be a range
    /// (e.g. `host:20000-50000`); see also [`Config::hop_ports`].
    pub server_addr: String,
    /// TLS SNI / server name. If empty, the host part of `server_addr` is used.
    pub server_name: String,
    /// Authentication string (sent in the `Hysteria-Auth` header).
    pub auth: String,
    /// Skip TLS certificate verification (test/self-signed only).
    pub insecure: bool,

    /// Client receive (download) bandwidth in **bytes/sec**, reported to the
    /// server via `Hysteria-CC-RX`. `0` = unknown → ask the server to use its
    /// own bandwidth detection (and the client uses BBR for sending).
    pub rx_bps: u64,

    /// Client send (upload) bandwidth cap in **bytes/sec**. When `> 0`, the
    /// client uses the Brutal congestion controller for the upload direction;
    /// when `0`, it uses BBR.
    ///
    /// After the handshake the rate is reconciled with the server's `CC-RX`
    /// header, exactly like the Go reference: a numeric value clamps Brutal to
    /// `min(tx_bps, server Rx)`, while `auto` switches the upload to BBR.
    pub tx_bps: u64,

    /// Salamander obfuscation pre-shared key. Empty = obfuscation disabled.
    /// Must be at least 4 bytes when set.
    pub obfs_password: String,

    /// Port-hopping port specification, e.g. `"20000-50000"` or
    /// `"443,8443,9000-9100"`. Empty = disabled (use the single port from
    /// `server_addr`). When set, datagrams are spread across these ports.
    pub hop_ports: String,
    /// Minimum hop interval in seconds. `0` selects the default (30s).
    pub hop_interval_min_secs: u64,
    /// Maximum hop interval in seconds. `0` makes the interval fixed at the min.
    pub hop_interval_max_secs: u64,

    /// Fast-open: return the proxied TCP stream before the server's TCPResponse
    /// (validated lazily on first read). Avoids a round-trip stall. Default on.
    pub fast_open: bool,

    /// Pin the server certificate to this SHA-256 fingerprint (hex, optional
    /// `:` separators). Empty = no pinning. Verified in addition to (or, with
    /// `insecure`, instead of) the normal chain.
    pub pin_sha256: String,
    /// Extra trusted root CA(s) in PEM, appended to the system roots. Empty =
    /// system roots only.
    pub ca_pem: String,

    /// QUIC transport tuning.
    pub quic: QuicParams,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            server_addr: String::new(),
            server_name: String::new(),
            auth: String::new(),
            insecure: false,
            rx_bps: 0,
            tx_bps: 0,
            obfs_password: String::new(),
            hop_ports: String::new(),
            hop_interval_min_secs: 0,
            hop_interval_max_secs: 0,
            fast_open: true,
            pin_sha256: String::new(),
            ca_pem: String::new(),
            quic: QuicParams::default(),
        }
    }
}

impl Config {
    pub(crate) fn resolved_server_name(&self) -> String {
        if !self.server_name.is_empty() {
            return self.server_name.clone();
        }
        self.host_part()
    }

    /// The host portion of `server_addr` (everything before the last `:`).
    pub(crate) fn host_part(&self) -> String {
        self.server_addr
            .rsplit_once(':')
            .map(|(h, _)| h.to_string())
            .unwrap_or_else(|| self.server_addr.clone())
    }
}

/// Parse a port-union string (single ports, comma lists and `a-b` ranges, or
/// `all`/`*`) into a sorted, de-duplicated port list. Returns `None` on a
/// malformed spec. Mirrors Go `utils.ParsePortUnion`.
pub(crate) fn parse_ports(spec: &str) -> Option<Vec<u16>> {
    if spec == "all" || spec == "*" {
        return Some((0..=u16::MAX).collect());
    }
    let mut ports: Vec<u16> = Vec::new();
    for part in spec.split(',') {
        if let Some((a, b)) = part.split_once('-') {
            let mut start: u16 = a.trim().parse().ok()?;
            let mut end: u16 = b.trim().parse().ok()?;
            if start > end {
                std::mem::swap(&mut start, &mut end);
            }
            ports.extend(start..=end);
        } else {
            ports.push(part.trim().parse().ok()?);
        }
    }
    if ports.is_empty() {
        return None;
    }
    ports.sort_unstable();
    ports.dedup();
    Some(ports)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ports_single_range_list() {
        assert_eq!(parse_ports("443"), Some(vec![443]));
        assert_eq!(parse_ports("443,445"), Some(vec![443, 445]));
        assert_eq!(parse_ports("100-103"), Some(vec![100, 101, 102, 103]));
        // Overlap + reversed range are normalized and de-duplicated.
        assert_eq!(parse_ports("103-100,101"), Some(vec![100, 101, 102, 103]));
        assert_eq!(parse_ports("*").unwrap().len(), 65536);
        assert!(parse_ports("nope").is_none());
        assert!(parse_ports("").is_none());
    }

    #[test]
    fn host_part_strips_port() {
        let c = Config {
            server_addr: "example.com:20000-50000".into(),
            ..Default::default()
        };
        assert_eq!(c.host_part(), "example.com");
        assert_eq!(c.resolved_server_name(), "example.com");
    }
}
