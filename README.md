# rsteria2

A clean, async Rust **client** for the [Hysteria2](https://hysteria.network/)
proxy protocol, built on [quinn](https://github.com/quinn-rs/quinn).

`rsteria2` is a from-scratch, dependency-light implementation of the Hysteria2
client, written against the official Go reference
([apernet/hysteria](https://github.com/apernet/hysteria)) and its
[protocol specification](https://v2.hysteria.network/docs/developers/Protocol/).
It is a **library**, not a proxy app: it exposes proxied TCP streams and UDP
sessions, and leaves local inbound (SOCKS5/HTTP) to the caller.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

## Features

- **HTTP/3 authentication** (`POST https://hysteria/auth`, status `233`) with the
  `Hysteria-Auth` / `Hysteria-CC-RX` / `Hysteria-Padding` headers.
- **TCP proxying** with QUIC-varint framing and reference-exact random padding.
- **Fast-open**: `tcp_connect` returns before the server's `TCPResponse`, which is
  validated lazily on first read — no round-trip stall, and no multi-second
  deadlock against servers that defer their response until they have upstream
  data. Can be turned off to surface a rejection eagerly.
- **UDP relay** over QUIC unreliable datagrams, with session management and
  automatic fragmentation / reassembly.
- **Salamander obfuscation** — per-packet `BLAKE2b-256(PSK ‖ salt)` XOR masking,
  wire-compatible with the Go `obfs` layer.
- **UDP port hopping** — spreads datagrams across a port range on a randomized
  interval, rewriting the peer address so QUIC never sees a path change.
- **Congestion control** — the signature **Brutal** fixed-rate controller (ported
  to quinn's `Controller` trait) or **BBR**, reconciled with the server's
  advertised receive rate after the handshake.
- **TLS** — system roots, additional custom CA PEM, `pinSHA256` certificate
  pinning, or fully insecure for testing.
- **Reconnection** — an optional `ReconnectableClient` that re-establishes the
  connection on demand.
- Tunable QUIC transport (receive windows, idle timeout, keep-alive, PMTUD).

## Installation

Not published to crates.io. Add it as a git or path dependency:

```toml
[dependencies]
rsteria2 = { git = "https://github.com/trustrusty/rsteria2" }
```

Requires a Tokio runtime and a process-wide rustls crypto provider; `connect`
installs the `ring` provider if none is set.

## Usage

### TCP

```rust,no_run
use rsteria2::{Config, connect};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

# async fn run() -> Result<(), Box<dyn std::error::Error>> {
let cfg = Config {
    server_addr: "example.com:443".into(),
    auth: "my-password".into(),
    ..Default::default()
};
let client = connect(&cfg).await?;

let mut conn = client.tcp_connect("ifconfig.me:80").await?;
conn.write_all(b"GET / HTTP/1.0\r\nHost: ifconfig.me\r\n\r\n").await?;
let mut buf = Vec::new();
conn.read_to_end(&mut buf).await?;
# Ok(()) }
```

The returned `DuplexStream` implements `AsyncRead + AsyncWrite`, so it drops
straight into `tokio::io::copy_bidirectional` for a SOCKS5/HTTP front-end.

### UDP

```rust,no_run
# use rsteria2::HysteriaClient;
# async fn run(client: HysteriaClient) -> Result<(), Box<dyn std::error::Error>> {
if client.udp_enabled() {
    let mut sess = client.udp()?;
    sess.send(&dns_query, "8.8.8.8:53")?;
    let (reply, from) = sess.recv().await?;
}
# Ok(()) }
```

### Obfuscation, port hopping & pinning

```rust,no_run
# use rsteria2::Config;
let cfg = Config {
    server_addr: "example.com:20000-50000".into(), // a port range enables hopping
    auth: "my-password".into(),
    obfs_password: "shared-secret".into(),          // Salamander
    hop_interval_min_secs: 30,
    hop_interval_max_secs: 60,                       // 0 = fixed at min
    pin_sha256: "ab:cd:…".into(),                    // optional cert pin (hex)
    ca_pem: "-----BEGIN CERTIFICATE-----\n…".into(), // optional extra root
    ..Default::default()
};
```

Port hopping can also be driven by a separate `hop_ports` spec (e.g.
`"443,8443,9000-9100"`) while keeping a single connect port in `server_addr`.

### Reconnecting client

```rust,no_run
# use rsteria2::{Config, ReconnectableClient};
# async fn run(cfg: Config) -> Result<(), Box<dyn std::error::Error>> {
let client = ReconnectableClient::new(cfg); // lazy; connects on first use
let mut conn = client.tcp_connect("example.com:80").await?;
// `invalidate()` drops the connection so the next call reconnects
// (e.g. after the device wakes from sleep with a dead UDP socket).
client.invalidate().await;
# Ok(()) }
```

## Configuration

All knobs live on `Config` (see the crate docs for full details):

| Field | Meaning |
| --- | --- |
| `server_addr` | `host:port`; the port may be a range for hopping |
| `server_name` | TLS SNI; defaults to the host of `server_addr` |
| `auth` | authentication string |
| `rx_bps` / `tx_bps` | download / upload caps in bytes/sec (`0` = BBR / server decides) |
| `obfs_password` | Salamander PSK (≥ 4 bytes); empty = off |
| `hop_ports`, `hop_interval_{min,max}_secs` | port-hopping spec and interval |
| `fast_open` | return TCP streams before the server response (default `true`) |
| `insecure`, `pin_sha256`, `ca_pem` | TLS verification options |
| `quic` | `QuicParams`: receive windows, idle timeout, keep-alive, PMTUD |

## Congestion control & bandwidth

Hysteria2 lets either side cap the other's send rate. The client advertises
`rx_bps` via `Hysteria-CC-RX`; the server answers with its own receive rate.
Because quinn fixes the congestion controller at connect time, the connection
runs a **switchable Brutal/BBR controller**: a numeric server `CC-RX` clamps
Brutal to `min(tx_bps, server_rx)`, and `CC-RX: auto` hands the upload window to
BBR — matching the Go reference's behaviour without swapping controllers
mid-connection. The server's advertised value is exposed via
`HysteriaClient::server_rx()`.

## Protocol coverage

Aligned with the Go reference at the protocol and client-library level: HTTP/3
auth, TCP framing and padding (`{256,2048}` / `{64,512}` / `{128,1024}`), UDP
relay with fragmentation, Salamander, port hopping, Brutal/BBR with post-handshake
bandwidth negotiation, and TLS pinning.

**Intentionally out of scope** (no Go-equivalent in quinn, or app-layer concern):
client-certificate mTLS, quic-go-specific congestion `Type`/`BBRProfile`
selection, separate initial-vs-max receive windows, and any server-side or
local-inbound (SOCKS5/HTTP) functionality.

## Status & testing

Protocol codec logic — UDP message round-trips, fragmentation/reassembly,
Salamander masking, port-spec and pin parsing — is covered by unit tests
(`cargo test`), and the crate builds clean under `cargo clippy`. End-to-end
testing against a live Hysteria2 server is recommended before production use;
contributions of integration tests are welcome.

## License

MIT — see [LICENSE](LICENSE).
