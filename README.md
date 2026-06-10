# rsteria2

A clean, async Rust **client** for the [Hysteria2](https://hysteria.network/)
proxy protocol, built on [quinn](https://github.com/quinn-rs/quinn).

Implemented from scratch against the official Go reference
([apernet/hysteria](https://github.com/apernet/hysteria)), with the protocol
details that matter for correctness and performance:

- **HTTP/3 authentication** (`POST https://hysteria/auth`, status `233`),
  including bandwidth negotiation headers (`Hysteria-CC-RX`, `auto`).
- **TCP request/response framing** with QUIC varints and random padding
  (auth `[256, 2048)`, request `[64, 512)`), matching the reference byte for byte.
- **UDP relay** over QUIC unreliable datagrams: session management, automatic
  fragmentation and reassembly (`UDPMessage`, `Defragger`).
- **Salamander obfuscation** — per-packet `BLAKE2b-256(PSK ‖ salt)` XOR masking,
  wire-compatible with the Go `obfs` layer.
- **UDP port hopping** — spreads datagrams across a configured port range on a
  randomized interval, rewriting the peer address so QUIC never sees a path
  change (equivalent to Go's `DisablePathManager`).
- **Fast-open**: `tcp_connect` returns immediately and validates the server's
  `TCPResponse` lazily on first read, so application data flows out without a
  round-trip stall. (A naive "wait for the response first" client deadlocks for
  several seconds against servers that defer their response until they have
  upstream data — this avoids that entirely.) Can be turned off.
- **Brutal congestion control** — the signature Hysteria2 fixed-rate,
  loss-tolerant controller, ported to quinn's `Controller` trait; or BBR.
- **TLS**: system roots, custom CA PEM, `pinSHA256` certificate pinning, or fully
  insecure for testing.
- **Reconnection**: an optional [`ReconnectableClient`] that re-establishes the
  connection on demand.
- Tunable QUIC transport (receive windows, idle timeout, keep-alive).

## Usage

```rust
use rsteria2::{Config, connect};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

let cfg = Config {
    server_addr: "example.com:443".into(),
    auth: "my-password".into(),
    ..Default::default()
};
let client = connect(&cfg).await?;

// TCP
let mut conn = client.tcp_connect("ifconfig.me:80").await?;
conn.write_all(b"GET / HTTP/1.0\r\nHost: ifconfig.me\r\n\r\n").await?;
let mut buf = Vec::new();
conn.read_to_end(&mut buf).await?;

// UDP (if the server enabled relay)
if client.udp_enabled() {
    let mut sess = client.udp()?;
    sess.send(b"\x00\x00...", "8.8.8.8:53")?; // a DNS query
    let (reply, from) = sess.recv().await?;
}
```

Enable obfuscation and port hopping via the config:

```rust
let cfg = Config {
    server_addr: "example.com:20000-50000".into(), // port range → hopping
    auth: "my-password".into(),
    obfs_password: "shared-secret".into(),         // Salamander
    hop_interval_min_secs: 30,
    pin_sha256: "ab:cd:...".into(),                 // optional cert pin
    ..Default::default()
};
```

## Scope & non-goals

- **Client only** (no server implementation).
- Congestion control honours the server's post-handshake `CC-RX` just like Go,
  despite quinn fixing the controller at connect time: the connection runs a
  switchable Brutal/BBR controller, so a numeric `CC-RX` clamps Brutal to
  `min(tx_bps, server Rx)` and `CC-RX: auto` hands the upload window to BBR. The
  server's value is also exposed via `HysteriaClient::server_rx()`.

## License

MIT
