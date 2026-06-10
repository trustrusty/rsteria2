use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use crate::{
    client::HysteriaClient,
    config::{parse_ports, Config},
    error::{Error, Result},
    protocol::auth_request_padding,
    transport::{build_client_config, build_endpoint, parse_pin, HopConfig, Salamander},
};

/// Hysteria2 auth success HTTP status (intentionally non-standard).
const STATUS_AUTH_OK: u16 = 233;
/// Default port-hop interval when the config leaves it at 0 (Go: 30s).
const DEFAULT_HOP_INTERVAL_SECS: u64 = 30;

/// Outcome of the auth handshake (Go `AuthResponse`).
struct AuthResponse {
    udp_enabled: bool,
    /// Server's advertised receive rate (bytes/sec); 0 = unlimited.
    server_rx: u64,
    /// Server asked the client to use its own bandwidth detection.
    rx_auto: bool,
}

/// Connect to a Hysteria2 server and perform the HTTP/3 auth handshake.
pub async fn connect(config: &Config) -> Result<HysteriaClient> {
    // Ensure a rustls crypto provider is installed (idempotent).
    let _ = rustls::crypto::ring::default_provider().install_default();

    let server_name = config.resolved_server_name();

    // Resolve the server IP and the set of candidate ports (for port hopping).
    let (canonical, hop) = resolve_endpoint(config).await?;

    // Optional Salamander obfuscation.
    let obfs = if config.obfs_password.is_empty() {
        None
    } else {
        Some(
            Salamander::new(config.obfs_password.as_bytes())
                .ok_or_else(|| Error::Config("obfs password must be at least 4 bytes".into()))?,
        )
    };

    let pin = parse_pin(&config.pin_sha256)?;
    let crypto = build_client_config(config.insecure, pin, &config.ca_pem)?;

    // When an upload cap is configured, the connection uses a switchable
    // Brutal/BBR controller. `rate` drives Brutal; `use_bbr` flips the window
    // over to BBR. Both are tuned after the handshake from the server's CC-RX,
    // mirroring Go's `actualTx = min(serverRx, clientTx)` (and its auto → BBR).
    let brutal = if config.tx_bps > 0 {
        Some((
            Arc::new(AtomicU64::new(config.tx_bps)),
            Arc::new(AtomicBool::new(false)),
        ))
    } else {
        None
    };
    let endpoint = build_endpoint(crypto, brutal.clone(), &config.quic, obfs, hop, canonical)?;

    let conn = endpoint.connect(canonical, &server_name)?.await?;

    let auth = authenticate(&conn, config).await?;
    if let Some((rate, use_bbr)) = &brutal {
        if auth.rx_auto {
            // Server refuses to give a rate → use our own congestion control.
            use_bbr.store(true, Ordering::Relaxed);
            tracing::debug!("hysteria2: server CC-RX=auto, switching upload to BBR");
        } else if auth.server_rx > 0 {
            // Clamp the live Brutal rate to min(configured, server Rx).
            let clamped = config.tx_bps.min(auth.server_rx);
            rate.store(clamped, Ordering::Relaxed);
            tracing::debug!(
                "hysteria2: clamped Brutal tx rate to {} B/s (server CC-RX={})",
                clamped,
                auth.server_rx
            );
        }
        // server_rx == 0 → server is unlimited → keep configured rate.
    }

    Ok(HysteriaClient::new(
        conn,
        endpoint,
        config.fast_open,
        auth.udp_enabled,
        auth.server_rx,
    ))
}

/// Resolve the server address into a concrete `SocketAddr` and, if more than
/// one port is in play, a [`HopConfig`].
async fn resolve_endpoint(config: &Config) -> Result<(SocketAddr, Option<HopConfig>)> {
    let host = config.host_part();

    // Port spec: explicit hop_ports wins; otherwise use the port from
    // server_addr (which may itself be a range like `host:20000-50000`).
    let port_spec = if !config.hop_ports.is_empty() {
        config.hop_ports.clone()
    } else {
        config
            .server_addr
            .rsplit_once(':')
            .map(|(_, p)| p.to_string())
            .ok_or_else(|| Error::Config(format!("server_addr missing port: {}", config.server_addr)))?
    };

    let ports =
        parse_ports(&port_spec).ok_or_else(|| Error::Config(format!("invalid ports: {port_spec}")))?;

    // Resolve the host to an IP using the first port.
    let first_port = ports[0];
    let ip = tokio::net::lookup_host((host.as_str(), first_port))
        .await?
        .next()
        .ok_or_else(|| Error::Config(format!("could not resolve server host: {host}")))?
        .ip();

    let canonical = SocketAddr::new(ip, first_port);

    if ports.len() <= 1 {
        return Ok((canonical, None));
    }

    let addrs: Vec<SocketAddr> = ports.iter().map(|&p| SocketAddr::new(ip, p)).collect();
    let min = if config.hop_interval_min_secs == 0 {
        DEFAULT_HOP_INTERVAL_SECS
    } else {
        config.hop_interval_min_secs
    };
    let max = if config.hop_interval_max_secs == 0 {
        min
    } else {
        config.hop_interval_max_secs.max(min)
    };
    let hop = HopConfig {
        addrs,
        interval_min: Duration::from_secs(min),
        interval_max: Duration::from_secs(max),
    };
    Ok((canonical, Some(hop)))
}

/// Perform the `POST https://hysteria/auth` HTTP/3 request and validate it.
async fn authenticate(conn: &quinn::Connection, config: &Config) -> Result<AuthResponse> {
    let h3_conn = h3_quinn::Connection::new(conn.clone());
    let (driver, mut send_request) = h3::client::new(h3_conn).await?;

    let req = http::Request::builder()
        .method(http::Method::POST)
        .uri("https://hysteria/auth")
        .header("Host", "hysteria")
        .header("Hysteria-Auth", &config.auth)
        .header("Hysteria-CC-RX", config.rx_bps.to_string())
        .header("Hysteria-Padding", auth_request_padding())
        .body(())
        .map_err(|e| Error::Protocol(format!("build auth request: {e}")))?;

    let mut stream = send_request.send_request(req).await?;
    stream.finish().await?;
    let resp = stream.recv_response().await?;

    // We're done with HTTP/3. The raw QUIC connection (held via `conn`) is
    // reused for proxying, so just drop the h3 driver — that does not close the
    // underlying connection. (Driving it to completion *would* close it.)
    drop(send_request);
    drop(driver);

    let status = resp.status().as_u16();
    if status != STATUS_AUTH_OK {
        return Err(Error::AuthFailed(status));
    }

    let headers = resp.headers();
    let udp_enabled = headers
        .get("Hysteria-UDP")
        .and_then(|v| v.to_str().ok())
        == Some("true");

    // Hysteria-CC-RX is either "auto" or a byte/sec integer (Go `AuthResponse`).
    let (server_rx, rx_auto) = match headers.get("Hysteria-CC-RX").and_then(|v| v.to_str().ok()) {
        Some("auto") => (0, true),
        Some(s) => (s.parse::<u64>().unwrap_or(0), false),
        None => (0, false),
    };

    Ok(AuthResponse {
        udp_enabled,
        server_rx,
        rx_auto,
    })
}
