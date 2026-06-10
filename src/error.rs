use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("invalid config: {0}")]
    Config(String),

    #[error("tls error: {0}")]
    Tls(#[from] rustls::Error),

    #[error("quic connect error: {0}")]
    Connect(#[from] quinn::ConnectError),

    #[error("quic connection error: {0}")]
    Connection(#[from] quinn::ConnectionError),

    #[error("h3 connection error: {0}")]
    H3Connection(#[from] h3::error::ConnectionError),

    #[error("h3 stream error: {0}")]
    H3Stream(#[from] h3::error::StreamError),

    #[error("auth failed: server returned status {0}")]
    AuthFailed(u16),

    #[error("tcp_connect rejected by server: {0}")]
    TcpRejected(String),

    #[error("protocol error: {0}")]
    Protocol(String),
}

pub type Result<T> = std::result::Result<T, Error>;
