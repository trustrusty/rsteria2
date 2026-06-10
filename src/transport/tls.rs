use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::WebPkiServerVerifier;
use rustls::{RootCertStore, SignatureScheme};
use rustls_pki_types::{CertificateDer, ServerName, UnixTime};
use sha2::{Digest, Sha256};

use crate::error::{Error, Result};

const ALPN_H3: &[u8] = b"h3";

/// Build the rustls client config used for the QUIC/HTTP3 handshake.
/// ALPN is fixed to `h3` (Hysteria2 masquerades as HTTP/3).
///
/// - `insecure`: skip standard chain verification.
/// - `pin_sha256`: if set, the server's leaf certificate must hash to this
///   SHA-256 digest (checked on top of, or instead of, chain verification).
/// - `ca_pem`: extra trusted roots in PEM, appended to the system roots.
pub(crate) fn build_client_config(
    insecure: bool,
    pin_sha256: Option<[u8; 32]>,
    ca_pem: &str,
) -> Result<Arc<rustls::ClientConfig>> {
    let builder = rustls::ClientConfig::builder();

    let roots = build_roots(ca_pem)?;

    let with_verifier = match (insecure, pin_sha256) {
        // Standard verification against the (possibly extended) root store.
        (false, None) => builder.with_root_certificates(roots),
        // No verification at all.
        (true, None) => builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerify)),
        // Pinned: optionally still verify the chain when not insecure.
        (_, Some(pin)) => {
            let inner = if insecure {
                None
            } else {
                Some(
                    WebPkiServerVerifier::builder(Arc::new(roots))
                        .build()
                        .map_err(|e| Error::Config(format!("build verifier: {e}")))?,
                )
            };
            builder
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(PinVerifier { inner, pin }))
        }
    };

    let mut cfg = with_verifier.with_no_client_auth();
    cfg.alpn_protocols = vec![ALPN_H3.to_vec()];
    Ok(Arc::new(cfg))
}

/// System roots plus any caller-provided PEM CAs.
fn build_roots(ca_pem: &str) -> Result<RootCertStore> {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    if !ca_pem.is_empty() {
        let mut rd = ca_pem.as_bytes();
        for cert in rustls_pemfile::certs(&mut rd) {
            let cert = cert.map_err(|e| Error::Config(format!("parse CA PEM: {e}")))?;
            roots
                .add(cert)
                .map_err(|e| Error::Config(format!("add CA: {e}")))?;
        }
    }
    Ok(roots)
}

/// Parse a `pin_sha256` string (hex with optional `:` separators / whitespace)
/// into 32 bytes. Returns `Ok(None)` for an empty string.
pub(crate) fn parse_pin(s: &str) -> Result<Option<[u8; 32]>> {
    if s.is_empty() {
        return Ok(None);
    }
    let hex: String = s
        .chars()
        .filter(|c| !c.is_whitespace() && *c != ':')
        .collect();
    if hex.len() != 64 {
        return Err(Error::Config(
            "pin_sha256 must be 32 bytes (64 hex chars)".into(),
        ));
    }
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)
            .map_err(|_| Error::Config("pin_sha256 is not valid hex".into()))?;
    }
    Ok(Some(out))
}

/// Verifier that pins the leaf certificate to a SHA-256 digest, optionally
/// delegating full chain verification to an inner WebPKI verifier.
#[derive(Debug)]
struct PinVerifier {
    inner: Option<Arc<WebPkiServerVerifier>>,
    pin: [u8; 32],
}

impl ServerCertVerifier for PinVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp: &[u8],
        now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        let digest = Sha256::digest(end_entity.as_ref());
        if digest.as_slice() != self.pin {
            return Err(rustls::Error::General(
                "certificate SHA-256 does not match pin".into(),
            ));
        }
        if let Some(inner) = &self.inner {
            inner.verify_server_cert(end_entity, intermediates, server_name, ocsp, now)
        } else {
            Ok(ServerCertVerified::assertion())
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        match &self.inner {
            Some(inner) => inner.verify_tls12_signature(message, cert, dss),
            None => Ok(HandshakeSignatureValid::assertion()),
        }
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        match &self.inner {
            Some(inner) => inner.verify_tls13_signature(message, cert, dss),
            None => Ok(HandshakeSignatureValid::assertion()),
        }
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        match &self.inner {
            Some(inner) => inner.supported_verify_schemes(),
            None => all_schemes(),
        }
    }
}

/// Certificate verifier that accepts everything (used only when `insecure`).
#[derive(Debug)]
struct NoVerify;

impl ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        all_schemes()
    }
}

fn all_schemes() -> Vec<SignatureScheme> {
    use rustls::SignatureScheme::*;
    vec![
        RSA_PKCS1_SHA256,
        ECDSA_NISTP256_SHA256,
        RSA_PKCS1_SHA384,
        ECDSA_NISTP384_SHA384,
        RSA_PKCS1_SHA512,
        ECDSA_NISTP521_SHA512,
        RSA_PSS_SHA256,
        RSA_PSS_SHA384,
        RSA_PSS_SHA512,
        ED25519,
        ED448,
    ]
}
