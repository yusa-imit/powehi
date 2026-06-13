use std::io::Cursor;
use std::sync::Arc;

use anyhow::Context;
use rustls::crypto::ring;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use tonic::transport::{Certificate, ClientTlsConfig, Identity, ServerTlsConfig};

const ALPN_H2: &[u8] = b"h2";

/// PEM-encoded TLS material for mTLS between regions.
pub struct TlsConfig {
    /// This region's server certificate (PEM).
    pub cert_pem: Vec<u8>,
    /// This region's private key (PEM).
    pub key_pem: Vec<u8>,
    /// CA certificate used to verify peer regions (PEM).
    pub ca_cert_pem: Vec<u8>,
}

impl TlsConfig {
    pub fn from_pem_files(
        cert_path: &str,
        key_path: &str,
        ca_cert_path: &str,
    ) -> anyhow::Result<Self> {
        let cert_pem =
            std::fs::read(cert_path).with_context(|| format!("read cert {cert_path}"))?;
        let key_pem = std::fs::read(key_path).with_context(|| format!("read key {key_path}"))?;
        let ca_cert_pem =
            std::fs::read(ca_cert_path).with_context(|| format!("read CA cert {ca_cert_path}"))?;
        Ok(Self {
            cert_pem,
            key_pem,
            ca_cert_pem,
        })
    }

    /// Build a `rustls::ServerConfig` with TLS 1.3 minimum for the gRPC inter-region listener.
    ///
    /// Closes Y-TLS-VERSION: tonic 0.12.3's `ServerTlsConfig` does not expose protocol-version
    /// pinning. This method builds the underlying `rustls::ServerConfig` directly with
    /// `builder_with_provider(ring).with_protocol_versions(&[&TLS13])`, guaranteeing that
    /// TLS 1.2 ClientHello messages are rejected at the handshake layer before any application
    /// data is exchanged.
    ///
    /// mTLS: `WebPkiClientVerifier` with the configured CA root — all peers must present a
    /// certificate signed by this CA. Anonymous (unauthenticated) clients are rejected.
    ///
    /// ALPN: `h2` only (gRPC over HTTP/2 per the gRPC-HTTP2 specification).
    ///
    /// Crypto backend: `ring` (matches tonic's tokio-rustls dependency; single backend in process).
    pub fn server_rustls_config(&self) -> anyhow::Result<Arc<ServerConfig>> {
        let provider = Arc::new(ring::default_provider());

        let ca_certs =
            parse_cert_chain_pem(&self.ca_cert_pem).context("parse CA certificate PEM")?;
        let mut roots = RootCertStore::empty();
        for cert in ca_certs {
            roots.add(cert).context("add CA cert to root store")?;
        }
        let verifier =
            WebPkiClientVerifier::builder_with_provider(Arc::new(roots), Arc::clone(&provider))
                .build()
                .context("build mTLS client cert verifier")?;

        let certs = parse_cert_chain_pem(&self.cert_pem).context("parse server certificate PEM")?;
        let key = parse_private_key_pem(&self.key_pem).context("parse server private key PEM")?;

        let mut config = ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .context("restrict gRPC TLS to 1.3")?
            .with_client_cert_verifier(verifier)
            .with_single_cert(certs, key)
            .context("set server certificate")?;

        config.alpn_protocols = vec![ALPN_H2.to_vec()];
        Ok(Arc::new(config))
    }

    /// Build a tonic `ServerTlsConfig` for mutual TLS.
    ///
    /// **Deprecated** — does not pin TLS 1.3 minimum (tonic 0.12 `ServerTlsConfig` exposes no
    /// protocol-version selection). Use `server_rustls_config()` for all production listeners.
    /// Retained only to avoid breaking any callers that test without a real TLS stack.
    #[deprecated(note = "use server_rustls_config() — this path does not enforce TLS 1.3 minimum")]
    pub fn server_tls(&self) -> anyhow::Result<ServerTlsConfig> {
        let identity = Identity::from_pem(&self.cert_pem, &self.key_pem);
        let ca = Certificate::from_pem(&self.ca_cert_pem);
        Ok(ServerTlsConfig::new().identity(identity).client_ca_root(ca))
    }

    /// Build a tonic `ClientTlsConfig` for mutual TLS.
    pub fn client_tls(&self, domain: &str) -> anyhow::Result<ClientTlsConfig> {
        let identity = Identity::from_pem(&self.cert_pem, &self.key_pem);
        let ca = Certificate::from_pem(&self.ca_cert_pem);
        Ok(ClientTlsConfig::new()
            .domain_name(domain)
            .ca_certificate(ca)
            .identity(identity))
    }

    /// Build a `rustls::ClientConfig` with TLS 1.3 minimum for outbound gRPC connections.
    ///
    /// Mirrors the server-side TLS 1.3 pin. This config is available for future integration
    /// with hyper-based gRPC clients that accept a custom `ClientConfig`. The tonic 0.12
    /// `ClientTlsConfig` path (used in `client_tls`) does not expose version pinning;
    /// upgrading to a custom hyper client or a tonic version with `rustls_client_config()`
    /// support would activate this.
    pub fn client_rustls_config(&self, domain: &str) -> anyhow::Result<Arc<ClientConfig>> {
        let provider = Arc::new(ring::default_provider());

        let ca_certs =
            parse_cert_chain_pem(&self.ca_cert_pem).context("parse CA certificate PEM")?;
        let mut roots = RootCertStore::empty();
        for cert in ca_certs {
            roots.add(cert).context("add CA cert to root store")?;
        }

        let certs = parse_cert_chain_pem(&self.cert_pem).context("parse client certificate PEM")?;
        let key = parse_private_key_pem(&self.key_pem).context("parse client private key PEM")?;

        let _ = domain; // SNI is set on the connection, not the config
        let config = ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .context("restrict gRPC client TLS to 1.3")?
            .with_root_certificates(roots)
            .with_client_auth_cert(certs, key)
            .context("set client certificate")?;

        Ok(Arc::new(config))
    }
}

fn parse_cert_chain_pem(pem: &[u8]) -> anyhow::Result<Vec<CertificateDer<'static>>> {
    rustls_pemfile::certs(&mut Cursor::new(pem))
        .collect::<Result<Vec<_>, _>>()
        .context("parse certificate chain PEM")
}

fn parse_private_key_pem(pem: &[u8]) -> anyhow::Result<PrivateKeyDer<'static>> {
    rustls_pemfile::private_key(&mut Cursor::new(pem))
        .context("read private key PEM")?
        .ok_or_else(|| anyhow::anyhow!("no private key found in PEM"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Generate a self-signed CA+server cert pair for unit tests.
    fn test_tls_config() -> TlsConfig {
        use rcgen::{CertificateParams, KeyPair};

        let key_pair = KeyPair::generate().expect("test key generation");
        let mut params =
            CertificateParams::new(vec!["eu-de-1".to_string()]).expect("test cert params");
        // Mark as CA so it can verify itself (client cert verifier needs CA trust anchor)
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let cert = params
            .self_signed(&key_pair)
            .expect("test self-signed cert");

        let cert_pem = cert.pem().into_bytes();
        let key_pem = key_pair.serialize_pem().into_bytes();

        TlsConfig {
            cert_pem: cert_pem.clone(),
            key_pem,
            ca_cert_pem: cert_pem, // self-signed CA
        }
    }

    #[test]
    fn server_rustls_config_builds_without_error() {
        let cfg = test_tls_config();
        let result = cfg.server_rustls_config();
        assert!(
            result.is_ok(),
            "server_rustls_config failed: {:?}",
            result.err()
        );
    }

    #[test]
    fn server_rustls_config_has_h2_alpn() {
        let cfg = test_tls_config();
        let config = cfg.server_rustls_config().expect("build config");
        assert_eq!(
            config.alpn_protocols,
            vec![b"h2".to_vec()],
            "ALPN must be h2 only (gRPC requirement)"
        );
    }

    #[test]
    fn server_rustls_config_rejects_missing_ca() {
        let cfg = TlsConfig {
            cert_pem: b"not a cert".to_vec(),
            key_pem: b"not a key".to_vec(),
            ca_cert_pem: b"not a ca cert".to_vec(),
        };
        assert!(
            cfg.server_rustls_config().is_err(),
            "invalid PEM must return error"
        );
    }

    #[test]
    fn client_rustls_config_builds_without_error() {
        let cfg = test_tls_config();
        let result = cfg.client_rustls_config("eu-de-1");
        assert!(
            result.is_ok(),
            "client_rustls_config failed: {:?}",
            result.err()
        );
    }

    #[test]
    fn parse_cert_chain_pem_rejects_garbage() {
        let result = parse_cert_chain_pem(b"not pem garbage");
        // garbage yields empty vec (no certs found), not an error at parse level
        // but the config builder will reject an empty cert chain
        assert!(result.is_ok());
        assert!(
            result.unwrap().is_empty(),
            "garbage PEM should yield no certs"
        );
    }

    #[test]
    fn parse_private_key_pem_rejects_missing_key() {
        let result =
            parse_private_key_pem(b"-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n");
        // A cert PEM has no private key
        assert!(
            result.is_err(),
            "PEM with no private key should return error"
        );
    }
}
