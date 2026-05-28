use anyhow::Context;
use tonic::transport::{Certificate, ClientTlsConfig, Identity, ServerTlsConfig};

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

    /// Build a tonic `ServerTlsConfig` for mutual TLS.
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
}
