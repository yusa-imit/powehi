//! SPKI certificate pinning for every TLS connection the CLI makes (prd.md §3.1 T2, §7A.3).
//!
//! The pin check runs *after* normal WebPKI verification (chain, name, expiry, signature): a
//! pin never replaces the CA check, it narrows it. A pin is the SHA-256 of a certificate's
//! DER `SubjectPublicKeyInfo`. A deployment may pin its leaf key or an intermediate's key (a pinned intermediate must really
//! be on the verified path, see `pinned_on_verified_path`). Root keys cannot be pinned: servers
//! do not send roots. A [`PinSet`] needs at least two
//! pins: one backup whose key is not yet deployed, so a key rotation never strands the fleet.
//! Rotation procedure: `docs/runbooks/cli-pin-rotation.md`.
//!
//! The production pin set is compiled in as [`PRODUCTION_PINS`]. It is empty until Phase 9
//! (9.9) chooses the production chain (ADR-0007), and an empty set means WebPKI only.

use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::WebPkiServerVerifier;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{CertificateError, DigitallySignedStruct, Error, RootCertStore, SignatureScheme};
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Length of a pin: a SHA-256 digest.
pub const PIN_LEN: usize = 32;
/// Fewest pins a non-empty set may hold: the live key and one backup.
pub const MIN_PINS: usize = 2;
/// Most pins a set may hold; a bound so a bad constant cannot grow without limit.
pub const MAX_PINS: usize = 8;
/// Most certificates examined per handshake (leaf plus intermediates).
const MAX_CHAIN: usize = 8;

/// Production pins, base64-free raw digests. Empty until Phase 9 task 9.9.
pub const PRODUCTION_PINS: &[[u8; PIN_LEN]] = &[];

#[derive(Debug, Error, PartialEq, Eq)]
pub enum PinError {
    #[error("a pin set needs at least {MIN_PINS} pins (one backup), got {0}")]
    TooFew(usize),
    #[error("a pin set holds at most {MAX_PINS} pins, got {0}")]
    TooMany(usize),
    #[error("duplicate pin in the set")]
    Duplicate,
    #[error("TLS configuration could not be built")]
    Config,
}

/// A validated set of SPKI SHA-256 pins.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinSet(Vec<[u8; PIN_LEN]>);

impl PinSet {
    pub fn new(pins: &[[u8; PIN_LEN]]) -> Result<Self, PinError> {
        if pins.len() < MIN_PINS {
            return Err(PinError::TooFew(pins.len()));
        }
        if pins.len() > MAX_PINS {
            return Err(PinError::TooMany(pins.len()));
        }
        for (i, pin) in pins.iter().enumerate() {
            if pins[..i].contains(pin) {
                return Err(PinError::Duplicate);
            }
        }
        Ok(Self(pins.to_vec()))
    }

    fn contains(&self, pin: &[u8; PIN_LEN]) -> bool {
        self.0.contains(pin)
    }
}

/// Whether TLS connections are narrowed to a pin set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PinPolicy {
    /// WebPKI verification only (no production pins exist yet, and test servers).
    WebPkiOnly,
    /// WebPKI verification, then at least one chain certificate must match a pin.
    Enforce(PinSet),
}

impl PinPolicy {
    /// The policy of a release build: [`PRODUCTION_PINS`], or WebPKI only while it is empty.
    pub fn production() -> Result<Self, PinError> {
        if PRODUCTION_PINS.is_empty() {
            return Ok(Self::WebPkiOnly);
        }
        Ok(Self::Enforce(PinSet::new(PRODUCTION_PINS)?))
    }
}

/// SHA-256 of the DER `SubjectPublicKeyInfo` of `cert`, or `None` if it does not parse.
pub fn spki_pin(cert: &CertificateDer<'_>) -> Option<[u8; PIN_LEN]> {
    let (_, parsed) = x509_parser::parse_x509_certificate(cert.as_ref()).ok()?;
    let digest = Sha256::digest(parsed.tbs_certificate.subject_pki.raw);
    Some(digest.into())
}

/// WebPKI verification followed by the pin check.
#[derive(Debug)]
struct PinnedVerifier {
    inner: Arc<WebPkiServerVerifier>,
    pins: PinSet,
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl PinnedVerifier {
    /// True when a pinned key sits on a path that really verifies the leaf. The server chooses
    /// which extra certificates it sends and WebPKI ignores the unused ones, so a pin match
    /// among them proves nothing (the OkHttp CVE-2016-2402 class). The leaf is accepted on
    /// its own pin because `inner` just verified it. Any other pinned certificate `C` must
    /// verify the leaf again as the *only* trust anchor, so `C` is provably on the path.
    fn pinned_on_verified_path(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        now: UnixTime,
    ) -> bool {
        if spki_pin(end_entity).is_some_and(|p| self.pins.contains(&p)) {
            return true;
        }
        for (i, candidate) in intermediates.iter().take(MAX_CHAIN).enumerate() {
            if !spki_pin(candidate).is_some_and(|p| self.pins.contains(&p)) {
                continue;
            }
            let mut roots = RootCertStore::empty();
            if roots.add(candidate.clone()).is_err() {
                continue;
            }
            let Ok(only) =
                WebPkiServerVerifier::builder_with_provider(Arc::new(roots), self.provider.clone())
                    .build()
            else {
                continue;
            };
            let rest: Vec<CertificateDer<'_>> = intermediates
                .iter()
                .enumerate()
                .filter(|(j, _)| *j != i)
                .map(|(_, c)| c.clone())
                .collect();
            if only
                .verify_server_cert(end_entity, &rest, server_name, &[], now)
                .is_ok()
            {
                return true;
            }
        }
        false
    }
}

impl ServerCertVerifier for PinnedVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        let verified = self.inner.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        )?;
        if self.pinned_on_verified_path(end_entity, intermediates, server_name, now) {
            Ok(verified)
        } else {
            Err(Error::InvalidCertificate(CertificateError::Other(
                rustls::OtherError(Arc::new(PinMismatch)),
            )))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

#[derive(Debug)]
struct PinMismatch;

impl std::fmt::Display for PinMismatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("server certificate does not match a pinned key")
    }
}

impl std::error::Error for PinMismatch {}

/// The Mozilla root store the CLI trusts.
pub fn webpki_roots_store() -> RootCertStore {
    RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    }
}

/// A TLS 1.3-only client config (7.11 F11) over `roots`, narrowed by `policy`. The `ring`
/// provider is named explicitly: the process default is ambiguous when another workspace
/// crate enables `aws-lc-rs`.
pub fn tls_config(
    roots: RootCertStore,
    policy: &PinPolicy,
) -> Result<rustls::ClientConfig, PinError> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|_| PinError::Config)?;
    let config = match policy {
        PinPolicy::WebPkiOnly => builder.with_root_certificates(roots).with_no_client_auth(),
        PinPolicy::Enforce(pins) => {
            let inner =
                WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider.clone())
                    .build()
                    .map_err(|_| PinError::Config)?;
            builder
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(PinnedVerifier {
                    inner,
                    pins: pins.clone(),
                    provider,
                }))
                .with_no_client_auth()
        }
    };
    debug_assert!(config.alpn_protocols.is_empty());
    Ok(config)
}

#[cfg(test)]
mod tests;
