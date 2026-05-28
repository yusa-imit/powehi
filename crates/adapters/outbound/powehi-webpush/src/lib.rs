//! VAPID Web Push adapter (RFC 8292 + RFC 8291).
//!
//! Sends empty-body push notifications — notification content is rendered by the
//! Service Worker (hardcoded "New encrypted message"). The server NEVER sees or
//! transmits message content, so there is no RFC 8291 ECE body encryption here:
//! an empty body needs no content encryption.
//!
//! VAPID signing: ES256 (ECDSA-P256-SHA256) using the `p256` crate (RustCrypto).
//! No homegrown crypto (rule: crypto-libraries-pinned).
//!
//! Security invariants (rule: no-plaintext-logging):
//!   - NEVER log the endpoint URL (it embeds a device-identifiable push ID).
//!   - NEVER log p256dh or auth_secret.
//!   - Logs carry only an outcome word and an error category.

use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use base64ct::{Base64UrlUnpadded, Encoding};
use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use p256::pkcs8::DecodePrivateKey;
use powehi_domain::{error::DomainError, push_subscription::PushSubscription};
use powehi_port_outbound::web_push::WebPushPort;
use reqwest::Client;

/// VAPID TTL header (seconds the push service should retain an undelivered push).
const PUSH_TTL_SECS: u64 = 86_400;
/// VAPID JWT validity window. RFC 8292 caps `exp` at 24h; 12h is well within it.
const JWT_EXP_SECS: u64 = 12 * 60 * 60;
/// Outbound push request timeout. Push delivery is fire-and-forget (best-effort
/// wake-up); a slow/unreachable push service must not stall the message path.
const PUSH_REQUEST_TIMEOUT_SECS: u64 = 10;

/// Immutable VAPID signing material + contact, loaded once at startup.
pub struct VapidConfig {
    signing_key: SigningKey,
    contact: String,
}

impl VapidConfig {
    /// Build from a PKCS#8 PEM-encoded P-256 private key and a contact URI
    /// (`mailto:` or `https:` per RFC 8292 §2.1).
    pub fn from_pem(
        private_key_pem: &str,
        contact: impl Into<String>,
    ) -> Result<Self, DomainError> {
        let signing_key = SigningKey::from_pkcs8_pem(private_key_pem)
            .map_err(|_| DomainError::Internal("invalid VAPID private key PEM".into()))?;
        Ok(Self {
            signing_key,
            contact: contact.into(),
        })
    }

    /// Base64url-unpadded uncompressed (65-byte) public key for the `k=` param.
    fn public_key_b64url(&self) -> String {
        let vk = self.signing_key.verifying_key();
        let point = vk.to_encoded_point(false);
        Base64UrlUnpadded::encode_string(point.as_bytes())
    }
}

/// Build the signed VAPID JWT (RFC 8292) for a given audience origin.
///
/// Pure function (no I/O) so it is unit-testable. `now_unix` is injected so
/// tests can pin the clock. Returns `header.claims.signature`, each segment
/// base64url-unpadded.
fn build_vapid_jwt(signing_key: &SigningKey, aud: &str, contact: &str, now_unix: u64) -> String {
    // Header: {"typ":"JWT","alg":"ES256"}
    let header = r#"{"typ":"JWT","alg":"ES256"}"#;
    let header_b64 = Base64UrlUnpadded::encode_string(header.as_bytes());

    // Claims: aud / exp / sub. Use serde_json to ensure correct JSON escaping of
    // aud (derived from attacker-influenced endpoint URL) and contact URI.
    let exp = now_unix + JWT_EXP_SECS;
    let claims = serde_json::json!({ "aud": aud, "exp": exp, "sub": contact }).to_string();
    let claims_b64 = Base64UrlUnpadded::encode_string(claims.as_bytes());

    let signing_input = format!("{header_b64}.{claims_b64}");
    let signature: Signature = signing_key.sign(signing_input.as_bytes());
    // ES256 JOSE signature is the raw 64-byte r||s (NOT DER). `to_bytes()` on a
    // p256 Signature yields exactly that fixed-size encoding.
    let sig_b64 = Base64UrlUnpadded::encode_string(signature.to_bytes().as_slice());

    format!("{signing_input}.{sig_b64}")
}

/// Derive the `aud` origin (scheme + authority) from a push endpoint URL.
/// e.g. `https://fcm.googleapis.com/fcm/send/abc` -> `https://fcm.googleapis.com`.
fn audience_origin(endpoint: &str) -> Result<String, DomainError> {
    // Minimal parse: <scheme>://<authority>/<rest>. Reject anything not https.
    let rest = endpoint
        .strip_prefix("https://")
        .ok_or_else(|| DomainError::InvalidInput("push endpoint must be https".into()))?;
    let authority = rest.split('/').next().unwrap_or("");
    if authority.is_empty() {
        return Err(DomainError::InvalidInput(
            "push endpoint missing host".into(),
        ));
    }
    Ok(format!("https://{authority}"))
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// VAPID Web Push adapter. Holds an optional `VapidConfig`: when absent (dev
/// without keys) `notify` degrades gracefully to a no-op.
pub struct VapidWebPushAdapter {
    client: Client,
    vapid: Option<VapidConfig>,
}

impl VapidWebPushAdapter {
    /// Construct with VAPID enabled.
    pub fn new(vapid: VapidConfig) -> Self {
        Self {
            client: Self::build_client(),
            vapid: Some(vapid),
        }
    }

    /// Construct without VAPID keys — `notify` becomes a logged no-op. Useful
    /// for dev/test environments that have no push credentials.
    pub fn disabled() -> Self {
        Self {
            client: Self::build_client(),
            vapid: None,
        }
    }

    fn build_client() -> Client {
        Client::builder()
            .connect_timeout(std::time::Duration::from_secs(PUSH_REQUEST_TIMEOUT_SECS))
            .timeout(std::time::Duration::from_secs(PUSH_REQUEST_TIMEOUT_SECS))
            // Redirects are disabled: a public push service must never redirect
            // the VAPID-signed POST into an internal address (open-redirect SSRF).
            .redirect(reqwest::redirect::Policy::none())
            .build()
            // A misconfigured TLS backend is a startup-time bug, not a runtime
            // condition; fall back to the default client rather than panicking.
            .unwrap_or_else(|_| Client::new())
    }

    /// Build the `Authorization: vapid t=<jwt>,k=<pubkey>` header value.
    fn authorization_header(vapid: &VapidConfig, endpoint: &str) -> Result<String, DomainError> {
        let aud = audience_origin(endpoint)?;
        let jwt = build_vapid_jwt(&vapid.signing_key, &aud, &vapid.contact, now_unix());
        Ok(format!("vapid t={},k={}", jwt, vapid.public_key_b64url()))
    }
}

#[async_trait]
impl WebPushPort for VapidWebPushAdapter {
    async fn notify(&self, sub: &PushSubscription) -> Result<(), DomainError> {
        let Some(vapid) = self.vapid.as_ref() else {
            // Graceful degradation: no keys configured (dev). Do not fail the
            // caller's message flow. Endpoint is never logged.
            tracing::warn!("web push skipped: VAPID not configured");
            return Ok(());
        };

        let auth = Self::authorization_header(vapid, &sub.endpoint)?;

        // Empty body — zero-knowledge. No ECE encryption, no content headers.
        let resp = self
            .client
            .post(&sub.endpoint)
            .header(reqwest::header::AUTHORIZATION, auth)
            .header("TTL", PUSH_TTL_SECS.to_string())
            .header(reqwest::header::CONTENT_LENGTH, "0")
            .body(Vec::<u8>::new())
            .send()
            .await
            .map_err(|_| {
                // No endpoint/error detail logged or surfaced.
                tracing::warn!(error_kind = "transport", "web push send failed");
                DomainError::Internal("web push transport error".into())
            })?;

        let status = resp.status();
        if status.is_success() {
            tracing::info!("push notification sent");
            return Ok(());
        }
        // 410 Gone: subscription expired. Treat as success; cleanup happens
        // separately (the device will re-subscribe). Do not fail the caller.
        if status.as_u16() == 410 {
            tracing::info!(error_kind = "gone", "push subscription expired");
            return Ok(());
        }
        if status.is_client_error() {
            tracing::warn!(error_kind = "client", "web push rejected (4xx)");
            return Err(DomainError::InvalidInput(
                "push service rejected request".into(),
            ));
        }
        // 5xx and anything else: push service problem.
        tracing::warn!(error_kind = "server", "web push service error (5xx)");
        Err(DomainError::Internal("push service error".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::SigningKey;
    use rand_core::OsRng;

    fn test_signing_key() -> SigningKey {
        SigningKey::random(&mut OsRng)
    }

    #[test]
    fn vapid_jwt_is_three_dot_separated() {
        let key = test_signing_key();
        let jwt = build_vapid_jwt(
            &key,
            "https://push.example",
            "mailto:ops@example.com",
            1_000,
        );
        let parts: Vec<&str> = jwt.split('.').collect();
        assert_eq!(parts.len(), 3, "JWT must be header.claims.signature");
        for p in &parts {
            assert!(!p.is_empty(), "no empty JWT segment");
            // base64url-unpadded: no '+', '/', or '=' characters.
            assert!(!p.contains('+') && !p.contains('/') && !p.contains('='));
        }
    }

    #[test]
    fn vapid_jwt_header_decodes_to_es256() {
        let key = test_signing_key();
        let jwt = build_vapid_jwt(
            &key,
            "https://push.example",
            "mailto:ops@example.com",
            1_000,
        );
        let header_b64 = jwt.split('.').next().unwrap();
        let decoded = Base64UrlUnpadded::decode_vec(header_b64).unwrap();
        let header = String::from_utf8(decoded).unwrap();
        assert!(header.contains("\"alg\":\"ES256\""));
        assert!(header.contains("\"typ\":\"JWT\""));
    }

    #[test]
    fn vapid_jwt_claims_contain_aud_exp_sub() {
        let key = test_signing_key();
        let jwt = build_vapid_jwt(
            &key,
            "https://push.example",
            "mailto:ops@example.com",
            1_000,
        );
        let claims_b64 = jwt.split('.').nth(1).unwrap();
        let decoded = Base64UrlUnpadded::decode_vec(claims_b64).unwrap();
        let claims = String::from_utf8(decoded).unwrap();
        assert!(claims.contains("\"aud\":\"https://push.example\""));
        assert!(claims.contains("\"sub\":\"mailto:ops@example.com\""));
        // exp = now (1000) + 12h.
        assert!(claims.contains(&format!("\"exp\":{}", 1_000 + JWT_EXP_SECS)));
    }

    #[test]
    fn audience_origin_strips_path() {
        assert_eq!(
            audience_origin("https://fcm.googleapis.com/fcm/send/abc123").unwrap(),
            "https://fcm.googleapis.com"
        );
    }

    #[test]
    fn audience_origin_rejects_non_https() {
        assert!(matches!(
            audience_origin("http://insecure.example/x"),
            Err(DomainError::InvalidInput(_))
        ));
    }

    #[test]
    fn audience_origin_rejects_missing_host() {
        assert!(matches!(
            audience_origin("https:///nohost"),
            Err(DomainError::InvalidInput(_))
        ));
    }

    #[test]
    fn public_key_is_65_byte_uncompressed_b64url() {
        let cfg = VapidConfig {
            signing_key: test_signing_key(),
            contact: "mailto:ops@example.com".into(),
        };
        let b64 = cfg.public_key_b64url();
        let raw = Base64UrlUnpadded::decode_vec(&b64).unwrap();
        assert_eq!(raw.len(), 65, "uncompressed P-256 point is 65 bytes");
        assert_eq!(raw[0], 0x04, "uncompressed point prefix");
    }

    #[tokio::test]
    async fn disabled_adapter_notify_is_ok_noop() {
        let adapter = VapidWebPushAdapter::disabled();
        let sub = PushSubscription::new(
            powehi_domain::device::DeviceId::new(),
            "https://push.example/abc".into(),
            vec![4u8; 65],
            vec![0u8; 16],
        );
        assert!(adapter.notify(&sub).await.is_ok());
    }

    #[tokio::test]
    async fn push_to_nonexistent_endpoint_returns_error() {
        // Reserved-TEST-NET address that never accepts connections → transport
        // error → DomainError::Internal. Verifies the failure path without a
        // live push service.
        let cfg = VapidConfig {
            signing_key: test_signing_key(),
            contact: "mailto:ops@example.com".into(),
        };
        let adapter = VapidWebPushAdapter::new(cfg);
        let sub = PushSubscription::new(
            powehi_domain::device::DeviceId::new(),
            // Port 1 on loopback: connection is refused immediately (no timeout
            // wait), so the transport-error path is exercised deterministically.
            "https://127.0.0.1:1/push/dead".into(),
            vec![4u8; 65],
            vec![0u8; 16],
        );
        let err = adapter.notify(&sub).await.unwrap_err();
        assert!(matches!(err, DomainError::Internal(_)));
    }
}
