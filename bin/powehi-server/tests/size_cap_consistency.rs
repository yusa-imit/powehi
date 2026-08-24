//! Cross-crate envelope size-cap consistency (threat-model-checker cycle 355
//! follow-up).
//!
//! `powehi-grpc`'s cross-region forwarder deliberately duplicates
//! `powehi-application::messaging_service`'s per-type envelope byte caps
//! instead of depending on `powehi-application` (hexagonal boundary — an
//! inbound adapter must not depend on the application layer of a different
//! ingress path). That duplication has drifted before in this codebase
//! (RED-1, threat-model-checker cycle 353): a stale generic 1 MiB gRPC cap
//! silently outlived a tightened REST-side 96 KiB Application cap, letting a
//! compromised peer region forward oversized envelopes that invalidated
//! `ENVELOPE_POLL_LIMIT`'s documented worst-case per-poll memory bound
//! (`envelope_repo.rs`). `bin/powehi-server` is the only crate in the
//! workspace that already depends on both sides, so this lives here rather
//! than in either adapter crate.

// Compile-time assertions (security-auditor cycle 357): stronger than the
// runtime tests below since these fail `cargo build`/`cargo check` itself,
// not just a test run someone might skip or filter out.
const _: () = assert!(
    powehi_application::messaging_service::MAX_CIPHERTEXT_BYTES
        == powehi_grpc::server::MAX_APPLICATION_CIPHERTEXT_BYTES
);
const _: () = assert!(
    powehi_application::messaging_service::MAX_COMMIT_BYTES
        == powehi_grpc::server::MAX_COMMIT_BYTES
);
const _: () = assert!(
    powehi_application::messaging_service::MAX_WELCOME_BYTES
        == powehi_grpc::server::MAX_WELCOME_BYTES
);

#[test]
fn application_ciphertext_cap_matches_grpc_forwarder_cap() {
    assert_eq!(
        powehi_application::messaging_service::MAX_CIPHERTEXT_BYTES,
        powehi_grpc::server::MAX_APPLICATION_CIPHERTEXT_BYTES,
        "REST-side Application ciphertext cap drifted from the gRPC cross-region \
         forwarder's cap — a peer region could forward oversized envelopes that \
         the REST ingress path would reject, invalidating ENVELOPE_POLL_LIMIT's \
         documented worst-case per-poll memory bound",
    );
}

#[test]
fn commit_cap_matches_grpc_forwarder_cap() {
    assert_eq!(
        powehi_application::messaging_service::MAX_COMMIT_BYTES,
        powehi_grpc::server::MAX_COMMIT_BYTES,
        "REST-side Commit cap drifted from the gRPC cross-region forwarder's cap",
    );
}

#[test]
fn welcome_cap_matches_grpc_forwarder_cap() {
    assert_eq!(
        powehi_application::messaging_service::MAX_WELCOME_BYTES,
        powehi_grpc::server::MAX_WELCOME_BYTES,
        "REST-side Welcome cap drifted from the gRPC cross-region forwarder's cap",
    );
}
