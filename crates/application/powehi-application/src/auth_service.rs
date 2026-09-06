use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use ed25519_dalek::{Signature, VerifyingKey};
use hmac::{Hmac, Mac};
use powehi_domain::{
    device::{Device, DeviceId},
    error::DomainError,
    event::DomainEvent,
    user::{User, UserId},
};
use powehi_port_inbound::auth::{
    AuthUseCase, DeviceInfo, DeviceRegistrationRequest, LoginFinishRequest, LoginInitRequest,
    LoginInitResponse, RecoveryProof, RegistrationFinishRequest, RegistrationFinishResponse,
    RegistrationInitRequest, RegistrationInitResponse, SessionToken,
};
use powehi_port_inbound::invite::InviteUseCase;
use powehi_port_outbound::{
    cache::CachePort, device_repo::DeviceRepository, event_bus::DomainEventBus,
    group_repo::GroupRepository, key_package_repo::KeyPackageRepository, opaque::OpaqueServerPort,
    user_repo::UserRepository,
};
use sha2::Sha256;
use tracing::instrument;
use uuid::Uuid;

type HmacSha256 = Hmac<Sha256>;

const REG_TTL: Duration = Duration::from_secs(300);
const LOGIN_NONCE_TTL: Duration = Duration::from_secs(300);
const SESSION_TTL: Duration = Duration::from_secs(86_400);
/// Buffer added to `device_sessions` set TTL so it outlives any session it tracks.
const DEVICE_SESSIONS_TTL: Duration = Duration::from_secs(86_400 + 300);
/// Maximum number of devices a single user account may register. Prevents
/// unbounded device proliferation and limits per-user KeyPackage storage.
const MAX_DEVICES_PER_USER: usize = 10;
/// A real MLS `BasicCredential` identity is a small opaque label (well under
/// 1KB); this bounds the amount of `devices.mls_credential` bytea storage an
/// authenticated (or, via §8.5 recovery, freshly-authenticated) caller can
/// persist per device row — mirrors the `MAX_KEY_PACKAGE_BYTES` cap already
/// applied to invite KeyPackages (security-auditor finding, cycle 304 YELLOW #3,
/// prd.md §8.3/§8.5).
const MAX_MLS_CREDENTIAL_BYTES: usize = 4 * 1024;

/// A fixed, valid Ed25519 public key with NO known corresponding private key
/// (SHA-256("powehi-dummy-recovery-verify-key-v1-not-a-real-account") fed
/// through `SigningKey::from_bytes(..).verifying_key()`; the private key was
/// discarded immediately after generation and is not reconstructible from
/// this public value alone). Used ONLY as the `verify_strict` target in
/// `AuthService::mint_recovery_device` when the account has no enrolled
/// `recovery_pubkey`, so an unenrolled account's §8.5 restore rejection takes
/// the identical code path / timing profile as an enrolled account's
/// bad-signature rejection — no real client-produced signature can ever
/// verify against it (security-auditor finding, cycle 304).
const DUMMY_RECOVERY_PUBKEY: [u8; 32] = [
    33, 150, 102, 62, 33, 168, 147, 22, 120, 201, 204, 46, 173, 129, 169, 11, 255, 63, 89, 124, 54,
    94, 148, 112, 45, 146, 223, 9, 71, 83, 41, 194,
];

pub struct AuthService {
    user_repo: Arc<dyn UserRepository>,
    device_repo: Arc<dyn DeviceRepository>,
    key_package_repo: Arc<dyn KeyPackageRepository>,
    group_repo: Arc<dyn GroupRepository>,
    opaque: Arc<dyn OpaqueServerPort>,
    cache: Arc<dyn CachePort>,
    event_bus: Arc<dyn DomainEventBus>,
    /// The inbound port `revoke_device` calls to delete a revoked device's
    /// outstanding invite codes. Each invite pins its own copy of that
    /// device's KeyPackage bytes in Redis, outside the KeyPackage pool.
    invite: Arc<dyn InviteUseCase>,
    /// Server-side secret for HMAC-SHA256 synthetic user_id derivation.
    /// Prevents handle-existence timing oracle: unknown handles always map to the
    /// same deterministic UUID (per secret), indistinguishable from known handles.
    handle_oracle_secret: [u8; 32],
}

impl AuthService {
    // Nine collaborators, all of them ports this service genuinely needs:
    // the four repositories/stores it reads and writes (user, device,
    // key-package, group), the OPAQUE verifier, the session cache, the
    // event bus it publishes revocation signals on, the invite use case
    // whose outstanding invite codes `revoke_device` must delete (each pins
    // its own copy of a device's KeyPackage bytes in Redis, outside the
    // KeyPackage pool), and the handle-oracle secret. Bundling them into a
    // params struct would add a type whose only purpose is to satisfy the
    // lint, and this is a composition-root-only constructor called from
    // exactly one production site.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        user_repo: Arc<dyn UserRepository>,
        device_repo: Arc<dyn DeviceRepository>,
        key_package_repo: Arc<dyn KeyPackageRepository>,
        group_repo: Arc<dyn GroupRepository>,
        opaque: Arc<dyn OpaqueServerPort>,
        cache: Arc<dyn CachePort>,
        event_bus: Arc<dyn DomainEventBus>,
        invite: Arc<dyn InviteUseCase>,
        handle_oracle_secret: [u8; 32],
    ) -> Self {
        Self {
            user_repo,
            device_repo,
            key_package_repo,
            group_repo,
            opaque,
            cache,
            event_bus,
            invite,
            handle_oracle_secret,
        }
    }

    /// Derives a deterministic UserId from `handle_hash` using HMAC-SHA256 keyed
    /// with `handle_oracle_secret`. The result is stable across calls within a
    /// server lifetime (or across restarts when the secret is persisted in config),
    /// closing the handle-enumeration oracle in `login_init`.
    fn synthetic_user_id(&self, handle_hash: &[u8]) -> UserId {
        let mut mac = HmacSha256::new_from_slice(&self.handle_oracle_secret)
            .expect("HMAC accepts any key size");
        mac.update(handle_hash);
        let digest: [u8; 32] = mac.finalize().into_bytes().into();
        // Interpret first 16 bytes as a UUID v4 (version + variant bits set per RFC 4122).
        let mut id_bytes = [0u8; 16];
        id_bytes.copy_from_slice(&digest[..16]);
        id_bytes[6] = (id_bytes[6] & 0x0f) | 0x40; // version 4
        id_bytes[8] = (id_bytes[8] & 0x3f) | 0x80; // RFC 4122 variant
        UserId::from(Uuid::from_bytes(id_bytes))
    }

    /// §8.5 recovery-phrase device mint. Called from `login_finish` ONLY after
    /// OPAQUE verification + nonce consumption have already authenticated the user,
    /// and ONLY when the presented `device_id` does not yet exist. Verifies the
    /// recovery-phrase Ed25519 signature over the login nonce against the user's
    /// stored `recovery_pubkey`; on success mints and persists a new Device.
    ///
    /// Every failure mode collapses to `DomainError::Unauthorized` to avoid an
    /// account-state oracle on this pre-session path: no distinguishable error for
    /// "account not enrolled in recovery", "malformed key/sig", "bad signature", or
    /// "device cap reached" — all indistinguishable to an unauthenticated caller.
    async fn mint_recovery_device(
        &self,
        authenticated_user_id: &UserId,
        req: &LoginFinishRequest,
        proof: &RecoveryProof,
    ) -> Result<Device, DomainError> {
        // Load the user. Absent → fail closed (no distinguishing oracle).
        let user = self
            .user_repo
            .find_by_id(authenticated_user_id)
            .await?
            .ok_or(DomainError::Unauthorized)?;
        // Never enrolled / opted out → still run the SAME verify_strict call below
        // (against a fixed dummy key that no real signature can satisfy) rather
        // than returning early, so an unenrolled account's rejection takes the
        // same code path / timing profile as an enrolled account's bad-signature
        // rejection (security-auditor finding, cycle 303/304: an early return here
        // is a timing oracle for recovery-enrollment status, observable only to a
        // caller who already passed OPAQUE — low severity, but cheap to close).
        let is_enrolled = user.recovery_pubkey.is_some();
        let pubkey = user
            .recovery_pubkey
            .unwrap_or_else(|| DUMMY_RECOVERY_PUBKEY.to_vec());

        // Reconstruct the EXACT signed message the client produced (must match the
        // WASM crate byte-for-byte):
        //   b"powehi-recovery-challenge-v1" || 0x00 || login_nonce.as_bytes()
        let mut message = Vec::new();
        message.extend_from_slice(b"powehi-recovery-challenge-v1");
        message.push(0u8);
        message.extend_from_slice(req.login_nonce.as_bytes());

        // Collapse malformed-pubkey / malformed-signature / verify-failure all to
        // the same Unauthorized (matches this fn's OPAQUE error convention).
        let vk_bytes: [u8; 32] = pubkey
            .as_slice()
            .try_into()
            .map_err(|_| DomainError::Unauthorized)?;
        let verifying_key =
            VerifyingKey::from_bytes(&vk_bytes).map_err(|_| DomainError::Unauthorized)?;
        let sig_bytes: [u8; 64] = proof
            .signature
            .as_slice()
            .try_into()
            .map_err(|_| DomainError::Unauthorized)?;
        let signature = Signature::from_bytes(&sig_bytes);
        // verify_strict (not verify): rejects non-canonical/cofactored signature
        // encodings per RFC 8032, the recommended default for a security-critical
        // account-recovery gate (crypto-reviewer finding, cycle 303).
        let verify_result = verifying_key.verify_strict(&message, &signature);
        if !is_enrolled || verify_result.is_err() {
            return Err(DomainError::Unauthorized);
        }

        // Enforce the SAME per-user device cap as register_device. Collapse an
        // exceeded cap to Unauthorized (NOT a distinguishable device_limit_exceeded):
        // this path is reachable pre-session, so a distinct error would leak
        // account-state to an unauthenticated caller.
        let existing = self.device_repo.find_by_user(authenticated_user_id).await?;
        if existing.len() >= MAX_DEVICES_PER_USER {
            return Err(DomainError::Unauthorized);
        }
        // Same anti-oracle collapse as every other check in this fn: an oversized
        // credential fails closed as Unauthorized, not a distinguishable error.
        if proof.mls_credential.len() > MAX_MLS_CREDENTIAL_BYTES {
            return Err(DomainError::Unauthorized);
        }

        let device = Device::new(
            req.device_id.clone(),
            authenticated_user_id.clone(),
            proof.mls_credential.clone(),
        );
        self.device_repo.save(&device).await?;
        Ok(device)
    }
}

#[async_trait]
impl AuthUseCase for AuthService {
    #[instrument(skip(self, req), fields(handle_hash_len = req.handle_hash.len()))]
    async fn register_init(
        &self,
        req: RegistrationInitRequest,
    ) -> Result<RegistrationInitResponse, DomainError> {
        let user_id = UserId::new();
        let ke2 = self
            .opaque
            .registration_start(&req.opaque_request, user_id.as_uuid().as_bytes())?;
        let cache_key = format!("reg:{}", user_id.as_uuid());
        self.cache
            .set(&cache_key, req.handle_hash, Some(REG_TTL))
            .await?;
        Ok(RegistrationInitResponse {
            user_id,
            opaque_response: ke2,
        })
    }

    #[instrument(skip(self, req), fields(user_id = %req.user_id))]
    async fn register_finish(
        &self,
        req: RegistrationFinishRequest,
    ) -> Result<RegistrationFinishResponse, DomainError> {
        let password_file = self.opaque.registration_finish(&req.opaque_record)?;
        let cache_key = format!("reg:{}", req.user_id.as_uuid());
        // Atomically consume the registration session — prevents concurrent-finish
        // races and nonce replay within the TTL window (audit finding sec-F1).
        let handle_hash = self
            .cache
            .get_del(&cache_key)
            .await?
            .ok_or_else(|| DomainError::NotFound("registration session".into()))?;

        // Reject a malformed recovery_pubkey at enrollment time rather than only
        // failing closed later at restore (security-auditor finding, cycle 303) —
        // a raw Ed25519 verifying key is always exactly 32 bytes.
        if let Some(pk) = &req.recovery_pubkey {
            if pk.len() != 32 {
                return Err(DomainError::InvalidInput(
                    "invalid recovery_pubkey length".into(),
                ));
            }
        }
        if req.mls_credential.len() > MAX_MLS_CREDENTIAL_BYTES {
            return Err(DomainError::InvalidInput("mls_credential too large".into()));
        }

        let mut user = User::registered(req.user_id.clone(), handle_hash, password_file);
        // Enroll the account in §8.5 phrase-based recovery when the client supplied a
        // recovery_pubkey. Absent → user opts out and cannot use the restore path.
        user.recovery_pubkey = req.recovery_pubkey.clone();
        self.user_repo.save(&user).await?;

        // Create the first device for this user. The client supplies its MLS
        // credential bytes (raw BasicCredential identity). The server assigns a
        // fresh DeviceId so the client can present it in subsequent LoginFinishRequests.
        let device_id = DeviceId::new();
        let device = Device::new(device_id.clone(), req.user_id.clone(), req.mls_credential);
        self.device_repo.save(&device).await?;

        Ok(RegistrationFinishResponse {
            user_id: req.user_id,
            device_id,
        })
    }

    #[instrument(skip(self, req), fields(handle_hash_len = req.handle_hash.len()))]
    async fn login_init(&self, req: LoginInitRequest) -> Result<LoginInitResponse, DomainError> {
        // Look up user; for unknown handles use a synthetic identity so we
        // still call login_start(None) → synthetic KE2 (R-3: anti-oracle).
        let (user_id, password_file_opt) =
            match self.user_repo.find_by_handle_hash(&req.handle_hash).await? {
                Some(user) => (user.id, Some(user.opaque_password_file)),
                // Deterministic synthetic path: same handle_hash always yields the same
                // UserId so consecutive login_init calls for an unknown handle are
                // indistinguishable from known-handle calls (closes handle-oracle).
                None => (self.synthetic_user_id(&req.handle_hash), None),
            };

        let identity = user_id.as_uuid().as_bytes().to_vec();
        let login_nonce = Uuid::new_v4().to_string();

        let ke2 = self.opaque.login_start(
            password_file_opt.as_deref(),
            &req.opaque_ke1,
            &identity,
            login_nonce.as_bytes(),
        )?;

        // Cache nonce → user_id so login_finish can look up the authenticated user
        // without trusting the client-supplied req.user_id.
        let nonce_key = format!("login_nonce:{}", login_nonce);
        self.cache
            .set(
                &nonce_key,
                user_id.as_uuid().as_bytes().to_vec(),
                Some(LOGIN_NONCE_TTL),
            )
            .await?;

        Ok(LoginInitResponse {
            user_id,
            opaque_ke2: ke2,
            login_nonce,
        })
    }

    // device_id not logged before ownership verification — added after (Y-4).
    // §8.5: when device_id is unknown AND req.recovery_proof is present, this fn
    // mints a NEW device via proof-of-recovery-phrase (see mint_recovery_device)
    // instead of rejecting — a distinct authentication path from a live session.
    #[instrument(skip(self, req))]
    async fn login_finish(&self, req: LoginFinishRequest) -> Result<SessionToken, DomainError> {
        // Collapse all OPAQUE errors to Unauthorized (no error oracle).
        self.opaque
            .login_finish(req.login_nonce.as_bytes(), &req.opaque_ke3)
            .map_err(|_| DomainError::Unauthorized)?;

        // Atomically consume the nonce — GETDEL prevents replay within the same
        // TTL window (Y-3: no TOCTOU between get and delete).
        let nonce_key = format!("login_nonce:{}", req.login_nonce);
        let user_id_bytes = self
            .cache
            .get_del(&nonce_key)
            .await
            .map_err(|_| DomainError::Unauthorized)?
            .ok_or(DomainError::Unauthorized)?;
        let user_uuid = Uuid::from_slice(&user_id_bytes).map_err(|_| DomainError::Unauthorized)?;
        let authenticated_user_id = UserId::from(user_uuid);

        // Verify the claimed device belongs to the authenticated user.
        // Log device_id only after this ownership check passes (Y-4).
        let device = match self.device_repo.find_by_id(&req.device_id).await? {
            Some(device) => device,
            // Unknown device_id. Normal case → reject (unknown/foreign device). §8.5
            // exception: a lost-everything restore carries a recovery-phrase proof and
            // has no existing device yet, so mint device_id as a brand-new device iff
            // the phrase signature verifies. `recovery_proof: None` stays a hard reject
            // (no regression of the existing unknown-device rejection path).
            None => match &req.recovery_proof {
                None => return Err(DomainError::Unauthorized),
                Some(proof) => {
                    self.mint_recovery_device(&authenticated_user_id, &req, proof)
                        .await?
                }
            },
        };
        if device.user_id != authenticated_user_id {
            return Err(DomainError::Unauthorized);
        }
        tracing::debug!(device_id = %req.device_id, "login_finish.device_verified");

        // Session maps token → DeviceId. All protected routes need DeviceId;
        // storing it here avoids a DB lookup per request.
        let token = Uuid::new_v4().to_string();
        let session_cache_key = format!("session:{}", token);
        self.cache
            .set(
                &session_cache_key,
                req.device_id.as_uuid().as_bytes().to_vec(),
                Some(SESSION_TTL),
            )
            .await
            .map_err(|_| DomainError::Unauthorized)?;

        // Track token in per-device set so revoke_device can invalidate it (Y-1).
        // Fail hard — a tracking failure leaves an unrevocable orphan session.
        // On error: delete the session we already wrote before returning Unauthorized.
        let device_sessions_key = format!("device_sessions:{}", req.device_id.as_uuid());
        if self
            .cache
            .set_add(&device_sessions_key, &token)
            .await
            .is_err()
        {
            // Best-effort cleanup: token is never returned to client so the
            // orphan session cannot be used, but log to surface cache partitions.
            if self.cache.delete(&session_cache_key).await.is_err() {
                tracing::warn!(
                    "login_finish: set_add failed and cleanup delete also failed — \
                     orphan session may persist until SESSION_TTL expires"
                );
            }
            return Err(DomainError::Unauthorized);
        }
        let _ = self
            .cache
            .set_expire(&device_sessions_key, DEVICE_SESSIONS_TTL)
            .await;

        // Re-verify device still exists after session write (R-1: closes the
        // revoke↔login_finish race — if revoke_device deleted the device between
        // our first ownership check and here, we detect it and clean up).
        if self.device_repo.find_by_id(&req.device_id).await?.is_none() {
            if self.cache.delete(&session_cache_key).await.is_err() {
                tracing::warn!(
                    "login_finish: revoked-device race and cleanup delete failed — \
                     orphan session may persist until SESSION_TTL expires"
                );
            }
            let _ = self.cache.delete(&device_sessions_key).await;
            return Err(DomainError::Unauthorized);
        }

        Ok(SessionToken(token))
    }

    #[instrument(skip(self, user_id, req))]
    async fn register_device(
        &self,
        user_id: &UserId,
        req: DeviceRegistrationRequest,
    ) -> Result<DeviceId, DomainError> {
        // Soft cap: count-then-insert is not wrapped in a serializable
        // transaction, so a race between two concurrent registrations could
        // temporarily exceed MAX_DEVICES_PER_USER by one. This is acceptable
        // at the application layer — a hard DB-level invariant would require a
        // serializable transaction in the outbound adapter (future hardening).
        // Practical risk is very low: registration requires an active session
        // and is governed by auth_governor (burst=8, 1 token/6s).
        let existing = self.device_repo.find_by_user(user_id).await?;
        if existing.len() >= MAX_DEVICES_PER_USER {
            return Err(DomainError::InvalidInput("device_limit_exceeded".into()));
        }
        if req.mls_credential.len() > MAX_MLS_CREDENTIAL_BYTES {
            return Err(DomainError::InvalidInput("mls_credential too large".into()));
        }
        let device_id = DeviceId::new();
        let device = Device::new(device_id.clone(), user_id.clone(), req.mls_credential);
        self.device_repo.save(&device).await?;
        Ok(device_id)
    }

    #[instrument(skip(self, user_id))]
    async fn list_devices(&self, user_id: &UserId) -> Result<Vec<DeviceInfo>, DomainError> {
        let devices = self.device_repo.find_by_user(user_id).await?;
        Ok(devices
            .into_iter()
            .map(|d| DeviceInfo {
                device_id: d.id,
                created_at: d.created_at,
                last_seen_at: d.last_seen_at,
            })
            .collect())
    }

    #[instrument(skip(self, user_id, device_id))]
    async fn revoke_device(
        &self,
        user_id: &UserId,
        device_id: &DeviceId,
    ) -> Result<(), DomainError> {
        let device = self
            .device_repo
            .find_by_id(device_id)
            .await?
            .ok_or_else(|| DomainError::NotFound("device".into()))?;
        if &device.user_id != user_id {
            return Err(DomainError::Unauthorized);
        }
        // Delete this device's outstanding invite codes BEFORE anything
        // irreversible. An invite pins a copy of this device's KeyPackage
        // bytes directly in Redis with its own 24h TTL, entirely outside the
        // shared KeyPackage pool `delete_by_device` cleans up below — so
        // deleting the pool row alone does not stop an already-issued invite
        // code from handing out the revoked credential.
        //
        // This step lives here — hard-fail (`?`), before anything
        // irreversible — for exactly the reason `delete_by_device` runs
        // before `device_repo.delete`: `revoke_invites_for_device` is
        // documented idempotent (a device with zero outstanding invites is
        // `Ok(())`), so a failure here leaves the device row fully intact
        // and the whole revocation safely retryable. It must NOT sit
        // downstream of the session invalidation at the end of this
        // function, which hard-fails on a cache outage AFTER the device row
        // is already gone — a Redis blip there would then permanently skip
        // invite cleanup, since a retry can only hit NotFound. (This is the
        // ordering discipline this function already follows: idempotent
        // hard-fail steps first, then irreversible deletes, then the
        // best-effort notification fan-out, then the final hard-fail
        // session invalidation.)
        self.invite.revoke_invites_for_device(device_id).await?;
        // Capture the device's group memberships BEFORE deleting it.
        // `group_members.device_id` is `ON DELETE CASCADE` to `devices(id)`
        // (migration 0001), so once `device_repo.delete` runs the server has
        // permanently lost its own record of which groups this device was in
        // — and with it the ability to tell those groups' remaining members
        // that they still owe an MLS Remove for the revoked leaf.
        //
        // Hard-fail (`?`) rather than log-and-continue: this read happens
        // before anything irreversible, so a failure leaves the device fully
        // intact and a client retry safely re-runs the whole revocation.
        // The per-group writes AFTER the delete take the opposite posture,
        // for the opposite reason — see below.
        let affected_groups = self.group_repo.list_groups_for_device(device_id).await?;
        // Record the durable backstop BEFORE anything irreversible. This
        // write is idempotent (`ON CONFLICT (group_id, device_id) DO
        // NOTHING`, see migration 0020) and `pending_removals.device_id` has
        // no FK to `devices(id)` by design, so it does not depend on the
        // device row still existing. Hard-fail (`?`) for the same reason as
        // `revoke_invites_for_device`/`list_groups_for_device` above: if this
        // write fails, the device row is still present and the whole
        // revocation is safely retryable. Writing it AFTER the irreversible
        // deletes below (as an earlier draft of this function did) traded a
        // recoverable failure (retry) for an unrecoverable one (a DB blip
        // here would permanently drop the one signal that a revoked leaf
        // still needs removing from the group, with no way to reconstruct it
        // since `find_by_id` on the already-deleted device returns
        // `NotFound` on any retry).
        //
        // NOTE ON WHAT THIS ROW PROVES: `delete_pending_removal`'s epoch gate
        // (see `GroupRepository::delete_pending_removal`) only proves that
        // *some* Commit landed after this row was written — the server
        // cannot see Commit contents (RFC 9420 §6, §12.4) and so cannot tell
        // an unrelated Update/Add Commit from the actual Remove this row is
        // asking for. This table is a best-effort heuristic reminder and
        // discovery channel for clients, not a cryptographic guarantee that
        // the Remove happened; the only party that can actually verify a
        // leaf was removed is a client reconciling its own ratchet tree.
        for group_id in &affected_groups {
            self.group_repo
                .create_pending_removal(group_id, device_id)
                .await?;
        }
        // Delete every KeyPackage (consumed or not) belonging to the device
        // BEFORE deleting the device row itself. Without this cleanup, a
        // stale unconsumed KeyPackage could still be handed out via
        // fetch_one/gRPC ConsumeKeyPackage after revocation, letting a group
        // add a credential for a device that no longer exists. Hard-fail
        // like the session invalidation below: silently succeeding here
        // would leave a usable stale credential behind.
        //
        // Order matters: both calls are idempotent (delete_by_device on a
        // device with zero KeyPackages returns Ok(0); device_repo.delete on
        // an unknown id is a no-op), so if this call fails the device row is
        // still present and a client retry safely completes the whole
        // revocation. Deleting the device row first would do the opposite:
        // a failure there would leave the device unrevocable (find_by_id
        // returns NotFound on retry) while its stale KeyPackages survive
        // forever — exactly the state this cleanup exists to prevent.
        self.key_package_repo.delete_by_device(device_id).await?;
        self.device_repo.delete(device_id).await?;

        // Publish the live signal for each affected group. This is purely a
        // latency optimization on top of the durable row already written
        // above — a connected member acting on it now is strictly better
        // than waiting to poll `GET .../pending-removals`, but the durable
        // row is what actually survives if this publish is lost. Log-and-
        // continue, never fail the revocation: by this point the device row
        // and its KeyPackages are already gone and that deletion is
        // irreversible, so returning Err here would report a completed
        // revocation as failed and invite a retry that can only hit
        // NotFound.
        for group_id in &affected_groups {
            if self
                .event_bus
                .publish(DomainEvent::RemovalRequired {
                    group_id: group_id.clone(),
                    device_id: device_id.clone(),
                    at: chrono::Utc::now(),
                })
                .await
                .is_err()
            {
                tracing::warn!(
                    group_id = %group_id,
                    error_kind = "event_bus_error",
                    "revoke_device: failed to publish removal-required signal"
                );
            }
        }

        // Immediately invalidate all active sessions for the revoked device (Y-1).
        // Propagate set_members error — silently succeeding on cache failure
        // would leave live session tokens for a revoked device (Y-5). This
        // remains a hard-fail security control: it still runs after the
        // fan-out above (not skipped, not weakened) and still returns `Err`
        // from `revoke_device` on cache failure, same as before the fan-out
        // was moved ahead of it.
        let device_sessions_key = format!("device_sessions:{}", device_id.as_uuid());
        let tokens = self.cache.set_members(&device_sessions_key).await?;
        for token in &tokens {
            if self
                .cache
                .delete(&format!("session:{token}"))
                .await
                .is_err()
            {
                // Best-effort: continue revoking other tokens but surface the
                // cache failure so ops can detect a partially-revoked device.
                tracing::warn!(
                    "revoke_device: failed to delete session token — \
                     token may persist until SESSION_TTL expires"
                );
            }
        }
        let _ = self.cache.delete(&device_sessions_key).await;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use powehi_domain::{
        group::{Epoch, Group, GroupId, GroupMember},
        key_package::{ConsumeResult, KeyPackage, KeyPackageId},
    };
    use powehi_port_inbound::invite::{CreatedInvite, InviteUseCase, RedeemedInvite};
    use powehi_port_outbound::{
        cache::CachePort,
        device_repo::DeviceRepository,
        event_bus::{DomainEventBus, EventStream},
        group_repo::GroupRepository,
        key_package_repo::KeyPackageRepository,
        opaque::OpaqueServerPort,
        user_repo::UserRepository,
    };
    use std::collections::HashMap;
    use std::sync::Mutex;

    // ── fake repos ──────────────────────────────────────────────────────────

    struct FakeUserRepo {
        store: Mutex<HashMap<UserId, User>>,
    }
    impl FakeUserRepo {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                store: Mutex::new(HashMap::new()),
            })
        }
    }
    #[async_trait::async_trait]
    impl UserRepository for FakeUserRepo {
        async fn save(&self, user: &User) -> Result<(), DomainError> {
            self.store
                .lock()
                .unwrap()
                .insert(user.id.clone(), user.clone());
            Ok(())
        }
        async fn find_by_id(&self, id: &UserId) -> Result<Option<User>, DomainError> {
            Ok(self.store.lock().unwrap().get(id).cloned())
        }
        async fn find_by_handle_hash(&self, hash: &[u8]) -> Result<Option<User>, DomainError> {
            Ok(self
                .store
                .lock()
                .unwrap()
                .values()
                .find(|u| u.handle_hash == hash)
                .cloned())
        }
    }

    struct FakeDeviceRepo {
        store: Mutex<HashMap<DeviceId, Device>>,
        /// Simulates the real `group_members.device_id` `ON DELETE CASCADE`
        /// (migration 0001): when set, `delete` also purges this device's rows
        /// from the wired `FakeGroupRepo`, so a test can prove `revoke_device`
        /// captures group membership BEFORE calling `device_repo.delete`.
        cascade_group_repo: Option<Arc<FakeGroupRepo>>,
    }
    impl FakeDeviceRepo {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                store: Mutex::new(HashMap::new()),
                cascade_group_repo: None,
            })
        }
        fn with_cascade(group_repo: Arc<FakeGroupRepo>) -> Arc<Self> {
            Arc::new(Self {
                store: Mutex::new(HashMap::new()),
                cascade_group_repo: Some(group_repo),
            })
        }
    }
    #[async_trait::async_trait]
    impl DeviceRepository for FakeDeviceRepo {
        async fn save(&self, device: &Device) -> Result<(), DomainError> {
            self.store
                .lock()
                .unwrap()
                .insert(device.id.clone(), device.clone());
            Ok(())
        }
        async fn find_by_id(&self, id: &DeviceId) -> Result<Option<Device>, DomainError> {
            Ok(self.store.lock().unwrap().get(id).cloned())
        }
        async fn find_by_user(&self, user_id: &UserId) -> Result<Vec<Device>, DomainError> {
            Ok(self
                .store
                .lock()
                .unwrap()
                .values()
                .filter(|d| &d.user_id == user_id)
                .cloned()
                .collect())
        }
        async fn delete(&self, id: &DeviceId) -> Result<(), DomainError> {
            self.store.lock().unwrap().remove(id);
            if let Some(group_repo) = &self.cascade_group_repo {
                group_repo.cascade_delete_device(id);
            }
            Ok(())
        }
    }

    struct FakeKeyPackageRepo {
        store: Mutex<HashMap<KeyPackageId, KeyPackage>>,
    }
    impl FakeKeyPackageRepo {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                store: Mutex::new(HashMap::new()),
            })
        }
    }
    #[async_trait::async_trait]
    impl KeyPackageRepository for FakeKeyPackageRepo {
        async fn save(&self, kp: &KeyPackage) -> Result<(), DomainError> {
            self.store.lock().unwrap().insert(kp.id.clone(), kp.clone());
            Ok(())
        }
        async fn fetch_one(&self, device_id: &DeviceId) -> Result<Option<KeyPackage>, DomainError> {
            let mut store = self.store.lock().unwrap();
            let key = store
                .values()
                .find(|kp| &kp.device_id == device_id && !kp.consumed)
                .map(|kp| kp.id.clone());
            Ok(key.map(|k| {
                let kp = store.get_mut(&k).unwrap();
                kp.consumed = true;
                kp.clone()
            }))
        }
        async fn count_available(&self, device_id: &DeviceId) -> Result<u64, DomainError> {
            Ok(self
                .store
                .lock()
                .unwrap()
                .values()
                .filter(|kp| &kp.device_id == device_id && !kp.consumed)
                .count() as u64)
        }
        async fn delete(&self, id: &KeyPackageId) -> Result<(), DomainError> {
            self.store.lock().unwrap().remove(id);
            Ok(())
        }
        async fn mark_consumed(&self, id: &KeyPackageId) -> Result<ConsumeResult, DomainError> {
            let mut store = self.store.lock().unwrap();
            match store.get_mut(id) {
                Some(kp) if kp.consumed => Ok(ConsumeResult::AlreadyConsumed),
                Some(kp) => {
                    kp.consumed = true;
                    Ok(ConsumeResult::Consumed)
                }
                None => Ok(ConsumeResult::NotFound),
            }
        }
        async fn delete_by_device(&self, device_id: &DeviceId) -> Result<u64, DomainError> {
            let mut store = self.store.lock().unwrap();
            let before = store.len();
            store.retain(|_, kp| &kp.device_id != device_id);
            Ok((before - store.len()) as u64)
        }
    }

    /// A `KeyPackageRepository` whose `delete_by_device` always fails.
    /// Used to test that `revoke_device` propagates the error and leaves the
    /// device row retryable rather than committing a partial revocation.
    struct FailingDeleteByDeviceKeyPackageRepo;
    #[async_trait::async_trait]
    impl KeyPackageRepository for FailingDeleteByDeviceKeyPackageRepo {
        async fn save(&self, _kp: &KeyPackage) -> Result<(), DomainError> {
            Ok(())
        }
        async fn fetch_one(
            &self,
            _device_id: &DeviceId,
        ) -> Result<Option<KeyPackage>, DomainError> {
            Ok(None)
        }
        async fn count_available(&self, _device_id: &DeviceId) -> Result<u64, DomainError> {
            Ok(0)
        }
        async fn delete(&self, _id: &KeyPackageId) -> Result<(), DomainError> {
            Ok(())
        }
        async fn mark_consumed(&self, _id: &KeyPackageId) -> Result<ConsumeResult, DomainError> {
            Ok(ConsumeResult::NotFound)
        }
        async fn delete_by_device(&self, _device_id: &DeviceId) -> Result<u64, DomainError> {
            Err(DomainError::Internal(
                "injected delete_by_device failure".into(),
            ))
        }
    }

    // ── fake group repo (revoke_device fan-out) ──────────────────────────────

    struct FakeGroupRepo {
        members: Mutex<Vec<GroupMember>>,
        pending: Mutex<Vec<(GroupId, DeviceId)>>,
    }
    impl FakeGroupRepo {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                members: Mutex::new(vec![]),
                pending: Mutex::new(vec![]),
            })
        }
        fn with_memberships(pairs: Vec<(GroupId, DeviceId)>) -> Arc<Self> {
            let members = pairs
                .into_iter()
                .map(|(group_id, device_id)| GroupMember {
                    group_id,
                    device_id,
                    joined_at_epoch: Epoch(0),
                })
                .collect();
            Arc::new(Self {
                members: Mutex::new(members),
                pending: Mutex::new(vec![]),
            })
        }
        /// Test-only hook simulating `group_members.device_id`'s real
        /// `ON DELETE CASCADE` to `devices(id)`: drains every membership row
        /// for `device_id`, as Postgres would the instant `device_repo.delete`
        /// runs. Wired via `FakeDeviceRepo::with_cascade`.
        fn cascade_delete_device(&self, device_id: &DeviceId) {
            self.members
                .lock()
                .unwrap()
                .retain(|m| &m.device_id != device_id);
        }
    }
    #[async_trait::async_trait]
    impl GroupRepository for FakeGroupRepo {
        async fn save(&self, _group: &Group) -> Result<(), DomainError> {
            unimplemented!("auth_service tests never save a group")
        }
        async fn advance_epoch(
            &self,
            _group_id: &GroupId,
            _expected: Epoch,
        ) -> Result<Option<Epoch>, DomainError> {
            unimplemented!("auth_service tests never advance a group epoch")
        }
        async fn create_if_absent(&self, _group: &Group) -> Result<bool, DomainError> {
            unimplemented!("auth_service tests never create a group")
        }
        async fn create_with_creator(
            &self,
            _group: &Group,
            _creator: &GroupMember,
        ) -> Result<bool, DomainError> {
            unimplemented!("auth_service tests never create a group")
        }
        async fn find_by_id(&self, _id: &GroupId) -> Result<Option<Group>, DomainError> {
            unimplemented!("auth_service tests never look up a group entity")
        }
        async fn add_member(&self, _member: &GroupMember) -> Result<(), DomainError> {
            unimplemented!("auth_service tests never add a group member directly")
        }
        async fn remove_member(
            &self,
            _group_id: &GroupId,
            _device_id: &DeviceId,
        ) -> Result<(), DomainError> {
            unimplemented!("auth_service tests never remove a group member directly")
        }
        async fn list_members(&self, _group_id: &GroupId) -> Result<Vec<GroupMember>, DomainError> {
            unimplemented!("auth_service tests never list group members")
        }
        async fn list_groups_for_device(
            &self,
            device_id: &DeviceId,
        ) -> Result<Vec<GroupId>, DomainError> {
            Ok(self
                .members
                .lock()
                .unwrap()
                .iter()
                .filter(|m| &m.device_id == device_id)
                .map(|m| m.group_id.clone())
                .collect())
        }
        async fn upsert_members(
            &self,
            _group: &Group,
            _members: &[GroupMember],
        ) -> Result<(), DomainError> {
            unimplemented!("auth_service tests never upsert group members")
        }
        async fn create_pending_removal(
            &self,
            group_id: &GroupId,
            device_id: &DeviceId,
        ) -> Result<(), DomainError> {
            // Mirrors ON CONFLICT (group_id, device_id) DO NOTHING.
            let mut pending = self.pending.lock().unwrap();
            let pair = (group_id.clone(), device_id.clone());
            if !pending.contains(&pair) {
                pending.push(pair);
            }
            Ok(())
        }
        async fn delete_pending_removal(
            &self,
            _group_id: &GroupId,
            _device_id: &DeviceId,
        ) -> Result<(), DomainError> {
            unimplemented!("auth_service tests never clear a pending removal")
        }
        async fn list_pending_removals(
            &self,
            group_id: &GroupId,
        ) -> Result<Vec<DeviceId>, DomainError> {
            Ok(self
                .pending
                .lock()
                .unwrap()
                .iter()
                .filter(|(g, _)| g == group_id)
                .map(|(_, d)| d.clone())
                .collect())
        }
    }

    /// A `GroupRepository` wrapper whose `create_pending_removal` always fails,
    /// delegating everything else to `inner`. Used to test that `revoke_device`
    /// still succeeds (fail-safe posture) and still publishes the live signal
    /// even when the durable pending-removal write fails.
    struct FailingCreatePendingRemovalGroupRepo {
        inner: Arc<FakeGroupRepo>,
    }
    #[async_trait::async_trait]
    impl GroupRepository for FailingCreatePendingRemovalGroupRepo {
        async fn save(&self, group: &Group) -> Result<(), DomainError> {
            self.inner.save(group).await
        }
        async fn advance_epoch(
            &self,
            group_id: &GroupId,
            expected: Epoch,
        ) -> Result<Option<Epoch>, DomainError> {
            self.inner.advance_epoch(group_id, expected).await
        }
        async fn create_if_absent(&self, group: &Group) -> Result<bool, DomainError> {
            self.inner.create_if_absent(group).await
        }
        async fn create_with_creator(
            &self,
            group: &Group,
            creator: &GroupMember,
        ) -> Result<bool, DomainError> {
            self.inner.create_with_creator(group, creator).await
        }
        async fn find_by_id(&self, id: &GroupId) -> Result<Option<Group>, DomainError> {
            self.inner.find_by_id(id).await
        }
        async fn add_member(&self, member: &GroupMember) -> Result<(), DomainError> {
            self.inner.add_member(member).await
        }
        async fn remove_member(
            &self,
            group_id: &GroupId,
            device_id: &DeviceId,
        ) -> Result<(), DomainError> {
            self.inner.remove_member(group_id, device_id).await
        }
        async fn list_members(&self, group_id: &GroupId) -> Result<Vec<GroupMember>, DomainError> {
            self.inner.list_members(group_id).await
        }
        async fn list_groups_for_device(
            &self,
            device_id: &DeviceId,
        ) -> Result<Vec<GroupId>, DomainError> {
            self.inner.list_groups_for_device(device_id).await
        }
        async fn upsert_members(
            &self,
            group: &Group,
            members: &[GroupMember],
        ) -> Result<(), DomainError> {
            self.inner.upsert_members(group, members).await
        }
        async fn create_pending_removal(
            &self,
            _group_id: &GroupId,
            _device_id: &DeviceId,
        ) -> Result<(), DomainError> {
            Err(DomainError::Internal(
                "injected create_pending_removal failure".into(),
            ))
        }
        async fn delete_pending_removal(
            &self,
            group_id: &GroupId,
            device_id: &DeviceId,
        ) -> Result<(), DomainError> {
            self.inner.delete_pending_removal(group_id, device_id).await
        }
        async fn list_pending_removals(
            &self,
            group_id: &GroupId,
        ) -> Result<Vec<DeviceId>, DomainError> {
            self.inner.list_pending_removals(group_id).await
        }
    }

    // ── fake event bus (records published events for assertions) ────────────

    struct FakeEventBus {
        published: Mutex<Vec<DomainEvent>>,
    }
    impl FakeEventBus {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                published: Mutex::new(vec![]),
            })
        }
    }
    #[async_trait::async_trait]
    impl DomainEventBus for FakeEventBus {
        async fn publish(&self, event: DomainEvent) -> Result<(), DomainError> {
            self.published.lock().unwrap().push(event);
            Ok(())
        }
        async fn subscribe(&self, _topic: &str) -> Result<EventStream, DomainError> {
            Ok(Box::pin(futures::stream::empty()))
        }
    }

    /// An event bus whose `publish` always fails. Used to test that
    /// `revoke_device` still succeeds (fail-safe posture) and still records
    /// the durable pending removal even when the live signal fails to publish.
    struct FailingEventBus;
    #[async_trait::async_trait]
    impl DomainEventBus for FailingEventBus {
        async fn publish(&self, _event: DomainEvent) -> Result<(), DomainError> {
            Err(DomainError::Internal("injected publish failure".into()))
        }
        async fn subscribe(&self, _topic: &str) -> Result<EventStream, DomainError> {
            Ok(Box::pin(futures::stream::empty()))
        }
    }

    // ── fake invite use case (revoke_device's invite-cleanup collaborator) ───

    /// An `InviteUseCase` that always succeeds, recording every device whose
    /// invites were revoked so a test can assert `revoke_device` actually
    /// called it.
    struct FakeInvite {
        revoked: Mutex<Vec<DeviceId>>,
    }
    impl FakeInvite {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                revoked: Mutex::new(vec![]),
            })
        }
    }
    #[async_trait::async_trait]
    impl InviteUseCase for FakeInvite {
        async fn create_invite(
            &self,
            _device_id: &DeviceId,
            _key_package: Vec<u8>,
        ) -> Result<CreatedInvite, DomainError> {
            unimplemented!("auth_service tests never create/redeem an invite")
        }
        async fn redeem_invite(&self, _code: &str) -> Result<RedeemedInvite, DomainError> {
            unimplemented!("auth_service tests never create/redeem an invite")
        }
        async fn revoke_invites_for_device(&self, device_id: &DeviceId) -> Result<(), DomainError> {
            self.revoked.lock().unwrap().push(device_id.clone());
            Ok(())
        }
    }

    /// An `InviteUseCase` whose `revoke_invites_for_device` always fails, to
    /// prove revoke_device propagates it BEFORE anything irreversible happens.
    struct FailingInvite;
    #[async_trait::async_trait]
    impl InviteUseCase for FailingInvite {
        async fn create_invite(
            &self,
            _device_id: &DeviceId,
            _key_package: Vec<u8>,
        ) -> Result<CreatedInvite, DomainError> {
            unimplemented!("auth_service tests never create/redeem an invite")
        }
        async fn redeem_invite(&self, _code: &str) -> Result<RedeemedInvite, DomainError> {
            unimplemented!("auth_service tests never create/redeem an invite")
        }
        async fn revoke_invites_for_device(
            &self,
            _device_id: &DeviceId,
        ) -> Result<(), DomainError> {
            Err(DomainError::Internal(
                "injected revoke_invites_for_device failure".into(),
            ))
        }
    }

    // ── fake OPAQUE port (echo / always-succeeds stub) ───────────────────────

    struct FakeOpaque;
    impl OpaqueServerPort for FakeOpaque {
        fn registration_start(&self, ke1: &[u8], _id: &[u8]) -> Result<Vec<u8>, DomainError> {
            Ok(ke1.to_vec())
        }
        fn registration_finish(&self, upload: &[u8]) -> Result<Vec<u8>, DomainError> {
            Ok(upload.to_vec())
        }
        fn login_start(
            &self,
            _pf: Option<&[u8]>,
            ke1: &[u8],
            _id: &[u8],
            _nonce: &[u8],
        ) -> Result<Vec<u8>, DomainError> {
            Ok(ke1.to_vec())
        }
        fn login_finish(
            &self,
            _nonce: &[u8],
            _ke3: &[u8],
        ) -> Result<(Vec<u8>, Vec<u8>), DomainError> {
            Ok((vec![0u8; 64], b"fake-user-identity".to_vec()))
        }
    }

    // ── fake cache ───────────────────────────────────────────────────────────

    struct FakeCache {
        store: Mutex<HashMap<String, Vec<u8>>>,
        sets: Mutex<HashMap<String, Vec<String>>>,
    }
    impl FakeCache {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                store: Mutex::new(HashMap::new()),
                sets: Mutex::new(HashMap::new()),
            })
        }
    }
    #[async_trait::async_trait]
    impl CachePort for FakeCache {
        async fn get(&self, key: &str) -> Result<Option<Vec<u8>>, DomainError> {
            Ok(self.store.lock().unwrap().get(key).cloned())
        }
        async fn set(
            &self,
            key: &str,
            value: Vec<u8>,
            _ttl: Option<Duration>,
        ) -> Result<(), DomainError> {
            self.store.lock().unwrap().insert(key.to_owned(), value);
            Ok(())
        }
        async fn delete(&self, key: &str) -> Result<(), DomainError> {
            self.store.lock().unwrap().remove(key);
            self.sets.lock().unwrap().remove(key);
            Ok(())
        }
        async fn exists(&self, key: &str) -> Result<bool, DomainError> {
            Ok(self.store.lock().unwrap().contains_key(key))
        }
        async fn get_del(&self, key: &str) -> Result<Option<Vec<u8>>, DomainError> {
            Ok(self.store.lock().unwrap().remove(key))
        }
        async fn set_add(&self, key: &str, member: &str) -> Result<(), DomainError> {
            self.sets
                .lock()
                .unwrap()
                .entry(key.to_owned())
                .or_default()
                .push(member.to_owned());
            Ok(())
        }
        async fn set_expire(&self, _key: &str, _ttl: Duration) -> Result<(), DomainError> {
            Ok(())
        }
        async fn set_members(&self, key: &str) -> Result<Vec<String>, DomainError> {
            Ok(self
                .sets
                .lock()
                .unwrap()
                .get(key)
                .cloned()
                .unwrap_or_default())
        }
    }

    /// A FakeCache variant that fails on `set_add` to test the hard-fail path.
    struct SetAddFailCache {
        inner: Arc<FakeCache>,
    }
    impl SetAddFailCache {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                inner: FakeCache::new(),
            })
        }
    }
    #[async_trait::async_trait]
    impl CachePort for SetAddFailCache {
        async fn get(&self, key: &str) -> Result<Option<Vec<u8>>, DomainError> {
            self.inner.get(key).await
        }
        async fn set(
            &self,
            key: &str,
            value: Vec<u8>,
            ttl: Option<Duration>,
        ) -> Result<(), DomainError> {
            self.inner.set(key, value, ttl).await
        }
        async fn delete(&self, key: &str) -> Result<(), DomainError> {
            self.inner.delete(key).await
        }
        async fn exists(&self, key: &str) -> Result<bool, DomainError> {
            self.inner.exists(key).await
        }
        async fn get_del(&self, key: &str) -> Result<Option<Vec<u8>>, DomainError> {
            self.inner.get_del(key).await
        }
        async fn set_add(&self, _key: &str, _member: &str) -> Result<(), DomainError> {
            Err(DomainError::Internal("set_add injected failure".into()))
        }
        async fn set_expire(&self, _key: &str, _ttl: Duration) -> Result<(), DomainError> {
            Ok(())
        }
        async fn set_members(&self, key: &str) -> Result<Vec<String>, DomainError> {
            self.inner.set_members(key).await
        }
    }

    /// A FakeCache variant whose `delete` fails for any key starting with "session:".
    /// Used to test the revoke_device per-token deletion failure path.
    struct SessionDeleteFailCache {
        inner: Arc<FakeCache>,
    }
    impl SessionDeleteFailCache {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                inner: FakeCache::new(),
            })
        }
    }
    #[async_trait::async_trait]
    impl CachePort for SessionDeleteFailCache {
        async fn get(&self, key: &str) -> Result<Option<Vec<u8>>, DomainError> {
            self.inner.get(key).await
        }
        async fn set(
            &self,
            key: &str,
            value: Vec<u8>,
            ttl: Option<Duration>,
        ) -> Result<(), DomainError> {
            self.inner.set(key, value, ttl).await
        }
        async fn delete(&self, key: &str) -> Result<(), DomainError> {
            if key.starts_with("session:") {
                return Err(DomainError::Internal(
                    "injected session delete failure".into(),
                ));
            }
            self.inner.delete(key).await
        }
        async fn exists(&self, key: &str) -> Result<bool, DomainError> {
            self.inner.exists(key).await
        }
        async fn get_del(&self, key: &str) -> Result<Option<Vec<u8>>, DomainError> {
            self.inner.get_del(key).await
        }
        async fn set_add(&self, key: &str, member: &str) -> Result<(), DomainError> {
            self.inner.set_add(key, member).await
        }
        async fn set_expire(&self, key: &str, ttl: Duration) -> Result<(), DomainError> {
            self.inner.set_expire(key, ttl).await
        }
        async fn set_members(&self, key: &str) -> Result<Vec<String>, DomainError> {
            self.inner.set_members(key).await
        }
    }

    /// A FakeCache variant that fails on `set_members` to test the propagation path.
    struct SetMembersFailCache {
        inner: Arc<FakeCache>,
    }
    impl SetMembersFailCache {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                inner: FakeCache::new(),
            })
        }
    }
    #[async_trait::async_trait]
    impl CachePort for SetMembersFailCache {
        async fn get(&self, key: &str) -> Result<Option<Vec<u8>>, DomainError> {
            self.inner.get(key).await
        }
        async fn set(
            &self,
            key: &str,
            value: Vec<u8>,
            ttl: Option<Duration>,
        ) -> Result<(), DomainError> {
            self.inner.set(key, value, ttl).await
        }
        async fn delete(&self, key: &str) -> Result<(), DomainError> {
            self.inner.delete(key).await
        }
        async fn exists(&self, key: &str) -> Result<bool, DomainError> {
            self.inner.exists(key).await
        }
        async fn get_del(&self, key: &str) -> Result<Option<Vec<u8>>, DomainError> {
            self.inner.get_del(key).await
        }
        async fn set_add(&self, key: &str, member: &str) -> Result<(), DomainError> {
            self.inner.set_add(key, member).await
        }
        async fn set_expire(&self, key: &str, ttl: Duration) -> Result<(), DomainError> {
            self.inner.set_expire(key, ttl).await
        }
        async fn set_members(&self, _key: &str) -> Result<Vec<String>, DomainError> {
            Err(DomainError::Internal("injected set_members failure".into()))
        }
    }

    const TEST_ORACLE_SECRET: [u8; 32] = [42u8; 32];

    fn make_svc() -> (
        AuthService,
        Arc<FakeUserRepo>,
        Arc<FakeDeviceRepo>,
        Arc<FakeCache>,
    ) {
        let (svc, user_repo, device_repo, _kp_repo, cache) = make_svc_with_key_packages();
        (svc, user_repo, device_repo, cache)
    }

    fn make_svc_with_key_packages() -> (
        AuthService,
        Arc<FakeUserRepo>,
        Arc<FakeDeviceRepo>,
        Arc<FakeKeyPackageRepo>,
        Arc<FakeCache>,
    ) {
        let user_repo = FakeUserRepo::new();
        let device_repo = FakeDeviceRepo::new();
        let key_package_repo = FakeKeyPackageRepo::new();
        let group_repo = FakeGroupRepo::new();
        let opaque = Arc::new(FakeOpaque);
        let cache = FakeCache::new();
        let event_bus = FakeEventBus::new();
        let invite = FakeInvite::new();
        let svc = AuthService::new(
            user_repo.clone(),
            device_repo.clone(),
            key_package_repo.clone(),
            group_repo,
            opaque,
            cache.clone(),
            event_bus,
            invite,
            TEST_ORACLE_SECRET,
        );
        (svc, user_repo, device_repo, key_package_repo, cache)
    }

    /// Wires an `AuthService` around caller-supplied `device_repo`, `group_repo`
    /// and `event_bus`, for tests exercising `revoke_device`'s per-group
    /// pending-removal / event-fan-out behavior. `user_repo` is unused by
    /// `revoke_device` (ownership is checked against `device.user_id`
    /// directly), so it is created fresh and returned only for symmetry with
    /// the other `make_svc*` helpers.
    fn make_svc_with_group_repo(
        device_repo: Arc<FakeDeviceRepo>,
        group_repo: Arc<dyn GroupRepository>,
        event_bus: Arc<dyn DomainEventBus>,
    ) -> (AuthService, Arc<FakeUserRepo>) {
        let user_repo = FakeUserRepo::new();
        let key_package_repo = FakeKeyPackageRepo::new();
        let opaque = Arc::new(FakeOpaque);
        let cache = FakeCache::new();
        let invite = FakeInvite::new();
        let svc = AuthService::new(
            user_repo.clone(),
            device_repo,
            key_package_repo,
            group_repo,
            opaque,
            cache,
            event_bus,
            invite,
            TEST_ORACLE_SECRET,
        );
        (svc, user_repo)
    }

    #[tokio::test]
    async fn register_init_caches_handle_hash() {
        let (svc, _, _, cache) = make_svc();
        let handle_hash = b"sha256-of-alice".to_vec();
        let resp = svc
            .register_init(RegistrationInitRequest {
                opaque_request: vec![1u8; 32],
                handle_hash: handle_hash.clone(),
            })
            .await
            .unwrap();
        let cache_key = format!("reg:{}", resp.user_id.as_uuid());
        let stored = cache.get(&cache_key).await.unwrap().unwrap();
        assert_eq!(stored, handle_hash);
    }

    #[tokio::test]
    async fn register_finish_persists_user_with_opaque_file() {
        let (svc, user_repo, _, _) = make_svc();
        let handle_hash = b"sha256-of-alice".to_vec();
        let resp = svc
            .register_init(RegistrationInitRequest {
                opaque_request: vec![1u8; 32],
                handle_hash: handle_hash.clone(),
            })
            .await
            .unwrap();
        let uid = resp.user_id.clone();
        svc.register_finish(RegistrationFinishRequest {
            user_id: uid.clone(),
            opaque_record: vec![2u8; 32],
            mls_credential: vec![],
            recovery_pubkey: None,
        })
        .await
        .unwrap();
        let user = user_repo.find_by_id(&uid).await.unwrap().unwrap();
        assert_eq!(user.handle_hash, handle_hash);
        assert_eq!(user.opaque_password_file, vec![2u8; 32]);
    }

    #[tokio::test]
    async fn register_finish_rejects_wrong_length_recovery_pubkey() {
        // A raw Ed25519 verifying key is always exactly 32 bytes — reject a
        // malformed value at enrollment rather than only failing closed later
        // at restore time (security-auditor finding, cycle 303).
        let (svc, user_repo, _, _) = make_svc();
        let handle_hash = b"sha256-of-alice".to_vec();
        let resp = svc
            .register_init(RegistrationInitRequest {
                opaque_request: vec![1u8; 32],
                handle_hash: handle_hash.clone(),
            })
            .await
            .unwrap();
        let uid = resp.user_id.clone();
        let err = svc
            .register_finish(RegistrationFinishRequest {
                user_id: uid.clone(),
                opaque_record: vec![2u8; 32],
                mls_credential: vec![],
                recovery_pubkey: Some(vec![0u8; 31]), // one byte short
            })
            .await
            .unwrap_err();
        assert!(matches!(err, DomainError::InvalidInput(_)));
        // No user must have been persisted on rejection.
        assert!(user_repo.find_by_id(&uid).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn register_finish_rejects_oversized_mls_credential() {
        // security-auditor finding, cycle 304 YELLOW #3: bound mls_credential size.
        let (svc, user_repo, _, _) = make_svc();
        let handle_hash = b"sha256-of-alice".to_vec();
        let resp = svc
            .register_init(RegistrationInitRequest {
                opaque_request: vec![1u8; 32],
                handle_hash: handle_hash.clone(),
            })
            .await
            .unwrap();
        let uid = resp.user_id.clone();
        let err = svc
            .register_finish(RegistrationFinishRequest {
                user_id: uid.clone(),
                opaque_record: vec![2u8; 32],
                mls_credential: vec![0u8; MAX_MLS_CREDENTIAL_BYTES + 1],
                recovery_pubkey: None,
            })
            .await
            .unwrap_err();
        assert!(matches!(err, DomainError::InvalidInput(_)));
        // No user must have been persisted on rejection.
        assert!(user_repo.find_by_id(&uid).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn register_finish_without_init_returns_not_found() {
        let (svc, _, _, _) = make_svc();
        let err = svc
            .register_finish(RegistrationFinishRequest {
                user_id: UserId::new(),
                opaque_record: vec![],
                mls_credential: vec![],
                recovery_pubkey: None,
            })
            .await
            .unwrap_err();
        assert!(matches!(err, DomainError::NotFound(_)));
    }

    #[tokio::test]
    async fn login_init_returns_user_id_for_known_handle_hash() {
        let (svc, user_repo, _, _) = make_svc();
        let handle_hash = b"sha256-of-alice".to_vec();
        let uid = UserId::new();
        user_repo
            .save(&User::new(uid.clone(), handle_hash.clone()))
            .await
            .unwrap();
        let resp = svc
            .login_init(LoginInitRequest {
                handle_hash: handle_hash.clone(),
                opaque_ke1: vec![0u8; 32],
            })
            .await
            .unwrap();
        assert_eq!(resp.user_id, uid);
        assert!(!resp.login_nonce.is_empty(), "nonce must be set");
    }

    #[tokio::test]
    async fn login_init_unknown_handle_returns_synthetic_response() {
        // R-3: unknown user must NOT return an error; it returns a synthetic ke2+nonce.
        let (svc, _, _, _) = make_svc();
        let resp = svc
            .login_init(LoginInitRequest {
                handle_hash: vec![0u8; 32],
                opaque_ke1: vec![0u8; 32],
            })
            .await
            .unwrap();
        assert!(!resp.login_nonce.is_empty());
        // ke2 is non-empty (echo stub returns ke1)
        assert!(!resp.opaque_ke2.is_empty());
    }

    #[tokio::test]
    async fn login_finish_issues_session_token_bound_to_device() {
        let (svc, user_repo, _, cache) = make_svc();
        let uid = UserId::new();
        user_repo
            .save(&User::new(uid.clone(), b"hash".to_vec()))
            .await
            .unwrap();
        let device_id = svc
            .register_device(
                &uid,
                DeviceRegistrationRequest {
                    mls_credential: vec![],
                },
            )
            .await
            .unwrap();
        let init = svc
            .login_init(LoginInitRequest {
                handle_hash: b"hash".to_vec(),
                opaque_ke1: vec![0u8; 32],
            })
            .await
            .unwrap();
        let token = svc
            .login_finish(LoginFinishRequest {
                opaque_ke3: vec![0u8; 32],
                login_nonce: init.login_nonce,
                device_id: device_id.clone(),
                recovery_proof: None,
            })
            .await
            .unwrap();
        let session_key = format!("session:{}", token.0);
        let stored = cache
            .get(&session_key)
            .await
            .unwrap()
            .expect("session stored");
        assert_eq!(
            stored,
            device_id.as_uuid().as_bytes().to_vec(),
            "session must store DeviceId bytes"
        );
    }

    #[tokio::test]
    async fn login_finish_wrong_device_owner_returns_unauthorized() {
        let (svc, user_repo, _, _) = make_svc();
        let uid = UserId::new();
        let other_uid = UserId::new();
        user_repo
            .save(&User::new(uid.clone(), b"hash".to_vec()))
            .await
            .unwrap();
        // Register a device under a DIFFERENT user.
        let other_device = svc
            .register_device(
                &other_uid,
                DeviceRegistrationRequest {
                    mls_credential: vec![],
                },
            )
            .await
            .unwrap();
        let init = svc
            .login_init(LoginInitRequest {
                handle_hash: b"hash".to_vec(),
                opaque_ke1: vec![0u8; 32],
            })
            .await
            .unwrap();
        let err = svc
            .login_finish(LoginFinishRequest {
                opaque_ke3: vec![0u8; 32],
                login_nonce: init.login_nonce,
                device_id: other_device,
                recovery_proof: None,
            })
            .await
            .unwrap_err();
        assert!(matches!(err, DomainError::Unauthorized));
    }

    #[tokio::test]
    async fn login_finish_nonce_cannot_be_reused() {
        // Y-3: nonce must be consumed atomically; a second login_finish with the
        // same nonce must return Unauthorized even if OPAQUE ke3 verifies.
        let (svc, user_repo, _, _) = make_svc();
        let uid = UserId::new();
        user_repo
            .save(&User::new(uid.clone(), b"hash".to_vec()))
            .await
            .unwrap();
        let device_id = svc
            .register_device(
                &uid,
                DeviceRegistrationRequest {
                    mls_credential: vec![],
                },
            )
            .await
            .unwrap();
        let init = svc
            .login_init(LoginInitRequest {
                handle_hash: b"hash".to_vec(),
                opaque_ke1: vec![0u8; 32],
            })
            .await
            .unwrap();
        let nonce = init.login_nonce.clone();

        // First use succeeds.
        svc.login_finish(LoginFinishRequest {
            opaque_ke3: vec![0u8; 32],
            login_nonce: nonce.clone(),
            device_id: device_id.clone(),
            recovery_proof: None,
        })
        .await
        .unwrap();

        // Second use with the same nonce must fail (nonce was consumed).
        let err = svc
            .login_finish(LoginFinishRequest {
                opaque_ke3: vec![0u8; 32],
                login_nonce: nonce,
                device_id: device_id.clone(),
                recovery_proof: None,
            })
            .await
            .unwrap_err();
        assert!(matches!(err, DomainError::Unauthorized));
    }

    #[tokio::test]
    async fn revoke_device_invalidates_active_sessions() {
        // Y-1: revoking a device must delete all live session tokens for that device.
        let (svc, user_repo, _, cache) = make_svc();
        let uid = UserId::new();
        user_repo
            .save(&User::new(uid.clone(), b"hash".to_vec()))
            .await
            .unwrap();
        let device_id = svc
            .register_device(
                &uid,
                DeviceRegistrationRequest {
                    mls_credential: vec![],
                },
            )
            .await
            .unwrap();

        // Log in once to create a session.
        let init = svc
            .login_init(LoginInitRequest {
                handle_hash: b"hash".to_vec(),
                opaque_ke1: vec![0u8; 32],
            })
            .await
            .unwrap();
        let token = svc
            .login_finish(LoginFinishRequest {
                opaque_ke3: vec![0u8; 32],
                login_nonce: init.login_nonce,
                device_id: device_id.clone(),
                recovery_proof: None,
            })
            .await
            .unwrap();

        // Session exists before revocation.
        let session_key = format!("session:{}", token.0);
        assert!(
            cache.get(&session_key).await.unwrap().is_some(),
            "session must exist before revoke"
        );

        // Revoke the device.
        svc.revoke_device(&uid, &device_id).await.unwrap();

        // Session must be deleted.
        assert!(
            cache.get(&session_key).await.unwrap().is_none(),
            "session must be deleted after device revoke"
        );
    }

    #[tokio::test]
    async fn login_finish_after_device_revoked_returns_unauthorized() {
        // R-1 race-close: if the device is revoked between the ownership check
        // and the final re-verify in login_finish, the session must NOT be issued.
        // We simulate this by revoking the device before login_finish runs.
        let (svc, user_repo, _, cache) = make_svc();
        let uid = UserId::new();
        user_repo
            .save(&User::new(uid.clone(), b"hash".to_vec()))
            .await
            .unwrap();
        let device_id = svc
            .register_device(
                &uid,
                DeviceRegistrationRequest {
                    mls_credential: vec![],
                },
            )
            .await
            .unwrap();
        let init = svc
            .login_init(LoginInitRequest {
                handle_hash: b"hash".to_vec(),
                opaque_ke1: vec![0u8; 32],
            })
            .await
            .unwrap();

        // Revoke the device before login_finish.
        svc.revoke_device(&uid, &device_id).await.unwrap();

        let err = svc
            .login_finish(LoginFinishRequest {
                opaque_ke3: vec![0u8; 32],
                login_nonce: init.login_nonce,
                device_id: device_id.clone(),
                recovery_proof: None,
            })
            .await
            .unwrap_err();
        assert!(matches!(err, DomainError::Unauthorized));

        // No session must have been left in the cache.
        let session_count = cache
            .store
            .lock()
            .unwrap()
            .keys()
            .filter(|k| k.starts_with("session:"))
            .count();
        assert_eq!(session_count, 0, "no orphan session after revoke");
    }

    #[tokio::test]
    async fn login_finish_set_add_failure_returns_unauthorized_and_cleans_session() {
        // Hard-fail invariant: if set_add (session tracking) fails, login_finish must
        // return Unauthorized and must NOT leave an orphan session in the cache.
        let user_repo = FakeUserRepo::new();
        let device_repo = FakeDeviceRepo::new();
        let key_package_repo = FakeKeyPackageRepo::new();
        let group_repo = FakeGroupRepo::new();
        let opaque = Arc::new(FakeOpaque);
        let fail_cache = SetAddFailCache::new();
        let event_bus = FakeEventBus::new();
        let invite = FakeInvite::new();
        let svc = AuthService::new(
            user_repo.clone(),
            device_repo.clone(),
            key_package_repo,
            group_repo,
            opaque,
            fail_cache.clone(),
            event_bus,
            invite,
            TEST_ORACLE_SECRET,
        );

        let uid = UserId::new();
        user_repo
            .save(&User::new(uid.clone(), b"hash".to_vec()))
            .await
            .unwrap();
        let device_id = svc
            .register_device(
                &uid,
                DeviceRegistrationRequest {
                    mls_credential: vec![],
                },
            )
            .await
            .unwrap();
        let init = svc
            .login_init(LoginInitRequest {
                handle_hash: b"hash".to_vec(),
                opaque_ke1: vec![0u8; 32],
            })
            .await
            .unwrap();

        let err = svc
            .login_finish(LoginFinishRequest {
                opaque_ke3: vec![0u8; 32],
                login_nonce: init.login_nonce,
                device_id: device_id.clone(),
                recovery_proof: None,
            })
            .await
            .unwrap_err();
        assert!(
            matches!(err, DomainError::Unauthorized),
            "set_add failure must return Unauthorized"
        );

        // No orphan session must remain after the hard-fail.
        let session_count = fail_cache
            .inner
            .store
            .lock()
            .unwrap()
            .keys()
            .filter(|k| k.starts_with("session:"))
            .count();
        assert_eq!(session_count, 0, "no orphan session after set_add failure");
    }

    #[tokio::test]
    async fn register_device_creates_and_persists_device() {
        let (svc, _, device_repo, _) = make_svc();
        let uid = UserId::new();
        let device_id = svc
            .register_device(
                &uid,
                DeviceRegistrationRequest {
                    mls_credential: vec![1u8; 16],
                },
            )
            .await
            .unwrap();
        let stored = device_repo
            .find_by_id(&device_id)
            .await
            .unwrap()
            .expect("device saved");
        assert_eq!(stored.user_id, uid);
        assert_eq!(stored.mls_credential, vec![1u8; 16]);
    }

    #[tokio::test]
    async fn register_device_rejects_when_user_at_device_limit() {
        let (svc, _, _, _) = make_svc();
        let uid = UserId::new();
        // Fill up to MAX_DEVICES_PER_USER successfully.
        for _ in 0..MAX_DEVICES_PER_USER {
            svc.register_device(
                &uid,
                DeviceRegistrationRequest {
                    mls_credential: vec![],
                },
            )
            .await
            .unwrap();
        }
        // The next registration must be rejected.
        let err = svc
            .register_device(
                &uid,
                DeviceRegistrationRequest {
                    mls_credential: vec![],
                },
            )
            .await
            .unwrap_err();
        assert!(
            matches!(err, DomainError::InvalidInput(ref s) if s.contains("device_limit_exceeded")),
            "expected device_limit_exceeded, got: {err:?}"
        );
    }

    #[tokio::test]
    async fn register_device_rejects_oversized_mls_credential() {
        // security-auditor finding, cycle 304 YELLOW #3: bound mls_credential size.
        let (svc, _, device_repo, _) = make_svc();
        let uid = UserId::new();
        let err = svc
            .register_device(
                &uid,
                DeviceRegistrationRequest {
                    mls_credential: vec![0u8; MAX_MLS_CREDENTIAL_BYTES + 1],
                },
            )
            .await
            .unwrap_err();
        assert!(
            matches!(err, DomainError::InvalidInput(ref s) if s.contains("mls_credential")),
            "expected mls_credential-too-large InvalidInput, got: {err:?}"
        );
        assert!(device_repo.find_by_user(&uid).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn register_device_at_max_mls_credential_size_succeeds() {
        let (svc, _, _, _) = make_svc();
        let uid = UserId::new();
        svc.register_device(
            &uid,
            DeviceRegistrationRequest {
                mls_credential: vec![0u8; MAX_MLS_CREDENTIAL_BYTES],
            },
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn revoke_device_rejects_wrong_owner() {
        let (svc, _, device_repo, _) = make_svc();
        let owner = UserId::new();
        let attacker = UserId::new();
        let device_id = svc
            .register_device(
                &owner,
                DeviceRegistrationRequest {
                    mls_credential: vec![],
                },
            )
            .await
            .unwrap();
        let err = svc.revoke_device(&attacker, &device_id).await.unwrap_err();
        assert!(matches!(err, DomainError::Unauthorized));
        assert!(device_repo.find_by_id(&device_id).await.unwrap().is_some());
    }

    #[tokio::test]
    async fn revoke_device_owner_succeeds() {
        let (svc, _, device_repo, _) = make_svc();
        let owner = UserId::new();
        let device_id = svc
            .register_device(
                &owner,
                DeviceRegistrationRequest {
                    mls_credential: vec![],
                },
            )
            .await
            .unwrap();
        svc.revoke_device(&owner, &device_id).await.unwrap();
        assert!(device_repo.find_by_id(&device_id).await.unwrap().is_none());
    }

    /// SECURITY: revoking a device must delete every KeyPackage (consumed or
    /// not) it uploaded. Without this, a stale unconsumed KeyPackage could
    /// still be handed out via fetch_one/ConsumeKeyPackage after revocation,
    /// letting a group add a credential for a device that no longer exists.
    /// A sibling device's KeyPackages must be untouched (scoping, not a
    /// blanket wipe).
    #[tokio::test]
    async fn revoke_device_deletes_its_key_packages_but_not_a_sibling_devices() {
        let (svc, _, _, key_package_repo, _) = make_svc_with_key_packages();
        let owner = UserId::new();
        let revoked_device = svc
            .register_device(
                &owner,
                DeviceRegistrationRequest {
                    mls_credential: vec![],
                },
            )
            .await
            .unwrap();
        let surviving_device = svc
            .register_device(
                &owner,
                DeviceRegistrationRequest {
                    mls_credential: vec![],
                },
            )
            .await
            .unwrap();

        let revoked_kp = KeyPackage {
            id: KeyPackageId::new(),
            device_id: revoked_device.clone(),
            data: vec![0xaa; 16],
            uploaded_at: chrono::Utc::now(),
            consumed: false,
        };
        let revoked_kp_consumed = KeyPackage {
            id: KeyPackageId::new(),
            device_id: revoked_device.clone(),
            data: vec![0xbb; 16],
            uploaded_at: chrono::Utc::now(),
            consumed: true,
        };
        let surviving_kp = KeyPackage {
            id: KeyPackageId::new(),
            device_id: surviving_device.clone(),
            data: vec![0xcc; 16],
            uploaded_at: chrono::Utc::now(),
            consumed: false,
        };
        key_package_repo.save(&revoked_kp).await.unwrap();
        key_package_repo.save(&revoked_kp_consumed).await.unwrap();
        key_package_repo.save(&surviving_kp).await.unwrap();

        svc.revoke_device(&owner, &revoked_device).await.unwrap();

        assert_eq!(
            key_package_repo
                .count_available(&revoked_device)
                .await
                .unwrap(),
            0,
            "revoked device must have zero KeyPackages left, not just zero unconsumed ones"
        );
        assert!(
            key_package_repo
                .store
                .lock()
                .unwrap()
                .values()
                .all(|kp| kp.device_id != revoked_device),
            "no KeyPackage row of any consumed-state may survive for the revoked device"
        );
        assert_eq!(
            key_package_repo
                .count_available(&surviving_device)
                .await
                .unwrap(),
            1,
            "a sibling device's KeyPackages must be untouched by another device's revocation"
        );
    }

    #[tokio::test]
    async fn revoke_device_not_found_returns_error() {
        let (svc, _, _, _) = make_svc();
        let err = svc
            .revoke_device(&UserId::new(), &DeviceId::new())
            .await
            .unwrap_err();
        assert!(matches!(err, DomainError::NotFound(_)));
    }

    #[tokio::test]
    async fn revoke_device_partial_session_delete_failure_still_returns_ok() {
        // Per-token delete failures (e.g. cache partition) must not abort the
        // revocation — the device must be deleted and the function must return Ok.
        // Surviving tokens will expire after SESSION_TTL.
        let user_repo = FakeUserRepo::new();
        let device_repo = FakeDeviceRepo::new();
        let key_package_repo = FakeKeyPackageRepo::new();
        let group_repo = FakeGroupRepo::new();
        let opaque = Arc::new(FakeOpaque);
        let fail_cache = SessionDeleteFailCache::new();
        let event_bus = FakeEventBus::new();
        let invite = FakeInvite::new();
        let svc = AuthService::new(
            user_repo.clone(),
            device_repo.clone(),
            key_package_repo,
            group_repo,
            opaque,
            fail_cache.clone(),
            event_bus,
            invite,
            TEST_ORACLE_SECRET,
        );

        let uid = UserId::new();
        user_repo
            .save(&User::new(uid.clone(), b"hash".to_vec()))
            .await
            .unwrap();
        let device_id = svc
            .register_device(
                &uid,
                DeviceRegistrationRequest {
                    mls_credential: vec![],
                },
            )
            .await
            .unwrap();

        // Inject a token into the device_sessions set directly so the loop has
        // something to try to delete.
        let device_sessions_key = format!("device_sessions:{}", device_id.as_uuid());
        fail_cache
            .inner
            .set_add(&device_sessions_key, "fake-token-abc")
            .await
            .unwrap();

        // revoke_device must succeed even though the session delete will fail.
        svc.revoke_device(&uid, &device_id).await.unwrap();

        // Device must have been deleted despite the cache error.
        assert!(
            device_repo.find_by_id(&device_id).await.unwrap().is_none(),
            "device must be deleted even when session delete fails"
        );
    }

    #[tokio::test]
    async fn login_init_unknown_handle_returns_consistent_synthetic_user_id() {
        // Handle-oracle invariant: two consecutive login_init calls with the same
        // unknown handle_hash must return the SAME user_id (deterministic synthetic UUID).
        // If they returned different UUIDs, an attacker could enumerate valid handles.
        let (svc, _, _, _) = make_svc();
        let unknown_hash = vec![0xabu8; 32];

        let resp1 = svc
            .login_init(LoginInitRequest {
                handle_hash: unknown_hash.clone(),
                opaque_ke1: vec![0u8; 32],
            })
            .await
            .unwrap();
        let resp2 = svc
            .login_init(LoginInitRequest {
                handle_hash: unknown_hash.clone(),
                opaque_ke1: vec![0u8; 32],
            })
            .await
            .unwrap();

        assert_eq!(
            resp1.user_id, resp2.user_id,
            "unknown handle must map to the same synthetic user_id across calls"
        );
    }

    #[tokio::test]
    async fn login_init_different_unknown_handles_return_different_synthetic_ids() {
        // Different unknown handles must map to different synthetic user_ids so they
        // are not collapsed to the same nonce cache slot.
        let (svc, _, _, _) = make_svc();
        let resp1 = svc
            .login_init(LoginInitRequest {
                handle_hash: vec![0xaau8; 32],
                opaque_ke1: vec![0u8; 32],
            })
            .await
            .unwrap();
        let resp2 = svc
            .login_init(LoginInitRequest {
                handle_hash: vec![0xbbu8; 32],
                opaque_ke1: vec![0u8; 32],
            })
            .await
            .unwrap();

        assert_ne!(
            resp1.user_id, resp2.user_id,
            "different unknown handles must produce different synthetic user_ids"
        );
    }

    #[tokio::test]
    async fn revoke_device_set_members_failure_propagates_error() {
        // If we cannot enumerate active sessions the revocation fails — silently
        // leaving live tokens for a revoked device is worse than returning an error.
        // NOTE: the device delete happens BEFORE the cache enumeration, so the
        // device will be gone even if this returns an error.
        let user_repo = FakeUserRepo::new();
        let device_repo = FakeDeviceRepo::new();
        let key_package_repo = FakeKeyPackageRepo::new();
        let group_repo = FakeGroupRepo::new();
        let opaque = Arc::new(FakeOpaque);
        let fail_cache = SetMembersFailCache::new();
        let event_bus = FakeEventBus::new();
        let invite = FakeInvite::new();
        let svc = AuthService::new(
            user_repo.clone(),
            device_repo.clone(),
            key_package_repo,
            group_repo,
            opaque,
            fail_cache.clone(),
            event_bus,
            invite,
            TEST_ORACLE_SECRET,
        );

        let uid = UserId::new();
        user_repo
            .save(&User::new(uid.clone(), b"hash".to_vec()))
            .await
            .unwrap();
        let device_id = svc
            .register_device(
                &uid,
                DeviceRegistrationRequest {
                    mls_credential: vec![],
                },
            )
            .await
            .unwrap();

        let err = svc.revoke_device(&uid, &device_id).await.unwrap_err();
        assert!(
            matches!(err, DomainError::Internal(_)),
            "set_members failure must propagate"
        );
    }

    #[tokio::test]
    async fn revoke_device_records_pending_removals_even_when_session_invalidation_fails() {
        // Regression guard for the fan-out ordering: the durable
        // pending-removal write runs before the irreversible deletes (hard
        // fail, see the ordering test above), and the live RemovalRequired
        // publish runs after them but still BEFORE session invalidation,
        // since session invalidation hard-fails (`?`) on a cache outage. If
        // the publish were downstream of that `?`, this test would see no
        // published event even though the durable row was already written.
        let uid = UserId::new();
        let device_id = DeviceId::new();
        let device_repo = FakeDeviceRepo::new();
        device_repo
            .save(&Device::new(device_id.clone(), uid.clone(), vec![]))
            .await
            .unwrap();
        let group_id = GroupId::new();
        let group_repo: Arc<dyn GroupRepository> =
            FakeGroupRepo::with_memberships(vec![(group_id.clone(), device_id.clone())]);
        let key_package_repo = FakeKeyPackageRepo::new();
        let opaque = Arc::new(FakeOpaque);
        let fail_cache = SetMembersFailCache::new();
        let event_bus = FakeEventBus::new();
        let invite = FakeInvite::new();
        let svc = AuthService::new(
            FakeUserRepo::new(),
            device_repo,
            key_package_repo,
            group_repo.clone(),
            opaque,
            fail_cache,
            event_bus.clone(),
            invite,
            TEST_ORACLE_SECRET,
        );

        // Session invalidation is a hard-fail security control — that must
        // NOT change: revoke_device still returns Err on cache failure.
        let err = svc.revoke_device(&uid, &device_id).await.unwrap_err();
        assert!(
            matches!(err, DomainError::Internal(_)),
            "set_members failure must still propagate as an error"
        );

        // Despite the Err, the fan-out (which runs before the failing cache
        // call) must have already recorded the pending removal and published
        // the live signal.
        assert_eq!(
            group_repo.list_pending_removals(&group_id).await.unwrap(),
            vec![device_id.clone()],
            "pending removal must be recorded even though session invalidation failed"
        );
        let published = event_bus.published.lock().unwrap();
        assert!(
            published.iter().any(|e| matches!(
                e,
                DomainEvent::RemovalRequired { group_id: g, device_id: d, .. }
                    if *g == group_id && *d == device_id
            )),
            "RemovalRequired must be published even though session invalidation failed"
        );
    }

    /// SECURITY: this encodes "the 24h stale-invite-credential window cannot
    /// reopen due to a session-cache blip". Before the fix, the REST handler
    /// orchestrated invite cleanup AFTER `AuthService::revoke_device`
    /// returned, so a session-invalidation `Err` here short-circuited it
    /// permanently — a client retry can only hit `NotFound` (device already
    /// gone), so invite cleanup would be skipped forever. Invite revocation
    /// now sits inside `revoke_device`, upstream of the failing cache call,
    /// so it must run regardless of what happens downstream.
    #[tokio::test]
    async fn revoke_device_still_revokes_invites_even_when_session_invalidation_fails_afterward() {
        let uid = UserId::new();
        let device_id = DeviceId::new();
        let device_repo = FakeDeviceRepo::new();
        device_repo
            .save(&Device::new(device_id.clone(), uid.clone(), vec![]))
            .await
            .unwrap();
        let key_package_repo = FakeKeyPackageRepo::new();
        let group_repo = FakeGroupRepo::new();
        let opaque = Arc::new(FakeOpaque);
        let fail_cache = SetMembersFailCache::new();
        let event_bus = FakeEventBus::new();
        let invite = FakeInvite::new();
        let svc = AuthService::new(
            FakeUserRepo::new(),
            device_repo,
            key_package_repo,
            group_repo,
            opaque,
            fail_cache,
            event_bus,
            invite.clone(),
            TEST_ORACLE_SECRET,
        );

        // Session invalidation is still a hard-fail security control — that
        // must not change.
        let err = svc.revoke_device(&uid, &device_id).await.unwrap_err();
        assert!(
            matches!(err, DomainError::Internal(_)),
            "set_members failure must still propagate as an error"
        );

        // Invite revocation ran anyway, because it sits upstream of the
        // failing cache call.
        assert_eq!(
            invite.revoked.lock().unwrap().as_slice(),
            std::slice::from_ref(&device_id),
            "invite revocation must have run even though session invalidation failed"
        );
    }

    /// SECURITY: if KeyPackage cleanup fails, `revoke_device` must propagate
    /// the error and — critically — must NOT have already deleted the device
    /// row. `delete_by_device` runs BEFORE `device_repo.delete` precisely so
    /// a failure here leaves the device retryable rather than permanently
    /// stuck (device gone, but its KeyPackages orphaned forever since a
    /// retry would immediately hit `NotFound` on `find_by_id`).
    #[tokio::test]
    async fn revoke_device_key_package_cleanup_failure_propagates_and_device_survives() {
        let user_repo = FakeUserRepo::new();
        let device_repo = FakeDeviceRepo::new();
        let key_package_repo = Arc::new(FailingDeleteByDeviceKeyPackageRepo);
        let group_repo = FakeGroupRepo::new();
        let opaque = Arc::new(FakeOpaque);
        let cache = FakeCache::new();
        let event_bus = FakeEventBus::new();
        let invite = FakeInvite::new();
        let svc = AuthService::new(
            user_repo.clone(),
            device_repo.clone(),
            key_package_repo,
            group_repo,
            opaque,
            cache,
            event_bus,
            invite,
            TEST_ORACLE_SECRET,
        );

        let uid = UserId::new();
        user_repo
            .save(&User::new(uid.clone(), b"hash".to_vec()))
            .await
            .unwrap();
        let device_id = svc
            .register_device(
                &uid,
                DeviceRegistrationRequest {
                    mls_credential: vec![],
                },
            )
            .await
            .unwrap();

        let err = svc.revoke_device(&uid, &device_id).await.unwrap_err();
        assert!(
            matches!(err, DomainError::Internal(_)),
            "delete_by_device failure must propagate"
        );
        assert!(
            device_repo.find_by_id(&device_id).await.unwrap().is_some(),
            "device row must survive a failed KeyPackage cleanup so the caller can retry"
        );
    }

    /// SECURITY: pins the ordering invariant that invite revocation runs
    /// BEFORE anything irreversible in `revoke_device`. If
    /// `revoke_invites_for_device` fails, the function must propagate the
    /// error and — critically — must NOT have already deleted the device
    /// row or its KeyPackages: it runs first precisely so a failure here
    /// leaves the whole revocation safely retryable.
    #[tokio::test]
    async fn revoke_device_propagates_invite_revocation_failure_and_the_device_survives() {
        let user_repo = FakeUserRepo::new();
        let device_repo = FakeDeviceRepo::new();
        let key_package_repo = FakeKeyPackageRepo::new();
        let group_repo = FakeGroupRepo::new();
        let opaque = Arc::new(FakeOpaque);
        let cache = FakeCache::new();
        let event_bus = FakeEventBus::new();
        let invite = Arc::new(FailingInvite);
        let svc = AuthService::new(
            user_repo.clone(),
            device_repo.clone(),
            key_package_repo,
            group_repo,
            opaque,
            cache,
            event_bus,
            invite,
            TEST_ORACLE_SECRET,
        );

        let uid = UserId::new();
        user_repo
            .save(&User::new(uid.clone(), b"hash".to_vec()))
            .await
            .unwrap();
        let device_id = svc
            .register_device(
                &uid,
                DeviceRegistrationRequest {
                    mls_credential: vec![],
                },
            )
            .await
            .unwrap();

        let err = svc.revoke_device(&uid, &device_id).await.unwrap_err();
        assert!(
            matches!(err, DomainError::Internal(_)),
            "revoke_invites_for_device failure must propagate"
        );
        assert!(
            device_repo.find_by_id(&device_id).await.unwrap().is_some(),
            "device row must survive a failed invite-revocation so the caller can retry"
        );
    }

    // ── list_devices ─────────────────────────────────────────────────────────

    #[tokio::test]
    async fn list_devices_empty_when_user_has_no_devices() {
        let (svc, _, _, _) = make_svc();
        let uid = UserId::new();
        let devices = svc.list_devices(&uid).await.unwrap();
        assert!(devices.is_empty());
    }

    #[tokio::test]
    async fn list_devices_returns_all_registered_devices() {
        let (svc, _, _, _) = make_svc();
        let uid = UserId::new();
        let id1 = svc
            .register_device(
                &uid,
                DeviceRegistrationRequest {
                    mls_credential: vec![1],
                },
            )
            .await
            .unwrap();
        let id2 = svc
            .register_device(
                &uid,
                DeviceRegistrationRequest {
                    mls_credential: vec![2],
                },
            )
            .await
            .unwrap();

        let mut devices = svc.list_devices(&uid).await.unwrap();
        assert_eq!(devices.len(), 2);
        devices.sort_by_key(|d| d.device_id.as_uuid());
        let mut expected = [id1, id2];
        expected.sort_by_key(|d| d.as_uuid());
        assert_eq!(devices[0].device_id, expected[0]);
        assert_eq!(devices[1].device_id, expected[1]);
    }

    #[tokio::test]
    async fn list_devices_isolates_by_user() {
        // Security invariant: user A's devices must never appear in user B's list.
        let (svc, _, _, _) = make_svc();
        let user_a = UserId::new();
        let user_b = UserId::new();
        svc.register_device(
            &user_a,
            DeviceRegistrationRequest {
                mls_credential: vec![],
            },
        )
        .await
        .unwrap();
        let device_b = svc
            .register_device(
                &user_b,
                DeviceRegistrationRequest {
                    mls_credential: vec![],
                },
            )
            .await
            .unwrap();

        let list_a = svc.list_devices(&user_a).await.unwrap();
        let list_b = svc.list_devices(&user_b).await.unwrap();

        assert_eq!(list_a.len(), 1);
        assert_eq!(list_b.len(), 1);
        assert_eq!(list_b[0].device_id, device_b);
        // user_b's device must not appear in user_a's list.
        assert!(
            !list_a.iter().any(|d| d.device_id == device_b),
            "user_b device must not appear in user_a list"
        );
    }

    #[tokio::test]
    async fn list_devices_last_seen_at_is_none_at_registration() {
        // Freshly registered devices have no last_seen_at.
        let (svc, _, _, _) = make_svc();
        let uid = UserId::new();
        svc.register_device(
            &uid,
            DeviceRegistrationRequest {
                mls_credential: vec![],
            },
        )
        .await
        .unwrap();
        let devices = svc.list_devices(&uid).await.unwrap();
        assert_eq!(devices.len(), 1);
        assert!(
            devices[0].last_seen_at.is_none(),
            "newly registered device has no last_seen_at"
        );
    }
    // ── §8.5 recovery-phrase account restore ─────────────────────────────────

    use ed25519_dalek::{Signer, SigningKey};

    /// Reconstruct the exact domain-separated message the client signs:
    ///   b"powehi-recovery-challenge-v1" || 0x00 || login_nonce.as_bytes()
    fn recovery_message(login_nonce: &str) -> Vec<u8> {
        let mut msg = Vec::new();
        msg.extend_from_slice(b"powehi-recovery-challenge-v1");
        msg.push(0u8);
        msg.extend_from_slice(login_nonce.as_bytes());
        msg
    }

    fn sign_recovery(sk: &SigningKey, login_nonce: &str) -> Vec<u8> {
        sk.sign(&recovery_message(login_nonce)).to_bytes().to_vec()
    }

    /// Save a user enrolled in recovery (recovery_pubkey = Some(vk)) under `handle`.
    async fn save_recovery_user(
        user_repo: &FakeUserRepo,
        handle: &[u8],
        vk_bytes: [u8; 32],
    ) -> UserId {
        let uid = UserId::new();
        let mut user = User::new(uid.clone(), handle.to_vec());
        user.recovery_pubkey = Some(vk_bytes.to_vec());
        user_repo.save(&user).await.unwrap();
        uid
    }

    #[tokio::test]
    async fn recovery_valid_proof_mints_device_and_issues_session() {
        // §8.5: lost-everything restore with a valid phrase signature over the login
        // nonce mints a brand-new device (unknown device_id) and issues a session.
        let (svc, user_repo, device_repo, cache) = make_svc();
        let sk = SigningKey::generate(&mut rand::thread_rng());
        let vk = sk.verifying_key().to_bytes();
        let uid = save_recovery_user(&user_repo, b"hash", vk).await;

        let init = svc
            .login_init(LoginInitRequest {
                handle_hash: b"hash".to_vec(),
                opaque_ke1: vec![0u8; 32],
            })
            .await
            .unwrap();
        assert_eq!(init.user_id, uid);

        let new_device = DeviceId::new(); // never registered
        let signature = sign_recovery(&sk, &init.login_nonce);
        let token = svc
            .login_finish(LoginFinishRequest {
                opaque_ke3: vec![0u8; 32],
                login_nonce: init.login_nonce,
                device_id: new_device.clone(),
                recovery_proof: Some(RecoveryProof {
                    mls_credential: vec![7u8; 16],
                    signature,
                }),
            })
            .await
            .unwrap();

        // Device was minted and bound to the authenticated user.
        let minted = device_repo
            .find_by_id(&new_device)
            .await
            .unwrap()
            .expect("recovery device minted");
        assert_eq!(minted.user_id, uid);
        assert_eq!(minted.mls_credential, vec![7u8; 16]);

        // Session was issued and bound to the new device.
        let session_key = format!("session:{}", token.0);
        let stored = cache.get(&session_key).await.unwrap().expect("session");
        assert_eq!(stored, new_device.as_uuid().as_bytes().to_vec());
    }

    #[tokio::test]
    async fn recovery_oversized_mls_credential_rejected_as_unauthorized() {
        // security-auditor finding, cycle 304 YELLOW #3: bound proof.mls_credential
        // size. Must collapse to Unauthorized (not a distinguishable error) like
        // every other check in mint_recovery_device, to avoid a pre-session oracle.
        let (svc, user_repo, device_repo, _) = make_svc();
        let sk = SigningKey::generate(&mut rand::thread_rng());
        let vk = sk.verifying_key().to_bytes();
        let uid = save_recovery_user(&user_repo, b"hash", vk).await;

        let init = svc
            .login_init(LoginInitRequest {
                handle_hash: b"hash".to_vec(),
                opaque_ke1: vec![0u8; 32],
            })
            .await
            .unwrap();
        assert_eq!(init.user_id, uid);

        let new_device = DeviceId::new();
        let signature = sign_recovery(&sk, &init.login_nonce);
        let err = svc
            .login_finish(LoginFinishRequest {
                opaque_ke3: vec![0u8; 32],
                login_nonce: init.login_nonce,
                device_id: new_device.clone(),
                recovery_proof: Some(RecoveryProof {
                    mls_credential: vec![0u8; MAX_MLS_CREDENTIAL_BYTES + 1],
                    signature,
                }),
            })
            .await
            .unwrap_err();
        assert!(matches!(err, DomainError::Unauthorized));
        assert!(device_repo.find_by_id(&new_device).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn recovery_none_with_unknown_device_still_unauthorized() {
        // Regression: an unknown device_id with NO recovery_proof must stay a hard
        // reject (must not regress the pre-existing unknown/foreign-device path).
        let (svc, user_repo, _, _) = make_svc();
        user_repo
            .save(&User::new(UserId::new(), b"hash".to_vec()))
            .await
            .unwrap();
        let init = svc
            .login_init(LoginInitRequest {
                handle_hash: b"hash".to_vec(),
                opaque_ke1: vec![0u8; 32],
            })
            .await
            .unwrap();
        let err = svc
            .login_finish(LoginFinishRequest {
                opaque_ke3: vec![0u8; 32],
                login_nonce: init.login_nonce,
                device_id: DeviceId::new(), // unknown
                recovery_proof: None,
            })
            .await
            .unwrap_err();
        assert!(matches!(err, DomainError::Unauthorized));
    }

    #[test]
    fn dummy_recovery_pubkey_is_a_valid_ed25519_point() {
        // The timing-parity fix (mint_recovery_device) requires DUMMY_RECOVERY_PUBKEY
        // to decode successfully so the not-enrolled path reaches verify_strict
        // rather than short-circuiting on the malformed-pubkey branch, which would
        // reopen the timing gap this constant exists to close.
        assert!(VerifyingKey::from_bytes(&DUMMY_RECOVERY_PUBKEY).is_ok());
    }

    #[tokio::test]
    async fn recovery_proof_but_user_not_enrolled_is_unauthorized() {
        // User has recovery_pubkey = None (never enrolled). Even a well-formed proof
        // must fail closed to the SAME Unauthorized (no distinguishing oracle).
        let (svc, user_repo, device_repo, _) = make_svc();
        let uid = UserId::new();
        user_repo
            .save(&User::new(uid.clone(), b"hash".to_vec())) // recovery_pubkey: None
            .await
            .unwrap();
        let sk = SigningKey::generate(&mut rand::thread_rng());

        let init = svc
            .login_init(LoginInitRequest {
                handle_hash: b"hash".to_vec(),
                opaque_ke1: vec![0u8; 32],
            })
            .await
            .unwrap();
        let new_device = DeviceId::new();
        let signature = sign_recovery(&sk, &init.login_nonce);
        let err = svc
            .login_finish(LoginFinishRequest {
                opaque_ke3: vec![0u8; 32],
                login_nonce: init.login_nonce,
                device_id: new_device.clone(),
                recovery_proof: Some(RecoveryProof {
                    mls_credential: vec![1u8; 16],
                    signature,
                }),
            })
            .await
            .unwrap_err();
        assert!(matches!(err, DomainError::Unauthorized));
        // No device may be minted on the fail-closed path.
        assert!(device_repo.find_by_id(&new_device).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn recovery_signature_for_wrong_nonce_is_unauthorized() {
        // Signature is valid Ed25519 but over a DIFFERENT nonce → verify fails →
        // Unauthorized. Guards against nonce-replay / challenge substitution.
        let (svc, user_repo, device_repo, _) = make_svc();
        let sk = SigningKey::generate(&mut rand::thread_rng());
        let vk = sk.verifying_key().to_bytes();
        save_recovery_user(&user_repo, b"hash", vk).await;

        let init = svc
            .login_init(LoginInitRequest {
                handle_hash: b"hash".to_vec(),
                opaque_ke1: vec![0u8; 32],
            })
            .await
            .unwrap();
        // Sign a nonce that is NOT the one issued.
        let signature = sign_recovery(&sk, "some-other-nonce");
        let new_device = DeviceId::new();
        let err = svc
            .login_finish(LoginFinishRequest {
                opaque_ke3: vec![0u8; 32],
                login_nonce: init.login_nonce,
                device_id: new_device.clone(),
                recovery_proof: Some(RecoveryProof {
                    mls_credential: vec![2u8; 16],
                    signature,
                }),
            })
            .await
            .unwrap_err();
        assert!(matches!(err, DomainError::Unauthorized));
        assert!(device_repo.find_by_id(&new_device).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn recovery_mint_respects_device_cap() {
        // A recovery-minted device must NOT bypass MAX_DEVICES_PER_USER, and an
        // exceeded cap collapses to Unauthorized (no distinguishable device_limit).
        let (svc, user_repo, _, _) = make_svc();
        let sk = SigningKey::generate(&mut rand::thread_rng());
        let vk = sk.verifying_key().to_bytes();
        let uid = save_recovery_user(&user_repo, b"hash", vk).await;

        // Fill the account to the cap.
        for _ in 0..MAX_DEVICES_PER_USER {
            svc.register_device(
                &uid,
                DeviceRegistrationRequest {
                    mls_credential: vec![],
                },
            )
            .await
            .unwrap();
        }

        let init = svc
            .login_init(LoginInitRequest {
                handle_hash: b"hash".to_vec(),
                opaque_ke1: vec![0u8; 32],
            })
            .await
            .unwrap();
        let new_device = DeviceId::new();
        let signature = sign_recovery(&sk, &init.login_nonce);
        let err = svc
            .login_finish(LoginFinishRequest {
                opaque_ke3: vec![0u8; 32],
                login_nonce: init.login_nonce,
                device_id: new_device,
                recovery_proof: Some(RecoveryProof {
                    mls_credential: vec![3u8; 16],
                    signature,
                }),
            })
            .await
            .unwrap_err();
        assert!(matches!(err, DomainError::Unauthorized));
    }

    #[tokio::test]
    async fn recovery_minted_device_is_listed_and_revocable() {
        // A recovery-minted device needs no special-casing downstream: it appears in
        // list_devices and can be revoked by revoke_device like any other device.
        let (svc, user_repo, _, _) = make_svc();
        let sk = SigningKey::generate(&mut rand::thread_rng());
        let vk = sk.verifying_key().to_bytes();
        let uid = save_recovery_user(&user_repo, b"hash", vk).await;

        let init = svc
            .login_init(LoginInitRequest {
                handle_hash: b"hash".to_vec(),
                opaque_ke1: vec![0u8; 32],
            })
            .await
            .unwrap();
        let new_device = DeviceId::new();
        let signature = sign_recovery(&sk, &init.login_nonce);
        svc.login_finish(LoginFinishRequest {
            opaque_ke3: vec![0u8; 32],
            login_nonce: init.login_nonce,
            device_id: new_device.clone(),
            recovery_proof: Some(RecoveryProof {
                mls_credential: vec![4u8; 16],
                signature,
            }),
        })
        .await
        .unwrap();

        let devices = svc.list_devices(&uid).await.unwrap();
        assert!(devices.iter().any(|d| d.device_id == new_device));

        svc.revoke_device(&uid, &new_device).await.unwrap();
        let after = svc.list_devices(&uid).await.unwrap();
        assert!(!after.iter().any(|d| d.device_id == new_device));
    }

    // ── revoke_device group-removal fan-out ──────────────────────────────────

    #[tokio::test]
    async fn revoke_device_records_a_pending_removal_for_every_group_the_device_was_in() {
        let uid = UserId::new();
        let device_id = DeviceId::new();
        let device_repo = FakeDeviceRepo::new();
        device_repo
            .save(&Device::new(device_id.clone(), uid.clone(), vec![]))
            .await
            .unwrap();
        let group_a = GroupId::new();
        let group_b = GroupId::new();
        let group_repo = FakeGroupRepo::with_memberships(vec![
            (group_a.clone(), device_id.clone()),
            (group_b.clone(), device_id.clone()),
        ]);
        let event_bus = FakeEventBus::new();
        let (svc, _user_repo) =
            make_svc_with_group_repo(device_repo, group_repo.clone(), event_bus);

        svc.revoke_device(&uid, &device_id).await.unwrap();

        assert_eq!(
            group_repo.list_pending_removals(&group_a).await.unwrap(),
            vec![device_id.clone()]
        );
        assert_eq!(
            group_repo.list_pending_removals(&group_b).await.unwrap(),
            vec![device_id]
        );
    }

    #[tokio::test]
    async fn revoke_device_captures_group_membership_before_deleting_the_device() {
        // Regression guard: this test fails if `list_groups_for_device` is
        // ever moved to run AFTER `device_repo.delete`. The cascade hook
        // below mirrors the real `group_members.device_id` ON DELETE CASCADE
        // (migration 0001): once `device_repo.delete` runs, it wipes this
        // device's membership rows out of `group_repo` immediately. If
        // `revoke_device` read memberships after the delete instead of
        // before, `affected_groups` would already be empty and no pending
        // removal would ever be recorded.
        let uid = UserId::new();
        let device_id = DeviceId::new();
        let group_a = GroupId::new();
        let group_b = GroupId::new();
        let group_repo = FakeGroupRepo::with_memberships(vec![
            (group_a.clone(), device_id.clone()),
            (group_b.clone(), device_id.clone()),
        ]);
        let device_repo = FakeDeviceRepo::with_cascade(group_repo.clone());
        device_repo
            .save(&Device::new(device_id.clone(), uid.clone(), vec![]))
            .await
            .unwrap();
        let event_bus = FakeEventBus::new();
        let (svc, _user_repo) =
            make_svc_with_group_repo(device_repo, group_repo.clone(), event_bus);

        svc.revoke_device(&uid, &device_id).await.unwrap();

        assert_eq!(
            group_repo.list_pending_removals(&group_a).await.unwrap(),
            vec![device_id.clone()],
            "pending removal must survive even though cascade-delete already \
             wiped the membership row by the time it was recorded"
        );
        assert_eq!(
            group_repo.list_pending_removals(&group_b).await.unwrap(),
            vec![device_id]
        );
    }

    #[tokio::test]
    async fn revoke_device_publishes_one_removal_required_event_per_group() {
        let uid = UserId::new();
        let device_id = DeviceId::new();
        let device_repo = FakeDeviceRepo::new();
        device_repo
            .save(&Device::new(device_id.clone(), uid.clone(), vec![]))
            .await
            .unwrap();
        let group_a = GroupId::new();
        let group_b = GroupId::new();
        let group_repo = FakeGroupRepo::with_memberships(vec![
            (group_a.clone(), device_id.clone()),
            (group_b.clone(), device_id.clone()),
        ]);
        let event_bus = FakeEventBus::new();
        let (svc, _user_repo) =
            make_svc_with_group_repo(device_repo, group_repo, event_bus.clone());

        svc.revoke_device(&uid, &device_id).await.unwrap();

        let published = event_bus.published.lock().unwrap();
        let removals: Vec<(GroupId, DeviceId)> = published
            .iter()
            .filter_map(|e| match e {
                DomainEvent::RemovalRequired {
                    group_id,
                    device_id,
                    ..
                } => Some((group_id.clone(), device_id.clone())),
                _ => None,
            })
            .collect();
        assert_eq!(removals.len(), 2, "exactly one event per affected group");
        assert!(removals.contains(&(group_a, device_id.clone())));
        assert!(removals.contains(&(group_b, device_id)));
    }

    #[tokio::test]
    async fn revoke_device_succeeds_when_the_device_was_in_no_groups() {
        let uid = UserId::new();
        let device_id = DeviceId::new();
        let device_repo = FakeDeviceRepo::new();
        device_repo
            .save(&Device::new(device_id.clone(), uid.clone(), vec![]))
            .await
            .unwrap();
        let group_repo = FakeGroupRepo::new();
        let event_bus = FakeEventBus::new();
        let (svc, _user_repo) =
            make_svc_with_group_repo(device_repo, group_repo, event_bus.clone());

        svc.revoke_device(&uid, &device_id).await.unwrap();

        assert!(
            event_bus.published.lock().unwrap().is_empty(),
            "no groups affected means no removal-required events"
        );
    }

    /// SECURITY: pins the ordering invariant that the durable pending-removal
    /// write runs BEFORE anything irreversible in `revoke_device`, same
    /// reasoning as invite revocation and KeyPackage cleanup above. If
    /// `create_pending_removal` fails, the function must propagate the error
    /// and must NOT have already deleted the device row or its KeyPackages —
    /// a DB blip here is retryable, whereas losing this write silently after
    /// the device is already gone (the earlier draft of this function) would
    /// be unrecoverable.
    #[tokio::test]
    async fn revoke_device_propagates_pending_removal_failure_and_the_device_survives() {
        let uid = UserId::new();
        let device_id = DeviceId::new();
        let device_repo = FakeDeviceRepo::new();
        device_repo
            .save(&Device::new(device_id.clone(), uid.clone(), vec![]))
            .await
            .unwrap();
        let group_id = GroupId::new();
        let inner = FakeGroupRepo::with_memberships(vec![(group_id.clone(), device_id.clone())]);
        let group_repo: Arc<dyn GroupRepository> =
            Arc::new(FailingCreatePendingRemovalGroupRepo { inner });
        let event_bus = FakeEventBus::new();
        let (svc, _user_repo) =
            make_svc_with_group_repo(device_repo.clone(), group_repo, event_bus.clone());

        let err = svc.revoke_device(&uid, &device_id).await.unwrap_err();
        assert!(
            matches!(err, DomainError::Internal(_)),
            "create_pending_removal failure must propagate"
        );
        assert!(
            device_repo.find_by_id(&device_id).await.unwrap().is_some(),
            "device row must survive a failed pending-removal write so the caller can retry"
        );
        assert!(
            event_bus.published.lock().unwrap().is_empty(),
            "no live signal must be published when the durable write never completed"
        );
    }

    #[tokio::test]
    async fn revoke_device_still_succeeds_when_publishing_the_signal_fails() {
        // Fail-safe posture, mirrored: an event-bus failure must not fail the
        // whole revocation, and the durable pending-removal row must still
        // have been recorded so an offline member can pick it up later.
        let uid = UserId::new();
        let device_id = DeviceId::new();
        let device_repo = FakeDeviceRepo::new();
        device_repo
            .save(&Device::new(device_id.clone(), uid.clone(), vec![]))
            .await
            .unwrap();
        let group_id = GroupId::new();
        let group_repo =
            FakeGroupRepo::with_memberships(vec![(group_id.clone(), device_id.clone())]);
        let event_bus: Arc<dyn DomainEventBus> = Arc::new(FailingEventBus);
        let (svc, _user_repo) =
            make_svc_with_group_repo(device_repo, group_repo.clone(), event_bus);

        svc.revoke_device(&uid, &device_id)
            .await
            .expect("a failed event-bus publish must not fail revoke_device");

        assert_eq!(
            group_repo.list_pending_removals(&group_id).await.unwrap(),
            vec![device_id],
            "the durable pending removal must still be recorded when publish fails"
        );
    }
}
