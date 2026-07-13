import Dexie, { type Table } from "dexie";

// MessageRow — local encrypted storage.
// SECURITY: ciphertextB64 is the MLS application ciphertext from the wire.
// plaintextB64 is only populated after client-side decryption and is never
// transmitted to or received from the server.
export interface MessageRow {
	id: string; // UUID
	groupId: string; // MLS group UUID
	ciphertextB64: string; // base64 ciphertext — NEVER plaintext here
	senderDeviceId: string;
	epochSeq: number; // epoch<<32 | seq
	receivedAt: number; // Date.now()
	plaintextB64?: string; // only after decrypt — optional, user-clearable
	/** Unix ms at which this message expires (disappearing messages). undefined = no TTL. */
	expiresAt?: number;
	/** Latest edited text (base64 UTF-8), if this message was edited. Encrypted at rest like plaintextB64. */
	editedText?: string;
	/** Unix ms at which this message was tombstoned by a "delete for everyone" signal. undefined = not deleted. */
	deletedAt?: number;
	/** JSON-serialized emoji→senderDeviceId[] reaction map. Encrypted at rest like editedText. undefined = no reactions. */
	reactionsJson?: string;
}

// GroupRow — MLS group state snapshot.
export interface GroupRow {
	id: string; // MLS group UUID
	name: string; // user-visible conversation name — encrypted at rest, like message content
	/**
	 * Serialized MLS group state. No exporter for this exists yet (crypto-adjacent,
	 * not yet implemented) — writers currently persist "" as an explicit "not yet
	 * serialized" sentinel. Never treat "" as valid state to deserialize.
	 */
	mlsStateB64: string;
	lastActivity: number;
	/** Per-conversation disappearing timer in seconds. undefined = off. Not sensitive. */
	disappearingTtlSeconds?: number;
	/** id of the currently pinned MessageRow in this group, if any. Not sensitive — an opaque UUID reference, not content. */
	pinnedMessageId?: string;
	/** When true, incoming messages for this chat do not increment the unread badge. Local-only, never sent to server. */
	muted?: boolean;
	/** When false, incoming messages for this chat do not trigger notification sounds. Local-only, never sent to server. */
	sound?: boolean;
	/** When false, incoming messages for this chat do not trigger device vibration. Local-only, never sent to server. */
	vibrate?: boolean;
	/** Selected notification sound id for this chat. Opaque enum id, not content — not encrypted. undefined behaves as "default". */
	notificationSoundId?: string;
	/** Per-chat background theme key. Opaque enum key, not content — not encrypted. */
	chatTheme?: string;
}

// LocalIdentity — singleton device identity record.
// SECURITY: the OPAQUE export key is NOT stored here — it is session-lifetime only
// (held in the crypto worker). Re-authentication derives a fresh export key.
// mlsIdentityB64 stores the 16-byte BasicCredential identity bytes (RFC 9420 §5.3).
// These bytes are a PUBLIC label (included in KeyPackages); they are NOT a cryptographic
// secret and are safe to persist in IndexedDB.
export interface LocalIdentity {
	id: 1; // singleton
	deviceId: string;
	/** WASM MLS identity handle for the current session (re-generated each login). */
	mlsIdentityId?: string;
	/** base64(16-byte BasicCredential identity bytes) — public label, not a secret. */
	mlsIdentityB64?: string;
	/**
	 * ENCRYPTED JSON ENVELOPE: base64(AES-GCM(JSON.stringify({ stateB64, generation }))).
	 * Carries the full MLS context export from mls_export_state (identity + provider
	 * key store + every group). Closes the "MLS_CTX is a thread_local! that starts
	 * empty on every worker reload" gap (wasm_exports.rs). Contains live key material
	 * (Ed25519 signing key, MLS epoch secrets) — encrypted at rest, see
	 * db/encrypted-db.ts SENSITIVE.identity. NEVER read/write this field outside
	 * the EncryptedPowehiDb encrypted path (getMlsProviderState/setMlsProviderState).
	 *
	 * The bundled `generation` in THIS outer JSON envelope is an inert mirror of
	 * the same number that is separately embedded inside `stateB64` itself (see
	 * mls_group.rs `ProviderStateEnvelope.generation`). It is never used as a
	 * gate/decision input — Login.tsx's sign-in path reads it back only to
	 * re-persist it VERBATIM alongside the original stateB64 when a failed
	 * import is not allowed to discard the on-disk envelope (see Login.tsx's
	 * restore-on-failed-import comment); it is never compared against anything.
	 * It is NOT the security control; keeping it bundled in the same AEAD field
	 * as stateB64 (rather than a separate plaintext Dexie column) is defense-in-
	 * depth only — since it's never checked, a tampered copy would not by itself
	 * defeat anything. Do not mistake this field for the real freshness gate:
	 * see SCOPE below.
	 *
	 * SCOPE — what the ACTUAL generation check defends (read together with the
	 * useCryptoWorker.ts SECURITY header, which owns the import floor, and
	 * mls_group.rs, which owns the real comparison against the copy embedded
	 * inside stateB64):
	 *   • The import freshness gate (mls_import_state:
	 *     `state.generation < min_generation`) only rejects a blob below the
	 *     caller's floor, and the ONLY trustworthy floor is the worker's
	 *     in-session high-water-mark. On the first import of a fresh worker
	 *     (every reload / login) that floor is 0, so an authentic blob is never
	 *     rejected there.
	 *   • Therefore this counter does NOT prevent a wholesale replay of an entire
	 *     older-but-authentic envelope across a reload: an attacker with raw
	 *     IndexedDB write access who restores a captured older { ciphertext +
	 *     its own authentic generation } as one atomic unit is not defended
	 *     against — there is no monotonic hardware- or server-backed counter in
	 *     this client-only storage model to anchor the floor against (the
	 *     Delivery Service tracks only a per-group, client-driven, last-writer-
	 *     wins epoch with no login-time read endpoint). This residual risk is
	 *     accepted for this phase (threat-model-checker sign-off).
	 *   • Within a single live session it DOES prevent a second import from
	 *     rolling back below state already advanced this session.
	 */
	mlsProviderStateB64?: string;
}

// VerifiedContact — Safety Numbers verification state.
// Stores the safety number for a peer at the time the user verified it.
// When the MLS identity key changes (device re-registration) the stored
// safety number will no longer match the current one — alerting the user.
export interface VerifiedContact {
	contactId: string; // peer device ID or handle (opaque identifier)
	safetyNumber: string; // 12 six-digit groups: "689053 337949 ..." (prd.md §5.6)
	verifiedAt: number; // Date.now() timestamp in ms
}

export class PowehiDb extends Dexie {
	messages!: Table<MessageRow, string>;
	groups!: Table<GroupRow, string>;
	identity!: Table<LocalIdentity, 1>;
	verifiedContacts!: Table<VerifiedContact, string>;

	constructor() {
		super("PowehiDb");
		this.version(1).stores({
			messages: "id, groupId, epochSeq, receivedAt",
			groups: "id, lastActivity",
			identity: "id",
		});
		this.version(2).stores({
			messages: "id, groupId, epochSeq, receivedAt",
			groups: "id, lastActivity",
			identity: "id",
			verifiedContacts: "contactId, verifiedAt",
		});
		// v3: removed LocalIdentity.exportKeyB64 — OPAQUE export key must not be
		// persisted to IndexedDB (crypto-reviewer R1). No index change needed.
		this.version(3).stores({
			messages: "id, groupId, epochSeq, receivedAt",
			groups: "id, lastActivity",
			identity: "id",
			verifiedContacts: "contactId, verifiedAt",
		});
		// v4: added mlsIdentityId and mlsIdentityB64 to LocalIdentity — allows
		// MLS state to be re-initialised on login without generating a new identity.
		// No index change needed (identity table is singleton, keyed by id=1).
		this.version(4).stores({
			messages: "id, groupId, epochSeq, receivedAt",
			groups: "id, lastActivity",
			identity: "id",
			verifiedContacts: "contactId, verifiedAt",
		});
		// v5: added expiresAt to MessageRow for disappearing messages (prd.md §9.4.3).
		// Indexed so purgeExpiredMessages() can use a range query instead of full scan.
		this.version(5).stores({
			messages: "id, groupId, epochSeq, receivedAt, expiresAt",
			groups: "id, lastActivity",
			identity: "id",
			verifiedContacts: "contactId, verifiedAt",
		});
		// v6: added disappearingTtlSeconds to GroupRow — per-conversation timer
		// setting (prd.md §9.4.3). Not sensitive (bounded enum, not content); not indexed.
		this.version(6).stores({
			messages: "id, groupId, epochSeq, receivedAt, expiresAt",
			groups: "id, lastActivity",
			identity: "id",
			verifiedContacts: "contactId, verifiedAt",
		});
		// v7: added editedText and deletedAt to MessageRow so "edit message" and
		// "delete for everyone" state survives a reload (previously React-state-only).
		this.version(7).stores({
			messages: "id, groupId, epochSeq, receivedAt, expiresAt",
			groups: "id, lastActivity",
			identity: "id",
			verifiedContacts: "contactId, verifiedAt",
		});
		// v8: added reactionsJson to MessageRow so emoji reactions survive a reload
		// (previously React-state-only, same gap edit/delete had before v7). No index
		// change needed — reactions are never queried by Dexie, only read per-row.
		this.version(8).stores({
			messages: "id, groupId, epochSeq, receivedAt, expiresAt",
			groups: "id, lastActivity",
			identity: "id",
			verifiedContacts: "contactId, verifiedAt",
		});
		// v9: added pinnedMessageId to GroupRow so a pinned message survives a reload
		// (previously React-state-only, same gap edit/delete/reactions had before v7/v8).
		// Not sensitive (opaque UUID reference, like disappearingTtlSeconds); not indexed —
		// only ever read/written per-group, never queried across groups.
		this.version(9).stores({
			messages: "id, groupId, epochSeq, receivedAt, expiresAt",
			groups: "id, lastActivity",
			identity: "id",
			verifiedContacts: "contactId, verifiedAt",
		});
		// v10: added mlsProviderStateB64 and mlsProviderStateGeneration to LocalIdentity —
		// persists the full MLS context (identity + provider key store + every group) across
		// a worker reload/re-login, fixing "every MLS group's state is wiped on every page
		// reload" (mls_export_state/mls_import_state, wasm_exports.rs). mlsProviderStateB64
		// is encrypted at rest (see db/encrypted-db.ts SENSITIVE.identity) — no index change
		// needed (identity table remains a singleton keyed by id=1). GroupRow.mlsStateB64 is
		// intentionally left untouched — it is a pre-existing unused placeholder, not this field.
		this.version(10).stores({
			messages: "id, groupId, epochSeq, receivedAt, expiresAt",
			groups: "id, lastActivity",
			identity: "id",
			verifiedContacts: "contactId, verifiedAt",
		});
		// v11: removed LocalIdentity.mlsProviderStateGeneration as an independent
		// top-level column (crypto-reviewer finding 2, RED — see mlsProviderStateB64
		// doc comment above). The generation counter is now bundled INSIDE the
		// encrypted mlsProviderStateB64 envelope (JSON.stringify({ stateB64,
		// generation }), encrypted as one AES-GCM field) so it can no longer be
		// independently rolled back by an attacker with raw IndexedDB write access.
		// No .stores() index change needed — mlsProviderStateGeneration was never
		// indexed (identity table stays "id" only); this version bump exists solely
		// to document the LocalIdentity shape change for anyone diffing schema history.
		this.version(11).stores({
			messages: "id, groupId, epochSeq, receivedAt, expiresAt",
			groups: "id, lastActivity",
			identity: "id",
			verifiedContacts: "contactId, verifiedAt",
		});
		// v12: added muted, sound, vibrate, notificationSoundId, chatTheme to GroupRow —
		// these per-chat local preferences (previously React-state-only, same gap edit/
		// delete/reactions/pin had before v7-v9) now survive a reload. None are sensitive
		// (bounded booleans/opaque enum ids, like disappearingTtlSeconds/pinnedMessageId);
		// no index change needed — never queried across groups, only read/written per-group.
		this.version(12).stores({
			messages: "id, groupId, epochSeq, receivedAt, expiresAt",
			groups: "id, lastActivity",
			identity: "id",
			verifiedContacts: "contactId, verifiedAt",
		});
	}
}

export const db = new PowehiDb();
