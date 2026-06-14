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
}

// GroupRow — MLS group state snapshot.
export interface GroupRow {
	id: string; // MLS group UUID
	name: string;
	mlsStateB64: string; // serialized MLS group state
	lastActivity: number;
	/** Per-conversation disappearing timer in seconds. undefined = off. Not sensitive. */
	disappearingTtlSeconds?: number;
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
	}
}

export const db = new PowehiDb();
