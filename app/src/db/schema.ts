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
}

// GroupRow — MLS group state snapshot.
export interface GroupRow {
	id: string; // MLS group UUID
	name: string;
	mlsStateB64: string; // serialized MLS group state
	lastActivity: number;
}

// LocalIdentity — singleton device identity record.
export interface LocalIdentity {
	id: 1; // singleton
	deviceId: string;
	exportKeyB64: string; // OPAQUE export key (used to derive encryption keys)
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
	}
}

export const db = new PowehiDb();
