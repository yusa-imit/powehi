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

export class PowehiDb extends Dexie {
	messages!: Table<MessageRow, string>;
	groups!: Table<GroupRow, string>;
	identity!: Table<LocalIdentity, 1>;

	constructor() {
		super("PowehiDb");
		this.version(1).stores({
			messages: "id, groupId, epochSeq, receivedAt",
			groups: "id, lastActivity",
			identity: "id",
		});
	}
}

export const db = new PowehiDb();
