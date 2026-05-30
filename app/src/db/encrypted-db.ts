// EncryptedPowehiDb — explicit encryption wrapper over PowehiDb.
//
// Sensitive fields are AES-GCM encrypted at rest before indexedDB writes
// and decrypted after reads.  Indexed fields (UUIDs, timestamps) remain in
// plaintext so Dexie can use them for query operations.
//
// Pass the Comlink crypto-worker proxy as the `encryptor` argument so that
// the CryptoKey never crosses into the main thread (react-hooks-only.md).
// Tests use DirectFieldEncryptor from encryption.ts for isolation.

import type { FieldEncryptor } from "./encryption";
import type { GroupRow, LocalIdentity, MessageRow, VerifiedContact } from "./schema";
import type { PowehiDb } from "./schema";

// Per-table list of fields encrypted at rest.
// Indexed fields (id, groupId, epochSeq, receivedAt, contactId, verifiedAt, lastActivity)
// MUST NOT appear here — Dexie cannot query encrypted index values.
// identity has no sensitive unindexed fields (exportKeyB64 was removed in schema v3).
const SENSITIVE: Record<string, readonly string[]> = {
	messages: ["ciphertextB64", "plaintextB64"],
	groups: ["mlsStateB64"],
	verifiedContacts: ["safetyNumber"],
};

async function encRow<T extends Record<string, unknown>>(
	encryptor: FieldEncryptor,
	row: T,
	table: string,
): Promise<T> {
	const fields = SENSITIVE[table] ?? [];
	const result: Record<string, unknown> = { ...row };
	for (const field of fields) {
		const value = result[field];
		if (typeof value === "string") {
			result[field] = await encryptor.encryptDbField(value);
		}
	}
	return result as T;
}

async function decRow<T extends Record<string, unknown>>(
	encryptor: FieldEncryptor,
	row: T,
	table: string,
): Promise<T> {
	const fields = SENSITIVE[table] ?? [];
	const result: Record<string, unknown> = { ...row };
	for (const field of fields) {
		const value = result[field];
		if (typeof value === "string") {
			result[field] = await encryptor.decryptDbField(value);
		}
	}
	return result as T;
}

async function decOptional<T extends Record<string, unknown>>(
	encryptor: FieldEncryptor,
	row: T | undefined,
	table: string,
): Promise<T | undefined> {
	if (row === undefined) return undefined;
	return decRow(encryptor, row, table);
}

/**
 * Wraps PowehiDb with transparent AES-GCM-256 field encryption.
 *
 * All reads and writes go through this class in authenticated sessions.
 * The CryptoKey lives entirely inside the crypto worker (prd.md §5.1);
 * this class never holds or observes raw key material.
 *
 * Pass the Comlink crypto-worker proxy as `encryptor`. Construction is cheap (no I/O).
 * Pass the same `PowehiDb` instance shared across the app.
 */
export class EncryptedPowehiDb {
	constructor(
		private db: PowehiDb,
		private encryptor: FieldEncryptor,
	) {}

	// ── Messages ───────────────────────────────────────────────────────────────

	async addMessage(row: MessageRow): Promise<void> {
		const enc = await encRow(this.encryptor, row, "messages");
		await this.db.messages.add(enc);
	}

	async putMessage(row: MessageRow): Promise<void> {
		const enc = await encRow(this.encryptor, row, "messages");
		await this.db.messages.put(enc);
	}

	async getMessage(id: string): Promise<MessageRow | undefined> {
		const row = await this.db.messages.get(id);
		return decOptional(this.encryptor, row, "messages");
	}

	async getMessagesByGroup(groupId: string): Promise<MessageRow[]> {
		const rows = await this.db.messages.where("groupId").equals(groupId).toArray();
		const decrypted = await Promise.all(rows.map((r) => decRow(this.encryptor, r, "messages")));
		// Sort ascending by epochSeq — MLS replay detection depends on monotonic
		// epoch order (RFC 9420 §6.3.1); ordering after decrypt preserves this guarantee.
		return decrypted.sort((a, b) => a.epochSeq - b.epochSeq);
	}

	// ── Groups ─────────────────────────────────────────────────────────────────

	async addGroup(row: GroupRow): Promise<void> {
		const enc = await encRow(this.encryptor, row, "groups");
		await this.db.groups.add(enc);
	}

	async putGroup(row: GroupRow): Promise<void> {
		const enc = await encRow(this.encryptor, row, "groups");
		await this.db.groups.put(enc);
	}

	async getGroup(id: string): Promise<GroupRow | undefined> {
		const row = await this.db.groups.get(id);
		return decOptional(this.encryptor, row, "groups");
	}

	async getAllGroups(): Promise<GroupRow[]> {
		const rows = await this.db.groups.toArray();
		return Promise.all(rows.map((r) => decRow(this.encryptor, r, "groups")));
	}

	// ── Identity ───────────────────────────────────────────────────────────────

	async setIdentity(row: LocalIdentity): Promise<void> {
		await this.db.identity.put(row);
	}

	async getIdentity(): Promise<LocalIdentity | undefined> {
		return this.db.identity.get(1);
	}

	// ── VerifiedContacts ───────────────────────────────────────────────────────

	async putVerifiedContact(row: VerifiedContact): Promise<void> {
		const enc = await encRow(this.encryptor, row, "verifiedContacts");
		await this.db.verifiedContacts.put(enc);
	}

	async getVerifiedContact(contactId: string): Promise<VerifiedContact | undefined> {
		const row = await this.db.verifiedContacts.get(contactId);
		return decOptional(this.encryptor, row, "verifiedContacts");
	}

	async deleteVerifiedContact(contactId: string): Promise<void> {
		await this.db.verifiedContacts.delete(contactId);
	}
}
