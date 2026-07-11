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
	messages: ["ciphertextB64", "plaintextB64", "editedText", "reactionsJson"],
	groups: ["mlsStateB64"],
	verifiedContacts: ["safetyNumber"],
};

async function encRow<T extends object>(
	encryptor: FieldEncryptor,
	row: T,
	table: string,
): Promise<T> {
	const fields = SENSITIVE[table] ?? [];
	const result: Record<string, unknown> = { ...(row as Record<string, unknown>) };
	for (const field of fields) {
		const value = result[field];
		if (typeof value === "string") {
			result[field] = await encryptor.encryptDbField(value);
		}
	}
	return result as T;
}

async function decRow<T extends object>(
	encryptor: FieldEncryptor,
	row: T,
	table: string,
): Promise<T> {
	const fields = SENSITIVE[table] ?? [];
	const result: Record<string, unknown> = { ...(row as Record<string, unknown>) };
	for (const field of fields) {
		const value = result[field];
		if (typeof value === "string") {
			result[field] = await encryptor.decryptDbField(value);
		}
	}
	return result as T;
}

async function decOptional<T extends object>(
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

	/**
	 * Persist an "edit message" signal: stores the new text (encrypted at rest)
	 * against the existing row so a reload reflects the edit. No-op if the row
	 * does not exist locally (e.g. optimistic message not yet backfilled).
	 */
	async markMessageEdited(id: string, newTextB64: string): Promise<void> {
		const enc = await this.encryptor.encryptDbField(newTextB64);
		await this.db.messages.update(id, { editedText: enc });
	}

	/**
	 * Persist a "delete for everyone" signal: tombstones the row with a
	 * deletion timestamp so a reload keeps the message deleted.
	 */
	async markMessageDeleted(id: string): Promise<void> {
		await this.db.messages.update(id, { deletedAt: Date.now() });
	}

	/**
	 * Persist the current emoji reaction state for a message (encrypted at rest)
	 * so reactions survive a reload. Takes the full JSON-serialized senders map —
	 * callers pass the post-mutation state, not a diff. No-op if the row does not
	 * exist locally, same as markMessageEdited/markMessageDeleted.
	 */
	async markMessageReactions(id: string, reactionsJson: string): Promise<void> {
		const enc = await this.encryptor.encryptDbField(reactionsJson);
		await this.db.messages.update(id, { reactionsJson: enc });
	}

	async getMessagesByGroup(groupId: string): Promise<MessageRow[]> {
		const rows = await this.db.messages.where("groupId").equals(groupId).toArray();
		const decrypted = await Promise.all(rows.map((r) => decRow(this.encryptor, r, "messages")));
		// Sort ascending by receivedAt (wall-clock ms). Both incoming (epochSeq from
		// MLS, small integers) and outgoing (epochSeq = Date.now(), 13-digit ms) use
		// receivedAt so they interleave correctly — fixes Y1 epoch-namespace mismatch.
		// epochSeq is retained in each row for replay-detection at the WASM layer.
		return decrypted.sort((a, b) => a.receivedAt - b.receivedAt);
	}

	/**
	 * Delete all messages whose expiresAt is defined and in the past.
	 * Operates across all groups — suitable for background periodic sweeps.
	 * No decryption required: expiresAt is an unencrypted index field.
	 * @returns count of deleted rows.
	 */
	async purgeExpiredMessages(): Promise<number> {
		const now = Date.now();
		// belowOrEqual(now) covers all non-undefined numeric values ≤ now.
		// Rows with expiresAt = undefined have no index entry and are skipped.
		const expired = await this.db.messages.where("expiresAt").belowOrEqual(now).primaryKeys();
		await this.db.messages.bulkDelete(expired as string[]);
		return expired.length;
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

	/**
	 * Read the per-conversation disappearing timer for a group.
	 * disappearingTtlSeconds is not sensitive — reads directly from the raw row
	 * without decrypting mlsStateB64 (no wasted crypto ops).
	 */
	async getGroupDisappearingTtl(groupId: string): Promise<number | undefined> {
		const row = await this.db.groups.get(groupId);
		return row?.disappearingTtlSeconds;
	}

	/**
	 * Persist the per-conversation disappearing timer setting.
	 * Uses a partial Dexie update so mlsStateB64 (encrypted at rest) is never
	 * touched. Silently no-ops if the group row does not exist yet.
	 */
	async setGroupDisappearingTtl(groupId: string, ttl: number | undefined): Promise<void> {
		await this.db.groups.update(groupId, { disappearingTtlSeconds: ttl });
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
