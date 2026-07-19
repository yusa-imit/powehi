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
// identity.mlsProviderStateB64 (added schema v10, envelope shape changed v11) carries
// live MLS key material (Ed25519 signing key + epoch secrets, see mls_export_state),
// with a companion `generation` value bundled into the same JSON.stringify({
// stateB64, generation }) plaintext before a single encryptDbField call — see
// setMlsProviderState/getMlsProviderState below and schema.ts's doc comment.
// NOTE (crypto-reviewer finding Y3): this envelope-level `generation` is inert
// bookkeeping, not a security control — it is never used as a gate/decision
// input (Login.tsx reads it back only to re-persist it verbatim on a failed-
// import restore; it is never compared against anything). The REAL freshness
// gate compares the generation embedded INSIDE stateBytes (checked by
// mls_import_state against useCryptoWorker.ts's in-session currentGeneration
// floor); bundling this outer field alongside stateB64 only means it can't be
// edited independently of the ciphertext, not that anything
// currently relies on it being correct. deviceId/mlsIdentityId/mlsIdentityB64
// remain unencrypted — mlsIdentityB64 is a documented public label, not a
// secret (schema.ts).
const SENSITIVE: Record<string, readonly string[]> = {
	messages: ["ciphertextB64", "plaintextB64", "editedText", "reactionsJson"],
	groups: ["mlsStateB64", "name"],
	identity: ["mlsProviderStateB64"],
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

	/**
	 * Persist a "delivery receipt" signal: marks the row delivered so a reload
	 * keeps showing the delivered indicator. No-op if the row does not exist
	 * locally, same as markMessageEdited/markMessageDeleted.
	 */
	async markMessageDelivered(id: string): Promise<void> {
		await this.db.messages.update(id, { delivered: true });
	}

	/**
	 * Persist a "read receipt" signal: marks the row read and unions `readBy`
	 * into the currently-persisted reader set rather than overwriting it.
	 * Callers compute `readBy` from a possibly-stale in-memory snapshot, so two
	 * read_receipts for the same message from different devices arriving in
	 * quick succession could previously race and have the later write clobber
	 * the earlier one's entry (security-auditor YELLOW, cycle 321). Reading the
	 * persisted row and writing the merged set inside one Dexie transaction
	 * closes that race: IndexedDB serializes readwrite transactions on the same
	 * store, so the second transaction's read always observes the first
	 * transaction's committed write. No-op if the row does not exist locally.
	 */
	async markMessageRead(id: string, readBy: string[]): Promise<void> {
		await this.db.transaction("rw", this.db.messages, async () => {
			const row = await this.db.messages.get(id);
			if (!row) return;
			let existing: string[] = [];
			if (row.readByJson) {
				try {
					existing = JSON.parse(row.readByJson) as string[];
				} catch {
					existing = [];
				}
			}
			const merged = Array.from(new Set([...existing, ...readBy]));
			await this.db.messages.update(id, { read: true, readByJson: JSON.stringify(merged) });
		});
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
		const enc = await encRow(this.encryptor, row, "identity");
		await this.db.identity.put(enc);
	}

	async getIdentity(): Promise<LocalIdentity | undefined> {
		const row = await this.db.identity.get(1);
		return decOptional(this.encryptor, row, "identity");
	}

	/**
	 * Persist a fresh MLS provider-state export (mls_export_state) against the
	 * identity singleton row, encrypted at rest.
	 *
	 * SECURITY: `stateB64` and `generation` are JSON-encoded together into ONE
	 * string and passed through encryptDbField ONCE, so both are covered by the
	 * same AES-GCM authentication tag — this envelope-level `generation` cannot
	 * be edited independently of the ciphertext without forging the AEAD tag.
	 * That said, it is inert bookkeeping, NOT the mechanism enforcing the
	 * anti-replay gate: getMlsProviderState's caller (Login.tsx) reads this
	 * field back only to re-persist it verbatim on a failed-import restore —
	 * it is never compared against anything. The real freshness check compares
	 * the generation embedded INSIDE stateBytes against useCryptoWorker.ts's
	 * in-session currentGeneration floor, which is only meaningful in-session
	 * (0 on the first import after a reload). It does NOT defend against wholesale
	 * replay of an entire older-but-authentic envelope; see schema.ts's
	 * mlsProviderStateB64 SCOPE note and useCryptoWorker.ts's SECURITY header.
	 *
	 * Uses a partial Dexie update (not put) so deviceId/mlsIdentityId/
	 * mlsIdentityB64 are never touched by a persist that only has the exported
	 * blob + generation, not the full LocalIdentity row. No-op if the identity
	 * row does not exist yet — callers only invoke this after an MLS identity
	 * is already established, so the row is normally present; if it is not
	 * (e.g. a persist attempt racing before the identity row's first write),
	 * this silently does nothing rather than throwing.
	 */
	async setMlsProviderState(stateB64: string, generation: number): Promise<void> {
		const envelope = JSON.stringify({ stateB64, generation });
		const encrypted = await this.encryptor.encryptDbField(envelope);
		await this.db.identity.update(1, { mlsProviderStateB64: encrypted });
	}

	/**
	 * Read back the MLS provider-state envelope persisted by setMlsProviderState,
	 * decrypting the single AES-GCM field and JSON-parsing the bundled
	 * { stateB64, generation } pair. Returns undefined if no identity row exists
	 * yet, or no provider-state envelope has ever been persisted.
	 *
	 * Throws if the ciphertext fails AES-GCM authentication (tampered/wrong key)
	 * or the decrypted plaintext is not valid JSON (corrupt/pre-v11 legacy
	 * shape) — callers MUST catch this and fall back to re-deriving MLS state
	 * from scratch (see Login.tsx's sign-in rehydration path), never crash on it.
	 */
	async getMlsProviderState(): Promise<{ stateB64: string; generation: number } | undefined> {
		const row = await this.db.identity.get(1);
		const raw = row?.mlsProviderStateB64;
		if (typeof raw !== "string") return undefined;
		const decrypted = await this.encryptor.decryptDbField(raw);
		const parsed = JSON.parse(decrypted) as { stateB64: string; generation: number };
		return parsed;
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
