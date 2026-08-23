// EncryptedPowehiDb — explicit encryption wrapper over PowehiDb.
//
// Sensitive fields are AES-GCM encrypted at rest before indexedDB writes
// and decrypted after reads.  Indexed fields (UUIDs, timestamps) remain in
// plaintext so Dexie can use them for query operations.
//
// Pass the Comlink crypto-worker proxy as the `encryptor` argument so that
// the CryptoKey never crosses into the main thread (react-hooks-only.md).
// Tests use DirectFieldEncryptor from encryption.ts for isolation.

import Dexie from "dexie";
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
	messages: [
		"ciphertextB64",
		"plaintextB64",
		"editedText",
		"reactionsJson",
		"pollJson",
		"replyToJson",
	],
	groups: ["mlsStateB64", "name", "draft", "description", "nickname"],
	identity: ["mlsProviderStateB64", "customStatusEmoji", "customStatusText"],
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
	 * Persist a single sender's add/remove of one emoji reaction, merged against the
	 * currently-persisted reaction map rather than overwritten wholesale. Callers used
	 * to pass the full post-mutation map computed from a possibly-stale in-memory
	 * snapshot — two reactions to the same message from different devices in quick
	 * succession could race and have the later write clobber the earlier one's entry
	 * (same class of bug as markMessageRead's readBy, security-auditor YELLOW cycle
	 * 321; deferred for reactions at the time, now closed the same way).
	 *
	 * reactionsJson is encrypted at rest (SENSITIVE.messages), so the merge requires
	 * an async crypto-worker round-trip inside the transaction. `Dexie.waitFor` tells
	 * Dexie to keep the IndexedDB transaction open across that non-Dexie await instead
	 * of letting it auto-commit early (the risk `claimScheduledFire` above avoids by
	 * doing its crypto work outside the transaction — not an option here since the
	 * read-modify-write itself must happen on the decrypted value). IndexedDB still
	 * serializes readwrite transactions on the same store, so the second caller's
	 * `get` always observes the first caller's committed `update`. No-op if the row
	 * does not exist locally, same as markMessageEdited/markMessageDeleted.
	 *
	 * NOTE (security-auditor, cycle 344): this only closes the race between concurrent
	 * markMessageReactionDelta calls. `putMessage` is a full-row upsert (encrypted
	 * outside any transaction) and callers build fresh rows with `reactionsJson:
	 * undefined` — a duplicate/replayed persistIncoming for an id that already has
	 * reactions can still wipe this field. Pre-existing, out of scope here.
	 */
	async markMessageReactionDelta(
		id: string,
		emoji: string,
		senderId: string,
		action: "add" | "remove",
	): Promise<void> {
		await this.db.transaction("rw", this.db.messages, async () => {
			const row = await this.db.messages.get(id);
			if (!row) return;
			let reactions: Record<string, string[]> = {};
			if (row.reactionsJson) {
				const plaintext = await Dexie.waitFor(this.encryptor.decryptDbField(row.reactionsJson));
				try {
					reactions = JSON.parse(plaintext) as Record<string, string[]>;
				} catch {
					reactions = {};
				}
			}
			const senders = reactions[emoji] ?? [];
			const alreadyIn = senders.includes(senderId);
			if (action === "add" && alreadyIn) return;
			if (action === "remove" && !alreadyIn) return;
			const nextSenders =
				action === "add" ? [...senders, senderId] : senders.filter((s) => s !== senderId);
			const nextReactions = { ...reactions };
			if (nextSenders.length === 0) {
				delete nextReactions[emoji];
			} else {
				nextReactions[emoji] = nextSenders;
			}
			const enc = await Dexie.waitFor(this.encryptor.encryptDbField(JSON.stringify(nextReactions)));
			await this.db.messages.update(id, { reactionsJson: enc });
		});
	}

	/**
	 * Persist the current poll state (question + option vote lists, JSON-serialized,
	 * encrypted at rest) so a group poll and its votes survive a reload. Takes the full
	 * post-mutation poll (a "callers pass post-mutation state, not a diff" contract) —
	 * unlike markMessageReactionDelta, which merges a single add/remove against the
	 * persisted state. No-op if the row does not exist locally.
	 */
	async markMessagePoll(id: string, pollJson: string): Promise<void> {
		const enc = await this.encryptor.encryptDbField(pollJson);
		await this.db.messages.update(id, { pollJson: enc });
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

	/**
	 * Persist the star/bookmark toggle for a message so it survives a reload.
	 * Unlike markMessageDelivered (one-way true), this takes an explicit value
	 * since starring is a user-toggleable flag that can go back to false.
	 * No-op if the row does not exist locally, same as markMessageEdited/markMessageDeleted.
	 */
	async markMessageStarred(id: string, starred: boolean): Promise<void> {
		await this.db.messages.update(id, { starred });
	}

	/**
	 * Persist a "fired" scheduled message: clears scheduledFor so a reload no longer shows
	 * the scheduled badge / offers cancel. No-op if the row does not exist locally, same as
	 * markMessageEdited/markMessageDeleted. Does not touch ciphertextB64/plaintextB64 — a
	 * real MLS send-on-fire, if/when implemented, is a separate write.
	 */
	async clearMessageScheduled(id: string): Promise<void> {
		await this.db.messages.update(id, { scheduledFor: undefined });
	}

	/**
	 * Delete a message row outright. Used for "cancel scheduled message" — unlike
	 * markMessageDeleted (which tombstones a sent message so peers' delete-for-everyone
	 * stays visible), a cancelled scheduled message never had an MLS envelope and never
	 * left this device, so there is nothing to tombstone — the row is simply removed.
	 *
	 * SECURITY (security-auditor finding, cycle 339): this is the only hard-delete in this
	 * class — every other message mutation here is a tombstone/update, and cancelScheduled's
	 * caller-side gate (only offered in the UI while `scheduledFor` is set) is the sole thing
	 * that would otherwise stop a bare-id call from destroying a real MLS message's history.
	 * Defense-in-depth: only actually deletes when the row is still a not-yet-fired scheduled
	 * message (`scheduledFor` set); no-ops on any other row, same "no-op on missing/ineligible
	 * row" contract as markMessageEdited/markMessageDeleted.
	 */
	async deleteMessage(id: string): Promise<void> {
		const row = await this.db.messages.get(id);
		if (!row || row.scheduledFor === undefined) return;
		await this.db.messages.delete(id);
	}

	/**
	 * Atomically "claim" a scheduled message for firing: inside a single Dexie readwrite
	 * transaction, read the row and delete it if — and only if — `scheduledFor` is still set,
	 * returning the pre-delete, decrypted row. Returns undefined if the row is missing or was
	 * already claimed/cancelled/fired, by this tab or any other same-origin tab. The row is
	 * deleted (not merely updated) because a successful claim always leads to a brand-new row
	 * being written under the server-assigned envelope id (persistOutgoing) — there is nothing
	 * left for the local `sched_...`-keyed row to represent once claimed.
	 *
	 * SECURITY (crypto-reviewer finding, cycle 341): a bare "read scheduledFor, then later
	 * encrypt+send, then delete the row" sequence is a TOCTOU — every open tab runs its own
	 * fire sweep against its own Dexie-rehydrated snapshot, and the window between the read and
	 * the eventual delete spans a full mlsEncrypt + network round trip (which can exceed the
	 * sweep interval), during which this SAME scheduled message could be claimed twice (this
	 * tab's own overlapping sweep ticks, or another same-origin tab). IndexedDB serializes
	 * readwrite transactions on the same store, so wrapping the check-and-delete in one
	 * transaction makes it an actual claim: at most one caller across all tabs ever observes
	 * `scheduledFor` still set for a given id and receives a defined row back — the same
	 * argument markMessageRead already relies on for its own cross-device race. Scheduled rows
	 * are local-only until fired (never synced across devices, see persistScheduledCreate), so
	 * this claim's same-origin-tab scope is the complete threat surface for double-firing THIS
	 * message — there is no separate device with its own copy to race against. This is
	 * narrower than (and does not by itself resolve) the general cross-tab cloned-MLS-state
	 * concern: every open tab imports its own independent copy of the group's sender ratchet
	 * (useCryptoWorker.ts), and that pre-existing property applies equally to every other send
	 * path in this app (typing indicators, presence, regular sendMessage) — this claim closes
	 * "this message sent twice," not "two tabs' independent ratchet copies diverge." Also note
	 * RFC 9420 §6.3.2's per-message `reuse_guard` means a bare generation collision across two
	 * independently-derived ratchet copies is not automatically nonce reuse — treat that as a
	 * separate, pre-existing, unresolved risk class, not something introduced or fixed here.
	 * If the subsequent encrypt/send fails after a successful claim, the row is simply gone
	 * (no retry) — this is a UX gap (message silently never sends), not a safety requirement:
	 * re-encrypting/retrying the already-claimed plaintext in memory would be safe (each
	 * mlsEncrypt call advances the sender ratchet, so re-sending after a failed attempt is not
	 * a nonce/key reuse). Not implemented, matching sendMessage's own "no failed-message retry
	 * UI yet" scope.
	 *
	 * Decryption happens AFTER the transaction resolves, not inside it — the encryptor is an
	 * async Comlink round-trip, and awaiting non-Dexie-tracked work inside a Dexie transaction
	 * callback risks Dexie closing the transaction early ("transaction inactive"). Only the
	 * synchronous get+delete pair (gated on `scheduledFor`, which is not in SENSITIVE.messages)
	 * needs to be inside the atomic boundary.
	 */
	async claimScheduledFire(id: string): Promise<MessageRow | undefined> {
		const claimed = await this.db.transaction("rw", this.db.messages, async () => {
			const row = await this.db.messages.get(id);
			if (!row || row.scheduledFor === undefined) return undefined;
			await this.db.messages.delete(id);
			return row;
		});
		return decOptional(this.encryptor, claimed, "messages");
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

	/**
	 * Persist the per-conversation unsent composer draft (encrypted at rest — this is
	 * real unsent message content, same sensitivity tier as name/editedText, unlike the
	 * plain per-group preference fields above). Pass undefined to clear. Uses a partial
	 * Dexie update so mlsStateB64/name are never touched. No-op if the group row does
	 * not exist yet.
	 */
	async setGroupDraft(groupId: string, draft: string | undefined): Promise<void> {
		// Runs inside an explicit Dexie transaction so the encrypt-then-write stays one
		// atomic unit. Dexie.waitFor() is required around the non-Dexie encryptor await —
		// without it, Dexie has no way to know the transaction is still "in use" while
		// waiting on an external promise and will commit early (PrematureCommitError).
		await this.db.transaction("rw", this.db.groups, async () => {
			const enc =
				draft === undefined ? undefined : await Dexie.waitFor(this.encryptor.encryptDbField(draft));
			await this.db.groups.update(groupId, { draft: enc });
		});
	}

	/**
	 * Read and decrypt the per-conversation unsent composer draft.
	 */
	async getGroupDraft(groupId: string): Promise<string | undefined> {
		const row = await this.db.groups.get(groupId);
		if (!row?.draft) return undefined;
		return this.encryptor.decryptDbField(row.draft);
	}

	/**
	 * Persist the group description / topic text (encrypted at rest — real user-authored
	 * content, same sensitivity tier as name/draft). Pass undefined to clear. Uses a
	 * partial Dexie update so mlsStateB64/name/draft are never touched. No-op if the
	 * group row does not exist yet.
	 */
	async setGroupDescription(groupId: string, description: string | undefined): Promise<void> {
		await this.db.transaction("rw", this.db.groups, async () => {
			const enc =
				description === undefined
					? undefined
					: await Dexie.waitFor(this.encryptor.encryptDbField(description));
			await this.db.groups.update(groupId, { description: enc });
		});
	}

	/**
	 * Read and decrypt the group description / topic text.
	 */
	async getGroupDescription(groupId: string): Promise<string | undefined> {
		const row = await this.db.groups.get(groupId);
		if (!row?.description) return undefined;
		return this.encryptor.decryptDbField(row.description);
	}

	/**
	 * Persist the custom DM contact nickname (encrypted at rest — real user-authored
	 * content, same sensitivity tier as name/draft/description). Pass undefined to clear.
	 * Uses a partial Dexie update so mlsStateB64/name/draft/description are never touched.
	 * No-op if the group row does not exist yet.
	 */
	async setGroupNickname(groupId: string, nickname: string | undefined): Promise<void> {
		await this.db.transaction("rw", this.db.groups, async () => {
			const enc =
				nickname === undefined
					? undefined
					: await Dexie.waitFor(this.encryptor.encryptDbField(nickname));
			await this.db.groups.update(groupId, { nickname: enc });
		});
	}

	/**
	 * Read and decrypt the custom DM contact nickname.
	 */
	async getGroupNickname(groupId: string): Promise<string | undefined> {
		const row = await this.db.groups.get(groupId);
		if (!row?.nickname) return undefined;
		return this.encryptor.decryptDbField(row.nickname);
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

	/**
	 * Persist the user-global custom status (emoji + text, encrypted at rest — real
	 * user-authored content, same sensitivity tier as GroupRow.nickname/description).
	 * Pass null to clear both fields. Uses a partial Dexie update so deviceId/
	 * mlsIdentityId/mlsIdentityB64/mlsProviderStateB64 are never touched. No-op if the
	 * identity row does not exist yet.
	 */
	async setCustomStatus(status: { emoji: string; text: string } | null): Promise<void> {
		await this.db.transaction("rw", this.db.identity, async () => {
			if (status === null) {
				await this.db.identity.update(1, {
					customStatusEmoji: undefined,
					customStatusText: undefined,
				});
				return;
			}
			const encEmoji = status.emoji
				? await Dexie.waitFor(this.encryptor.encryptDbField(status.emoji))
				: undefined;
			const encText = status.text
				? await Dexie.waitFor(this.encryptor.encryptDbField(status.text))
				: undefined;
			await this.db.identity.update(1, { customStatusEmoji: encEmoji, customStatusText: encText });
		});
	}

	/**
	 * Read and decrypt the user-global custom status. Returns null if no identity row
	 * exists yet, or no status is currently set (mirrors the in-memory `CustomStatus` shape
	 * — never an empty-string placeholder).
	 */
	async getCustomStatus(): Promise<{ emoji: string; text: string } | null> {
		const row = await this.db.identity.get(1);
		if (!row) return null;
		const emoji = row.customStatusEmoji
			? await this.encryptor.decryptDbField(row.customStatusEmoji)
			: "";
		const text = row.customStatusText
			? await this.encryptor.decryptDbField(row.customStatusText)
			: "";
		if (!emoji && !text) return null;
		return { emoji, text };
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
