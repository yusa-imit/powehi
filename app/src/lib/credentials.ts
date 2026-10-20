/**
 * Handle and password canonicalisation (Phase 8 item 8.6, issue #19). Mirrors the Rust
 * `powehi_crypto_core::credentials`; both run docs/test-vectors/credential-normalization.json.
 *
 * - Handle: trim Unicode White_Space + U+FEFF. New accounts must match [a-z0-9-]{1,64};
 *   login accepts any trimmed handle so older accounts keep working.
 * - Password: Unicode NFC only (no trim, no NFKC). `passwordCandidates` adds the raw input
 *   as a second attempt for accounts registered before NFC.
 */

export const MAX_HANDLE_LEN = 64;

// Unicode White_Space (what Rust's char::is_whitespace uses) plus U+FEFF. JS String.trim
// differs (it lacks U+0085), so the set is spelled out.
const EDGE_SPACE =
	"[\\u0009-\\u000D\\u0020\\u0085\\u00A0\\u1680\\u2000-\\u200A\\u2028\\u2029\\u202F\\u205F\\u3000\\uFEFF]";
const EDGE_RE = new RegExp(`^${EDGE_SPACE}+|${EDGE_SPACE}+$`, "gu");

export type HandleError = "empty" | "too_long" | "bad_character";

export function trimHandle(raw: string): string {
	return raw.replace(EDGE_RE, "");
}

/** The canonical handle for a new account, or why it cannot be used. */
export function registrableHandle(
	raw: string,
): { ok: true; handle: string } | { ok: false; error: HandleError } {
	const handle = trimHandle(raw);
	if (handle.length === 0) return { ok: false, error: "empty" };
	if (!/^[a-z0-9-]+$/.test(handle)) return { ok: false, error: "bad_character" };
	if (handle.length > MAX_HANDLE_LEN) return { ok: false, error: "too_long" };
	return { ok: true, handle };
}

export function nfcPassword(raw: string): string {
	return raw.normalize("NFC");
}

/** Passwords to try at login, in order: NFC, then the raw input when it differs. */
export function passwordCandidates(raw: string): string[] {
	const nfc = nfcPassword(raw);
	return nfc === raw ? [nfc] : [nfc, raw];
}

export const HANDLE_ERROR_TEXT: Record<HandleError, string> = {
	empty: "Handle is required.",
	too_long: `Handle must be at most ${MAX_HANDLE_LEN} characters.`,
	bad_character: "Handle may contain only lowercase a-z, 0-9 and '-'.",
};

/** The OPAQUE client rejected the password (login/finish failed locally, before the server). */
export class CredentialRejected extends Error {
	constructor(readonly cause: unknown) {
		super("credential_rejected");
	}
}
