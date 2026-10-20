import { describe, expect, it } from "vitest";
import vectors from "../../../docs/test-vectors/credential-normalization.json";
import {
	MAX_HANDLE_LEN,
	nfcPassword,
	passwordCandidates,
	registrableHandle,
	trimHandle,
} from "./credentials";

describe("credential normalization (shared vectors with powehi-crypto-core)", () => {
	it("handle vectors", () => {
		expect(vectors.handles.length).toBeGreaterThanOrEqual(10);
		for (const c of vectors.handles) {
			expect(trimHandle(c.input)).toBe(c.trimmed);
			expect(registrableHandle(c.input).ok).toBe(c.registrable);
		}
	});

	it("password vectors", () => {
		expect(vectors.passwords.length).toBeGreaterThanOrEqual(5);
		for (const c of vectors.passwords) {
			expect(nfcPassword(c.input)).toBe(c.nfc);
			expect(nfcPassword(nfcPassword(c.input))).toBe(c.nfc);
		}
	});

	it("handle error kinds and length bound", () => {
		expect(registrableHandle("  ")).toEqual({ ok: false, error: "empty" });
		expect(registrableHandle("Ab")).toEqual({ ok: false, error: "bad_character" });
		expect(registrableHandle("a".repeat(MAX_HANDLE_LEN)).ok).toBe(true);
		expect(registrableHandle("a".repeat(MAX_HANDLE_LEN + 1))).toEqual({
			ok: false,
			error: "too_long",
		});
	});

	it("candidates: NFC first, raw only when different", () => {
		expect(passwordCandidates("café")).toEqual(["café", "café"]);
		expect(passwordCandidates("plain")).toEqual(["plain"]);
	});
});
