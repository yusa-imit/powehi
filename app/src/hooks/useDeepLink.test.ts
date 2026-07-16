import { describe, expect, it } from "vitest";
import { parseDeepLink } from "./useDeepLink";

const CODE32 = "a".repeat(32); // 32-char all-hex reference code
const HASH64 = "b".repeat(64); // 64-char all-hex reference SHA-256 digest

describe("parseDeepLink — desktop scheme", () => {
	it("parses a valid powehi://invite/<code>.<hash>", () => {
		expect(parseDeepLink(`powehi://invite/${CODE32}.${HASH64}`)).toEqual({
			code: CODE32,
			keyPackageHash: HASH64,
		});
	});

	it("accepts code and hash with mixed hex digits", () => {
		const code = "0123456789abcdef0123456789abcdef";
		const hash = "0123456789abcdef".repeat(4);
		expect(parseDeepLink(`powehi://invite/${code}.${hash}`)).toEqual({
			code,
			keyPackageHash: hash,
		});
	});

	it("returns null when scheme differs", () => {
		expect(parseDeepLink(`powehix://invite/${CODE32}.${HASH64}`)).toBeNull();
	});

	it("returns null when path segment is not 'invite'", () => {
		expect(parseDeepLink(`powehi://join/${CODE32}.${HASH64}`)).toBeNull();
	});

	it("returns null when the hash is missing", () => {
		expect(parseDeepLink(`powehi://invite/${CODE32}`)).toBeNull();
	});

	it("returns null when code is too short (31 chars)", () => {
		expect(parseDeepLink(`powehi://invite/${"a".repeat(31)}.${HASH64}`)).toBeNull();
	});

	it("returns null when code is too long (33 chars)", () => {
		expect(parseDeepLink(`powehi://invite/${"a".repeat(33)}.${HASH64}`)).toBeNull();
	});

	it("returns null when code contains uppercase (must be lowercase hex)", () => {
		expect(parseDeepLink(`powehi://invite/${"A".repeat(32)}.${HASH64}`)).toBeNull();
	});

	it("returns null when hash is the wrong length", () => {
		expect(parseDeepLink(`powehi://invite/${CODE32}.${"b".repeat(63)}`)).toBeNull();
	});

	it("returns null when code contains non-hex chars", () => {
		expect(parseDeepLink(`powehi://invite/${"g".repeat(32)}.${HASH64}`)).toBeNull();
		expect(parseDeepLink("powehi://invite/<script>")).toBeNull();
	});

	it("returns null for empty URL", () => {
		expect(parseDeepLink("")).toBeNull();
	});
});

describe("parseDeepLink — mobile universal link", () => {
	it("parses a valid https://powehi.app/i/<code>.<hash>", () => {
		const code = "f".repeat(32);
		expect(parseDeepLink(`https://powehi.app/i/${code}.${HASH64}`)).toEqual({
			code,
			keyPackageHash: HASH64,
		});
	});

	it("accepts code.hash followed by query string", () => {
		const code = "e".repeat(32);
		expect(parseDeepLink(`https://powehi.app/i/${code}.${HASH64}?utm_source=share`)).toEqual({
			code,
			keyPackageHash: HASH64,
		});
	});

	it("returns null for wrong host", () => {
		expect(parseDeepLink(`https://evil.com/i/${CODE32}.${HASH64}`)).toBeNull();
	});

	it("returns null for wrong path prefix", () => {
		expect(parseDeepLink(`https://powehi.app/invite/${CODE32}.${HASH64}`)).toBeNull();
	});

	it("returns null when code length is wrong on mobile link (31 chars)", () => {
		expect(parseDeepLink(`https://powehi.app/i/${"a".repeat(31)}.${HASH64}`)).toBeNull();
	});

	it("returns null when the hash is missing", () => {
		expect(parseDeepLink(`https://powehi.app/i/${CODE32}`)).toBeNull();
	});
});
