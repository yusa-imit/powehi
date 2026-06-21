import { describe, expect, it } from "vitest";
import { parseDeepLink } from "./useDeepLink";

const CODE32 = "a".repeat(32); // 32-char all-hex reference code

describe("parseDeepLink — desktop scheme", () => {
	it("parses a valid powehi://invite/<code>", () => {
		expect(parseDeepLink(`powehi://invite/${CODE32}`)).toBe(CODE32);
	});

	it("accepts code with mixed hex digits", () => {
		const code = "0123456789abcdef0123456789abcdef";
		expect(parseDeepLink(`powehi://invite/${code}`)).toBe(code);
	});

	it("returns null when scheme differs", () => {
		expect(parseDeepLink(`powehix://invite/${CODE32}`)).toBeNull();
	});

	it("returns null when path segment is not 'invite'", () => {
		expect(parseDeepLink(`powehi://join/${CODE32}`)).toBeNull();
	});

	it("returns null when code is too short (31 chars)", () => {
		expect(parseDeepLink(`powehi://invite/${"a".repeat(31)}`)).toBeNull();
	});

	it("returns null when code is too long (33 chars)", () => {
		expect(parseDeepLink(`powehi://invite/${"a".repeat(33)}`)).toBeNull();
	});

	it("returns null when code contains uppercase (must be lowercase hex)", () => {
		expect(parseDeepLink(`powehi://invite/${"A".repeat(32)}`)).toBeNull();
	});

	it("returns null when code contains non-hex chars", () => {
		expect(parseDeepLink(`powehi://invite/${"g".repeat(32)}`)).toBeNull();
		expect(parseDeepLink("powehi://invite/<script>")).toBeNull();
	});

	it("returns null for empty URL", () => {
		expect(parseDeepLink("")).toBeNull();
	});
});

describe("parseDeepLink — mobile universal link", () => {
	it("parses a valid https://powehi.app/i/<code>", () => {
		const code = "f".repeat(32);
		expect(parseDeepLink(`https://powehi.app/i/${code}`)).toBe(code);
	});

	it("accepts code followed by query string", () => {
		const code = "e".repeat(32);
		expect(parseDeepLink(`https://powehi.app/i/${code}?utm_source=share`)).toBe(code);
	});

	it("returns null for wrong host", () => {
		expect(parseDeepLink(`https://evil.com/i/${CODE32}`)).toBeNull();
	});

	it("returns null for wrong path prefix", () => {
		expect(parseDeepLink(`https://powehi.app/invite/${CODE32}`)).toBeNull();
	});

	it("returns null when code length is wrong on mobile link (31 chars)", () => {
		expect(parseDeepLink(`https://powehi.app/i/${"a".repeat(31)}`)).toBeNull();
	});
});
