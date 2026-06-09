import { describe, expect, it } from "vitest";
import { base64ToText, base64ToUint8Array, textToBase64, uint8ToBase64 } from "./base64";

describe("uint8ToBase64", () => {
	it("encodes a Uint8Array to standard base64", () => {
		const bytes = new TextEncoder().encode("hello");
		expect(uint8ToBase64(bytes)).toBe(btoa("hello"));
	});

	it("encodes a number[] to standard base64", () => {
		const nums = [72, 101, 108, 108, 111]; // "Hello"
		expect(uint8ToBase64(nums)).toBe(btoa("Hello"));
	});

	it("handles an empty array", () => {
		expect(uint8ToBase64(new Uint8Array(0))).toBe("");
	});

	it("handles large arrays without stack overflow", () => {
		const big = new Uint8Array(100_000).fill(0xab);
		// Should not throw — the spread-based approach would throw RangeError here.
		expect(() => uint8ToBase64(big)).not.toThrow();
		// Spot-check: the output is valid base64.
		expect(uint8ToBase64(big)).toMatch(/^[A-Za-z0-9+/]+=*$/);
	});
});

describe("textToBase64 / base64ToText round-trip", () => {
	it("round-trips ASCII text", () => {
		const text = "hello world";
		expect(base64ToText(textToBase64(text))).toBe(text);
	});

	it("round-trips Korean text (UTF-8 multi-byte)", () => {
		const text = "안녕하세요";
		expect(base64ToText(textToBase64(text))).toBe(text);
	});

	it("round-trips emoji (4-byte UTF-8)", () => {
		const text = "🔐🔑";
		expect(base64ToText(textToBase64(text))).toBe(text);
	});

	it("round-trips empty string", () => {
		expect(base64ToText(textToBase64(""))).toBe("");
	});

	it("textToBase64 produces standard base64 (not base64url)", () => {
		// Standard base64 uses +, /, and = padding; base64url uses -, _, no padding.
		// We verify we get proper standard base64 by checking decoding with atob.
		const result = textToBase64("hello");
		expect(() => atob(result)).not.toThrow();
	});
});

describe("base64ToUint8Array", () => {
	it("round-trips with uint8ToBase64", () => {
		const bytes = new Uint8Array([0x00, 0xff, 0x7e, 0x80, 0x42]);
		expect(base64ToUint8Array(uint8ToBase64(bytes))).toEqual(bytes);
	});

	it("decodes 16-byte identity-like data correctly", () => {
		const bytes = new Uint8Array(16).fill(0xab);
		const b64 = uint8ToBase64(bytes);
		const decoded = base64ToUint8Array(b64);
		expect(decoded).toHaveLength(16);
		expect(decoded.every((v) => v === 0xab)).toBe(true);
	});

	it("handles empty base64 string", () => {
		expect(base64ToUint8Array("")).toHaveLength(0);
	});
});
