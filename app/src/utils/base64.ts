/**
 * Safe base64 utilities — avoids spread-argument stack overflow on large arrays.
 *
 * `btoa(String.fromCharCode(...largeArray))` exceeds JS engine argument limits
 * (~50K–500K depending on engine) and throws RangeError on realistic MLS payloads.
 * These helpers iterate byte-by-byte instead.
 */

/** Encode a Uint8Array or number[] to standard base64. */
export function uint8ToBase64(input: Uint8Array | number[]): string {
	const bytes = input instanceof Uint8Array ? input : new Uint8Array(input);
	let binary = "";
	const len = bytes.length;
	for (let i = 0; i < len; i++) {
		binary += String.fromCharCode(bytes[i]);
	}
	return btoa(binary);
}

/** Encode a UTF-8 string to standard base64 (TextEncoder → bytes → base64). */
export function textToBase64(text: string): string {
	return uint8ToBase64(new TextEncoder().encode(text));
}

/** Decode a standard base64 string back to a Uint8Array (binary-safe). */
export function base64ToUint8Array(b64: string): Uint8Array {
	const binary = atob(b64);
	const bytes = new Uint8Array(binary.length);
	for (let i = 0; i < binary.length; i++) {
		bytes[i] = binary.charCodeAt(i);
	}
	return bytes;
}

/** Decode a standard base64 string back to UTF-8 text. */
export function base64ToText(b64: string): string {
	return new TextDecoder().decode(base64ToUint8Array(b64));
}
