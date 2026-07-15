import { act, renderHook, waitFor } from "@testing-library/react";
import { type MockInstance, afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import * as MessagesModule from "../api/messages";
import type { Envelope } from "../api/messages";
import { useAuthStore } from "../store/auth";
import * as CryptoWorkerHook from "./useCryptoWorker";
import { ALLOWED_REACTION_EMOJIS, type IncomingMessage, useMessages } from "./useMessages";

const PQ_HANDLE = "pq-decap-handle-test";

const IDENTITY_ID = "identity-001";
const GROUP_ID = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
const SENDER_ID = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb";
const ENV_ID = "cccccccc-cccc-cccc-cccc-cccccccccccc";
const TOKEN = "session-token-xyz";
const DECRYPTED_TEXT = "hello world";

const mockWorker = {
	mlsDecrypt: vi.fn(async () => ({
		plaintext: new TextEncoder().encode(DECRYPTED_TEXT),
	})),
	mlKem768DecapV2: vi.fn(async () => ({ sharedSecretHandle: "mock-ss-dec-0" })),
	mlsPqDeriveBinding: vi.fn(async () => ({ bindingHex: "c702693eff3c46bd" })),
	mlKem768DropDecapKey: vi.fn(async () => {}),
};

let pollSpy: MockInstance<typeof MessagesModule.pollMessages>;
let ackSpy: MockInstance<typeof MessagesModule.ackMessage>;

beforeEach(() => {
	// Spy on the exported functions — works with Vitest's ESM proxy.
	pollSpy = vi.spyOn(MessagesModule, "pollMessages").mockResolvedValue([] as Envelope[]);
	ackSpy = vi.spyOn(MessagesModule, "ackMessage").mockResolvedValue(undefined);

	vi.spyOn(CryptoWorkerHook, "useCryptoWorker").mockReturnValue(
		mockWorker as unknown as ReturnType<typeof CryptoWorkerHook.useCryptoWorker>,
	);
	useAuthStore.setState({
		phase: "app",
		deviceId: "my-device",
		sessionToken: TOKEN,
	});
});

afterEach(() => {
	vi.restoreAllMocks();
	useAuthStore.setState({
		phase: "login",
		deviceId: null,
		sessionToken: null,
		pqDecapKeyHandle: null,
	});
});

function makeEnvelope(overrides: Partial<Envelope> = {}): Envelope {
	return {
		id: ENV_ID,
		group_id: GROUP_ID,
		sender: SENDER_ID,
		recipient: null,
		message_type: "Application",
		ciphertext: [1, 2, 3],
		epoch: null,
		created_at: "2026-06-03T12:00:00Z",
		expires_at: null,
		...overrides,
	};
}

describe("useMessages", () => {
	it("polls immediately on mount", async () => {
		const { unmount } = renderHook(() => useMessages(IDENTITY_ID, GROUP_ID, vi.fn()));

		await waitFor(() => {
			expect(pollSpy).toHaveBeenCalledWith(TOKEN, undefined);
		});
		await act(async () => {
			unmount();
		});
	});

	it("decrypts Application message and invokes onMessage", async () => {
		pollSpy.mockResolvedValueOnce([makeEnvelope()]);

		const received: IncomingMessage[] = [];
		const { unmount } = renderHook(() =>
			useMessages(IDENTITY_ID, GROUP_ID, (m) => received.push(m)),
		);

		await waitFor(() => {
			expect(received).toHaveLength(1);
		});

		expect(received[0].text).toBe(DECRYPTED_TEXT);
		expect(received[0].senderId).toBe(SENDER_ID);
		expect(received[0].id).toBe(ENV_ID);
		await act(async () => {
			unmount();
		});
	});

	it("acks Application message after successful decrypt", async () => {
		pollSpy.mockResolvedValueOnce([makeEnvelope()]);

		const { unmount } = renderHook(() => useMessages(IDENTITY_ID, GROUP_ID, vi.fn()));

		await waitFor(() => {
			expect(ackSpy).toHaveBeenCalledWith(TOKEN, ENV_ID);
		});
		await act(async () => {
			unmount();
		});
	});

	it("skips Welcome envelopes without acking (useWelcomePoller owns Welcome)", async () => {
		pollSpy.mockResolvedValueOnce([makeEnvelope({ message_type: "Welcome" })]);
		const onMessage = vi.fn();

		renderHook(() => useMessages(IDENTITY_ID, GROUP_ID, onMessage));

		await waitFor(() => {
			expect(pollSpy).toHaveBeenCalled();
		});
		await new Promise<void>((r) => setTimeout(r, 10));
		expect(ackSpy).not.toHaveBeenCalled();
		expect(onMessage).not.toHaveBeenCalled();
	});

	it("acks Commit envelopes silently without calling onMessage", async () => {
		pollSpy.mockResolvedValueOnce([makeEnvelope({ message_type: "Commit" })]);
		const onMessage = vi.fn();

		renderHook(() => useMessages(IDENTITY_ID, GROUP_ID, onMessage));

		await waitFor(() => {
			expect(ackSpy).toHaveBeenCalledWith(TOKEN, ENV_ID);
		});
		expect(onMessage).not.toHaveBeenCalled();
	});

	it("skips messages for other groups without decrypting", async () => {
		pollSpy.mockResolvedValueOnce([makeEnvelope({ group_id: "different-group-id" })]);
		const onMessage = vi.fn();

		renderHook(() => useMessages(IDENTITY_ID, GROUP_ID, onMessage));

		await waitFor(() => {
			expect(pollSpy).toHaveBeenCalled();
		});
		expect(mockWorker.mlsDecrypt).not.toHaveBeenCalled();
		expect(onMessage).not.toHaveBeenCalled();
	});

	it("does not poll when sessionToken is absent", async () => {
		useAuthStore.setState({
			phase: "login",
			deviceId: null,
			sessionToken: null,
		});

		await act(async () => {
			renderHook(() => useMessages(IDENTITY_ID, GROUP_ID, vi.fn()));
		});

		expect(pollSpy).not.toHaveBeenCalled();
	});

	it("does not poll when identityId is undefined", async () => {
		await act(async () => {
			renderHook(() => useMessages(undefined, GROUP_ID, vi.fn()));
		});

		expect(pollSpy).not.toHaveBeenCalled();
	});

	it("does not call onMessage when decrypt fails (swallows error), but logs a content-free diagnostic", async () => {
		const consoleErrorSpy = vi.spyOn(console, "error").mockImplementation(() => {});
		mockWorker.mlsDecrypt.mockRejectedValueOnce(new Error("stale_epoch"));
		pollSpy.mockResolvedValueOnce([makeEnvelope()]);
		const onMessage = vi.fn();

		renderHook(() => useMessages(IDENTITY_ID, GROUP_ID, onMessage));

		// Wait for the poll attempt to complete (decrypt was tried).
		await waitFor(() => {
			expect(pollSpy).toHaveBeenCalled();
		});
		// Give an extra tick for the rejected promise to settle.
		await new Promise<void>((r) => setTimeout(r, 10));
		expect(onMessage).not.toHaveBeenCalled();
		expect(consoleErrorSpy).toHaveBeenCalledWith("message_decrypt_failed", "Error", "stale_epoch");
		consoleErrorSpy.mockRestore();
	});

	it("logs a content-free diagnostic (and does not call onMessage) for an Application envelope from a different group", async () => {
		const consoleErrorSpy = vi.spyOn(console, "error").mockImplementation(() => {});
		const OTHER_GROUP_ID = "dddddddd-dddd-dddd-dddd-dddddddddddd";
		pollSpy.mockResolvedValueOnce([makeEnvelope({ group_id: OTHER_GROUP_ID })]);
		const onMessage = vi.fn();

		renderHook(() => useMessages(IDENTITY_ID, GROUP_ID, onMessage));

		await waitFor(() => {
			expect(ackSpy).toHaveBeenCalledWith(TOKEN, ENV_ID);
		});
		expect(onMessage).not.toHaveBeenCalled();
		expect(mockWorker.mlsDecrypt).not.toHaveBeenCalled();
		expect(consoleErrorSpy).toHaveBeenCalledWith(
			"message_group_mismatch",
			OTHER_GROUP_ID,
			GROUP_ID,
		);
		consoleErrorSpy.mockRestore();
	});

	it("maps expires_at from envelope to expiresAt unix ms in IncomingMessage", async () => {
		const EXPIRES_ISO = "2026-12-31T00:00:00.000Z";
		const expectedMs = new Date(EXPIRES_ISO).getTime();
		pollSpy.mockResolvedValueOnce([makeEnvelope({ expires_at: EXPIRES_ISO })]);

		const received: IncomingMessage[] = [];
		renderHook(() => useMessages(IDENTITY_ID, GROUP_ID, (m) => received.push(m)));

		await waitFor(() => {
			expect(received).toHaveLength(1);
		});
		expect(received[0].expiresAt).toBe(expectedMs);
	});

	it("yields undefined expiresAt when expires_at is null", async () => {
		pollSpy.mockResolvedValueOnce([makeEnvelope({ expires_at: null })]);

		const received: IncomingMessage[] = [];
		renderHook(() => useMessages(IDENTITY_ID, GROUP_ID, (m) => received.push(m)));

		await waitFor(() => {
			expect(received).toHaveLength(1);
		});
		expect(received[0].expiresAt).toBeUndefined();
	});

	it("stops polling after unmount", async () => {
		vi.useFakeTimers();
		try {
			const { unmount } = renderHook(() => useMessages(IDENTITY_ID, GROUP_ID, vi.fn()));

			await act(async () => {
				vi.advanceTimersByTime(0);
				await Promise.resolve();
				await Promise.resolve();
			});

			const countBeforeUnmount = pollSpy.mock.calls.length;
			unmount();

			// Advance well past the polling interval.
			vi.advanceTimersByTime(30_000);
			await Promise.resolve();

			// After unmount the poll count must not increase by more than 1 in-flight call.
			expect(pollSpy.mock.calls.length).toBeLessThanOrEqual(countBeforeUnmount + 1);
		} finally {
			vi.useRealTimers();
		}
	});
});

describe("useMessages — pq_init handling (§5.3 Phase B)", () => {
	function makePqEnvelope(): Envelope {
		return {
			id: ENV_ID,
			group_id: GROUP_ID,
			sender: SENDER_ID,
			recipient: null,
			message_type: "Application",
			ciphertext: [9, 9, 9],
			epoch: null,
			created_at: "2026-06-11T10:00:00Z",
			expires_at: null,
		};
	}

	beforeEach(() => {
		useAuthStore.setState({ pqDecapKeyHandle: PQ_HANDLE });
		mockWorker.mlsDecrypt.mockResolvedValue({
			plaintext: new TextEncoder().encode(JSON.stringify({ type: "pq_init", ct: [1, 2, 3, 4] })),
		});
	});

	afterEach(() => {
		// Restore default mlsDecrypt behaviour for other suites.
		mockWorker.mlsDecrypt.mockResolvedValue({
			plaintext: new TextEncoder().encode(DECRYPTED_TEXT),
		});
	});

	it("invokes onPqBinding with groupId and bindingHex on pq_init", async () => {
		pollSpy.mockResolvedValueOnce([makePqEnvelope()]);
		const onPqBinding = vi.fn();

		renderHook(() => useMessages(IDENTITY_ID, GROUP_ID, vi.fn(), onPqBinding));

		await waitFor(() => {
			expect(onPqBinding).toHaveBeenCalledWith(GROUP_ID, "c702693eff3c46bd");
		});
	});

	it("does NOT forward pq_init to onMessage (not a user-visible message)", async () => {
		pollSpy.mockResolvedValueOnce([makePqEnvelope()]);
		const onMessage = vi.fn();

		renderHook(() => useMessages(IDENTITY_ID, GROUP_ID, onMessage));

		await waitFor(() => expect(ackSpy).toHaveBeenCalledWith(TOKEN, ENV_ID));
		expect(onMessage).not.toHaveBeenCalled();
	});

	it("acks the pq_init envelope after processing", async () => {
		pollSpy.mockResolvedValueOnce([makePqEnvelope()]);

		renderHook(() => useMessages(IDENTITY_ID, GROUP_ID, vi.fn(), vi.fn()));

		await waitFor(() => {
			expect(ackSpy).toHaveBeenCalledWith(TOKEN, ENV_ID);
		});
	});

	it("calls mlKem768DecapV2 with the pqDecapKeyHandle from auth store", async () => {
		pollSpy.mockResolvedValueOnce([makePqEnvelope()]);

		renderHook(() => useMessages(IDENTITY_ID, GROUP_ID, vi.fn(), vi.fn()));

		await waitFor(() => {
			expect(mockWorker.mlKem768DecapV2).toHaveBeenCalledWith(PQ_HANDLE, expect.any(Uint8Array));
		});
	});

	it("degrades gracefully when mlKem768DecapV2 fails — onMessage still not called", async () => {
		mockWorker.mlKem768DecapV2.mockRejectedValueOnce(new Error("decap_failed"));
		pollSpy.mockResolvedValueOnce([makePqEnvelope()]);
		const onMessage = vi.fn();
		const onPqBinding = vi.fn();

		renderHook(() => useMessages(IDENTITY_ID, GROUP_ID, onMessage, onPqBinding));

		await waitFor(() => expect(ackSpy).toHaveBeenCalledWith(TOKEN, ENV_ID));
		expect(onMessage).not.toHaveBeenCalled();
		expect(onPqBinding).not.toHaveBeenCalled();
	});

	it("skips PQ decap when pqDecapKeyHandle is null (handle already consumed)", async () => {
		useAuthStore.setState({ pqDecapKeyHandle: null });
		pollSpy.mockResolvedValueOnce([makePqEnvelope()]);
		const onPqBinding = vi.fn();

		renderHook(() => useMessages(IDENTITY_ID, GROUP_ID, vi.fn(), onPqBinding));

		await waitFor(() => expect(ackSpy).toHaveBeenCalledWith(TOKEN, ENV_ID));
		expect(mockWorker.mlKem768DecapV2).not.toHaveBeenCalled();
		expect(onPqBinding).not.toHaveBeenCalled();
	});
});

describe("useMessages — §9.4.1 thumbnail parsing", () => {
	function makeImageEnvelope(thumbnailField?: unknown) {
		const payload: Record<string, unknown> = {
			type: "image",
			blobId: "test-blob-id",
			blobHash: Array.from({ length: 32 }, () => 0xab),
			mediaKey: Array.from({ length: 32 }, () => 0xcd),
			iv: Array.from({ length: 12 }, () => 0xef),
		};
		if (thumbnailField !== undefined) {
			payload.thumbnail = thumbnailField;
		}
		return {
			id: ENV_ID,
			group_id: GROUP_ID,
			sender: SENDER_ID,
			recipient: null,
			message_type: "Application" as const,
			ciphertext: [1, 2, 3],
			epoch: null,
			created_at: "2026-06-11T10:00:00Z",
			expires_at: null,
		};
	}

	beforeEach(() => {
		vi.spyOn(CryptoWorkerHook, "useCryptoWorker").mockReturnValue(
			mockWorker as unknown as ReturnType<typeof CryptoWorkerHook.useCryptoWorker>,
		);
		useAuthStore.setState({
			phase: "app",
			deviceId: "my-device",
			sessionToken: TOKEN,
		});
	});
	afterEach(() => {
		vi.restoreAllMocks();
		useAuthStore.setState({
			phase: "login",
			deviceId: null,
			sessionToken: null,
		});
	});

	it("parses thumbnail fields from image payload when present", async () => {
		const thumb = {
			ct: Array.from({ length: 32 }, (_, i) => i),
			key: Array.from({ length: 32 }, () => 0xcd),
			iv: Array.from({ length: 12 }, () => 0xef),
		};
		mockWorker.mlsDecrypt.mockResolvedValueOnce({
			plaintext: new TextEncoder().encode(
				JSON.stringify({
					type: "image",
					blobId: "test-blob",
					blobHash: Array.from({ length: 32 }, () => 0),
					mediaKey: Array.from({ length: 32 }, () => 0),
					iv: Array.from({ length: 12 }, () => 0),
					thumbnail: thumb,
				}),
			),
		});
		pollSpy.mockResolvedValueOnce([makeImageEnvelope(thumb)]);

		const received: IncomingMessage[] = [];
		renderHook(() => useMessages(IDENTITY_ID, GROUP_ID, (m) => received.push(m)));

		await waitFor(() => expect(received).toHaveLength(1));
		expect(received[0].media?.thumbnail).toEqual(thumb);
	});

	it("leaves thumbnail undefined when image payload has no thumbnail field", async () => {
		mockWorker.mlsDecrypt.mockResolvedValueOnce({
			plaintext: new TextEncoder().encode(
				JSON.stringify({
					type: "image",
					blobId: "test-blob",
					blobHash: Array.from({ length: 32 }, () => 0),
					mediaKey: Array.from({ length: 32 }, () => 0),
					iv: Array.from({ length: 12 }, () => 0),
				}),
			),
		});
		pollSpy.mockResolvedValueOnce([makeImageEnvelope()]);

		const received: IncomingMessage[] = [];
		renderHook(() => useMessages(IDENTITY_ID, GROUP_ID, (m) => received.push(m)));

		await waitFor(() => expect(received).toHaveLength(1));
		expect(received[0].media?.thumbnail).toBeUndefined();
	});

	it("ignores malformed thumbnail (missing key array) — leaves thumbnail undefined", async () => {
		mockWorker.mlsDecrypt.mockResolvedValueOnce({
			plaintext: new TextEncoder().encode(
				JSON.stringify({
					type: "image",
					blobId: "test-blob",
					blobHash: Array.from({ length: 32 }, () => 0),
					mediaKey: Array.from({ length: 32 }, () => 0),
					iv: Array.from({ length: 12 }, () => 0),
					thumbnail: { ct: [1, 2, 3], iv: [4, 5, 6] }, // missing key field
				}),
			),
		});
		pollSpy.mockResolvedValueOnce([makeImageEnvelope()]);

		const received: IncomingMessage[] = [];
		renderHook(() => useMessages(IDENTITY_ID, GROUP_ID, (m) => received.push(m)));

		await waitFor(() => expect(received).toHaveLength(1));
		expect(received[0].media?.thumbnail).toBeUndefined();
	});
});

describe("useMessages — typing_indicator handling", () => {
	function makeTypingEnvelope(): Envelope {
		return {
			id: ENV_ID,
			group_id: GROUP_ID,
			sender: SENDER_ID,
			recipient: null,
			message_type: "Application",
			ciphertext: [7, 7, 7],
			epoch: null,
			created_at: "2026-06-14T09:00:00Z",
			expires_at: null,
		};
	}

	beforeEach(() => {
		mockWorker.mlsDecrypt.mockResolvedValue({
			plaintext: new TextEncoder().encode(JSON.stringify({ type: "typing_indicator" })),
		});
	});

	afterEach(() => {
		mockWorker.mlsDecrypt.mockResolvedValue({
			plaintext: new TextEncoder().encode(DECRYPTED_TEXT),
		});
	});

	it("invokes onTyping with groupId when typing_indicator is received", async () => {
		pollSpy.mockResolvedValueOnce([makeTypingEnvelope()]);
		const onTyping = vi.fn();

		renderHook(() => useMessages(IDENTITY_ID, GROUP_ID, vi.fn(), undefined, onTyping));

		await waitFor(() => {
			expect(onTyping).toHaveBeenCalledWith(GROUP_ID);
		});
	});

	it("does NOT forward typing_indicator to onMessage", async () => {
		pollSpy.mockResolvedValueOnce([makeTypingEnvelope()]);
		const onMessage = vi.fn();

		renderHook(() => useMessages(IDENTITY_ID, GROUP_ID, onMessage, undefined, vi.fn()));

		await waitFor(() => expect(ackSpy).toHaveBeenCalledWith(TOKEN, ENV_ID));
		expect(onMessage).not.toHaveBeenCalled();
	});

	it("acks the typing_indicator envelope after processing", async () => {
		pollSpy.mockResolvedValueOnce([makeTypingEnvelope()]);

		renderHook(() => useMessages(IDENTITY_ID, GROUP_ID, vi.fn(), undefined, vi.fn()));

		await waitFor(() => {
			expect(ackSpy).toHaveBeenCalledWith(TOKEN, ENV_ID);
		});
	});
});

describe("useMessages — reaction handling", () => {
	const TARGET_ID = "dddddddd-dddd-dddd-dddd-dddddddddddd";

	function makeReactionEnvelope(overrides: Partial<Envelope> = {}): Envelope {
		return {
			id: ENV_ID,
			group_id: GROUP_ID,
			sender: SENDER_ID,
			recipient: null,
			message_type: "Application",
			ciphertext: [9, 9, 9],
			epoch: null,
			created_at: "2026-06-15T09:00:00Z",
			expires_at: null,
			...overrides,
		};
	}

	afterEach(() => {
		mockWorker.mlsDecrypt.mockResolvedValue({
			plaintext: new TextEncoder().encode(DECRYPTED_TEXT),
		});
	});

	it("invokes onReaction with groupId, targetId, emoji and senderId for a valid reaction", async () => {
		mockWorker.mlsDecrypt.mockResolvedValueOnce({
			plaintext: new TextEncoder().encode(
				JSON.stringify({
					type: "reaction",
					emoji: "👍",
					targetMessageId: TARGET_ID,
				}),
			),
		});
		pollSpy.mockResolvedValueOnce([makeReactionEnvelope()]);
		const onReaction = vi.fn();

		renderHook(() => useMessages(IDENTITY_ID, GROUP_ID, vi.fn(), undefined, undefined, onReaction));

		await waitFor(() => {
			expect(onReaction).toHaveBeenCalledWith(GROUP_ID, TARGET_ID, "👍", SENDER_ID);
		});
	});

	it("does NOT forward a reaction envelope to onMessage", async () => {
		mockWorker.mlsDecrypt.mockResolvedValueOnce({
			plaintext: new TextEncoder().encode(
				JSON.stringify({
					type: "reaction",
					emoji: "❤️",
					targetMessageId: TARGET_ID,
				}),
			),
		});
		pollSpy.mockResolvedValueOnce([makeReactionEnvelope()]);
		const onMessage = vi.fn();

		renderHook(() => useMessages(IDENTITY_ID, GROUP_ID, onMessage, undefined, undefined, vi.fn()));

		await waitFor(() => expect(ackSpy).toHaveBeenCalledWith(TOKEN, ENV_ID));
		expect(onMessage).not.toHaveBeenCalled();
	});

	it("acks the reaction envelope after processing", async () => {
		mockWorker.mlsDecrypt.mockResolvedValueOnce({
			plaintext: new TextEncoder().encode(
				JSON.stringify({
					type: "reaction",
					emoji: "😂",
					targetMessageId: TARGET_ID,
				}),
			),
		});
		pollSpy.mockResolvedValueOnce([makeReactionEnvelope()]);

		renderHook(() => useMessages(IDENTITY_ID, GROUP_ID, vi.fn(), undefined, undefined, vi.fn()));

		await waitFor(() => {
			expect(ackSpy).toHaveBeenCalledWith(TOKEN, ENV_ID);
		});
	});

	it("does NOT call onReaction for an emoji not in the whitelist", async () => {
		mockWorker.mlsDecrypt.mockResolvedValueOnce({
			plaintext: new TextEncoder().encode(
				JSON.stringify({
					type: "reaction",
					emoji: "🤖",
					targetMessageId: TARGET_ID,
				}),
			),
		});
		pollSpy.mockResolvedValueOnce([makeReactionEnvelope()]);
		const onReaction = vi.fn();

		renderHook(() => useMessages(IDENTITY_ID, GROUP_ID, vi.fn(), undefined, undefined, onReaction));

		await waitFor(() => expect(ackSpy).toHaveBeenCalledWith(TOKEN, ENV_ID));
		expect(onReaction).not.toHaveBeenCalled();
	});

	it("does NOT call onReaction when targetMessageId is empty", async () => {
		mockWorker.mlsDecrypt.mockResolvedValueOnce({
			plaintext: new TextEncoder().encode(
				JSON.stringify({ type: "reaction", emoji: "👍", targetMessageId: "" }),
			),
		});
		pollSpy.mockResolvedValueOnce([makeReactionEnvelope()]);
		const onReaction = vi.fn();

		renderHook(() => useMessages(IDENTITY_ID, GROUP_ID, vi.fn(), undefined, undefined, onReaction));

		await waitFor(() => expect(ackSpy).toHaveBeenCalledWith(TOKEN, ENV_ID));
		expect(onReaction).not.toHaveBeenCalled();
	});

	it("ALLOWED_REACTION_EMOJIS has exactly 6 entries and all are strings", () => {
		expect(ALLOWED_REACTION_EMOJIS).toHaveLength(6);
		for (const e of ALLOWED_REACTION_EMOJIS) {
			expect(typeof e).toBe("string");
			expect(e.length).toBeGreaterThan(0);
		}
	});

	it("does NOT forward invalid reaction (bad emoji) to onMessage", async () => {
		mockWorker.mlsDecrypt.mockResolvedValueOnce({
			plaintext: new TextEncoder().encode(
				JSON.stringify({
					type: "reaction",
					emoji: "🤖",
					targetMessageId: TARGET_ID,
				}),
			),
		});
		pollSpy.mockResolvedValueOnce([makeReactionEnvelope()]);
		const onMessage = vi.fn();

		renderHook(() => useMessages(IDENTITY_ID, GROUP_ID, onMessage, undefined, undefined, vi.fn()));

		await waitFor(() => expect(ackSpy).toHaveBeenCalledWith(TOKEN, ENV_ID));
		await act(async () => {});
		expect(onMessage).not.toHaveBeenCalled();
	});
});

describe("useMessages — read_receipt handling", () => {
	const MSG_ID_A = "aaaaaaaa-aaaa-aaaa-aaaa-000000000001";
	const MSG_ID_B = "aaaaaaaa-aaaa-aaaa-aaaa-000000000002";
	const READ_AT = 1_718_000_000_000;

	function makeReadReceiptEnvelope(overrides: Partial<Envelope> = {}): Envelope {
		return {
			id: ENV_ID,
			group_id: GROUP_ID,
			sender: SENDER_ID,
			recipient: null,
			message_type: "Application",
			ciphertext: [7, 8, 9],
			epoch: null,
			created_at: "2026-06-15T10:00:00Z",
			expires_at: null,
			...overrides,
		};
	}

	afterEach(() => {
		mockWorker.mlsDecrypt.mockResolvedValue({
			plaintext: new TextEncoder().encode(DECRYPTED_TEXT),
		});
	});

	it("invokes onReadReceipt with groupId, messageIds, readAt, and senderDeviceId", async () => {
		mockWorker.mlsDecrypt.mockResolvedValueOnce({
			plaintext: new TextEncoder().encode(
				JSON.stringify({
					type: "read_receipt",
					messageIds: [MSG_ID_A, MSG_ID_B],
					readAt: READ_AT,
				}),
			),
		});
		pollSpy.mockResolvedValueOnce([makeReadReceiptEnvelope()]);
		const onReadReceipt = vi.fn();

		renderHook(() =>
			useMessages(
				IDENTITY_ID,
				GROUP_ID,
				vi.fn(),
				undefined,
				undefined,
				undefined,
				undefined,
				onReadReceipt,
			),
		);

		await waitFor(() => {
			expect(onReadReceipt).toHaveBeenCalledWith(
				GROUP_ID,
				[MSG_ID_A, MSG_ID_B],
				READ_AT,
				SENDER_ID,
			);
		});
	});

	it("does NOT forward read_receipt envelope to onMessage", async () => {
		mockWorker.mlsDecrypt.mockResolvedValueOnce({
			plaintext: new TextEncoder().encode(
				JSON.stringify({
					type: "read_receipt",
					messageIds: [MSG_ID_A],
					readAt: READ_AT,
				}),
			),
		});
		pollSpy.mockResolvedValueOnce([makeReadReceiptEnvelope()]);
		const onMessage = vi.fn();

		renderHook(() =>
			useMessages(
				IDENTITY_ID,
				GROUP_ID,
				onMessage,
				undefined,
				undefined,
				undefined,
				undefined,
				vi.fn(),
			),
		);

		await waitFor(() => expect(ackSpy).toHaveBeenCalledWith(TOKEN, ENV_ID));
		expect(onMessage).not.toHaveBeenCalled();
	});

	it("acks the read_receipt envelope after processing", async () => {
		mockWorker.mlsDecrypt.mockResolvedValueOnce({
			plaintext: new TextEncoder().encode(
				JSON.stringify({
					type: "read_receipt",
					messageIds: [MSG_ID_A],
					readAt: READ_AT,
				}),
			),
		});
		pollSpy.mockResolvedValueOnce([makeReadReceiptEnvelope()]);

		renderHook(() =>
			useMessages(
				IDENTITY_ID,
				GROUP_ID,
				vi.fn(),
				undefined,
				undefined,
				undefined,
				undefined,
				vi.fn(),
			),
		);

		await waitFor(() => {
			expect(ackSpy).toHaveBeenCalledWith(TOKEN, ENV_ID);
		});
	});

	it("does NOT call onReadReceipt when messageIds array is empty", async () => {
		mockWorker.mlsDecrypt.mockResolvedValueOnce({
			plaintext: new TextEncoder().encode(
				JSON.stringify({
					type: "read_receipt",
					messageIds: [],
					readAt: READ_AT,
				}),
			),
		});
		pollSpy.mockResolvedValueOnce([makeReadReceiptEnvelope()]);
		const onReadReceipt = vi.fn();

		renderHook(() =>
			useMessages(
				IDENTITY_ID,
				GROUP_ID,
				vi.fn(),
				undefined,
				undefined,
				undefined,
				undefined,
				onReadReceipt,
			),
		);

		await waitFor(() => expect(ackSpy).toHaveBeenCalledWith(TOKEN, ENV_ID));
		expect(onReadReceipt).not.toHaveBeenCalled();
	});

	it("does NOT call onReadReceipt when messageIds exceeds 100-item cap", async () => {
		const tooMany = Array.from({ length: 101 }, (_, i) => `id-${String(i).padStart(3, "0")}`);
		mockWorker.mlsDecrypt.mockResolvedValueOnce({
			plaintext: new TextEncoder().encode(
				JSON.stringify({
					type: "read_receipt",
					messageIds: tooMany,
					readAt: READ_AT,
				}),
			),
		});
		pollSpy.mockResolvedValueOnce([makeReadReceiptEnvelope()]);
		const onReadReceipt = vi.fn();

		renderHook(() =>
			useMessages(
				IDENTITY_ID,
				GROUP_ID,
				vi.fn(),
				undefined,
				undefined,
				undefined,
				undefined,
				onReadReceipt,
			),
		);

		await waitFor(() => expect(ackSpy).toHaveBeenCalledWith(TOKEN, ENV_ID));
		expect(onReadReceipt).not.toHaveBeenCalled();
	});

	it("does NOT call onReadReceipt when messageIds contains non-string entries", async () => {
		mockWorker.mlsDecrypt.mockResolvedValueOnce({
			plaintext: new TextEncoder().encode(
				JSON.stringify({
					type: "read_receipt",
					messageIds: [42, null, MSG_ID_A],
					readAt: READ_AT,
				}),
			),
		});
		pollSpy.mockResolvedValueOnce([makeReadReceiptEnvelope()]);
		const onReadReceipt = vi.fn();

		renderHook(() =>
			useMessages(
				IDENTITY_ID,
				GROUP_ID,
				vi.fn(),
				undefined,
				undefined,
				undefined,
				undefined,
				onReadReceipt,
			),
		);

		await waitFor(() => expect(ackSpy).toHaveBeenCalledWith(TOKEN, ENV_ID));
		expect(onReadReceipt).not.toHaveBeenCalled();
	});

	it("does NOT forward invalid read_receipt (empty messageIds) to onMessage", async () => {
		mockWorker.mlsDecrypt.mockResolvedValueOnce({
			plaintext: new TextEncoder().encode(
				JSON.stringify({
					type: "read_receipt",
					messageIds: [],
					readAt: READ_AT,
				}),
			),
		});
		pollSpy.mockResolvedValueOnce([makeReadReceiptEnvelope()]);
		const onMessage = vi.fn();

		renderHook(() =>
			useMessages(
				IDENTITY_ID,
				GROUP_ID,
				onMessage,
				undefined,
				undefined,
				undefined,
				undefined,
				vi.fn(),
			),
		);

		await waitFor(() => expect(ackSpy).toHaveBeenCalledWith(TOKEN, ENV_ID));
		await act(async () => {});
		expect(onMessage).not.toHaveBeenCalled();
	});
});

describe("useMessages — delivery_receipt handling", () => {
	const MSG_ID_A = "dddddddd-dddd-dddd-dddd-000000000001";
	const MSG_ID_B = "dddddddd-dddd-dddd-dddd-000000000002";

	function makeDeliveryReceiptEnvelope(overrides: Partial<Envelope> = {}): Envelope {
		return {
			id: ENV_ID,
			group_id: GROUP_ID,
			sender: SENDER_ID,
			recipient: null,
			message_type: "Application",
			ciphertext: [10, 11, 12],
			epoch: null,
			created_at: "2026-06-15T11:00:00Z",
			expires_at: null,
			...overrides,
		};
	}

	afterEach(() => {
		mockWorker.mlsDecrypt.mockResolvedValue({
			plaintext: new TextEncoder().encode(DECRYPTED_TEXT),
		});
	});

	it("invokes onDeliveryReceipt with groupId, messageIds, and senderDeviceId", async () => {
		mockWorker.mlsDecrypt.mockResolvedValueOnce({
			plaintext: new TextEncoder().encode(
				JSON.stringify({
					type: "delivery_receipt",
					messageIds: [MSG_ID_A, MSG_ID_B],
				}),
			),
		});
		pollSpy.mockResolvedValueOnce([makeDeliveryReceiptEnvelope()]);
		const onDeliveryReceipt = vi.fn();

		renderHook(() =>
			useMessages(
				IDENTITY_ID,
				GROUP_ID,
				vi.fn(),
				undefined,
				undefined,
				undefined,
				undefined,
				undefined,
				onDeliveryReceipt,
			),
		);

		await waitFor(() => {
			expect(onDeliveryReceipt).toHaveBeenCalledWith(GROUP_ID, [MSG_ID_A, MSG_ID_B], SENDER_ID);
		});
	});

	it("does NOT forward delivery_receipt envelope to onMessage", async () => {
		mockWorker.mlsDecrypt.mockResolvedValueOnce({
			plaintext: new TextEncoder().encode(
				JSON.stringify({ type: "delivery_receipt", messageIds: [MSG_ID_A] }),
			),
		});
		pollSpy.mockResolvedValueOnce([makeDeliveryReceiptEnvelope()]);
		const onMessage = vi.fn();

		renderHook(() =>
			useMessages(
				IDENTITY_ID,
				GROUP_ID,
				onMessage,
				undefined,
				undefined,
				undefined,
				undefined,
				vi.fn(),
			),
		);

		await waitFor(() => expect(ackSpy).toHaveBeenCalledWith(TOKEN, ENV_ID));
		expect(onMessage).not.toHaveBeenCalled();
	});

	it("acks the delivery_receipt envelope after processing", async () => {
		mockWorker.mlsDecrypt.mockResolvedValueOnce({
			plaintext: new TextEncoder().encode(
				JSON.stringify({ type: "delivery_receipt", messageIds: [MSG_ID_A] }),
			),
		});
		pollSpy.mockResolvedValueOnce([makeDeliveryReceiptEnvelope()]);

		renderHook(() =>
			useMessages(
				IDENTITY_ID,
				GROUP_ID,
				vi.fn(),
				undefined,
				undefined,
				undefined,
				undefined,
				vi.fn(),
			),
		);

		await waitFor(() => {
			expect(ackSpy).toHaveBeenCalledWith(TOKEN, ENV_ID);
		});
	});

	it("does NOT call onDeliveryReceipt when messageIds array is empty", async () => {
		mockWorker.mlsDecrypt.mockResolvedValueOnce({
			plaintext: new TextEncoder().encode(
				JSON.stringify({ type: "delivery_receipt", messageIds: [] }),
			),
		});
		pollSpy.mockResolvedValueOnce([makeDeliveryReceiptEnvelope()]);
		const onDeliveryReceipt = vi.fn();

		renderHook(() =>
			useMessages(
				IDENTITY_ID,
				GROUP_ID,
				vi.fn(),
				undefined,
				undefined,
				undefined,
				undefined,
				undefined,
				onDeliveryReceipt,
			),
		);

		await waitFor(() => expect(ackSpy).toHaveBeenCalledWith(TOKEN, ENV_ID));
		expect(onDeliveryReceipt).not.toHaveBeenCalled();
	});

	it("does NOT call onDeliveryReceipt when messageIds exceeds 100-item cap", async () => {
		const tooMany = Array.from({ length: 101 }, (_, i) => `id-${String(i).padStart(3, "0")}`);
		mockWorker.mlsDecrypt.mockResolvedValueOnce({
			plaintext: new TextEncoder().encode(
				JSON.stringify({ type: "delivery_receipt", messageIds: tooMany }),
			),
		});
		pollSpy.mockResolvedValueOnce([makeDeliveryReceiptEnvelope()]);
		const onDeliveryReceipt = vi.fn();

		renderHook(() =>
			useMessages(
				IDENTITY_ID,
				GROUP_ID,
				vi.fn(),
				undefined,
				undefined,
				undefined,
				undefined,
				undefined,
				onDeliveryReceipt,
			),
		);

		await waitFor(() => expect(ackSpy).toHaveBeenCalledWith(TOKEN, ENV_ID));
		expect(onDeliveryReceipt).not.toHaveBeenCalled();
	});

	it("does NOT call onDeliveryReceipt when messageIds contains non-string entries", async () => {
		mockWorker.mlsDecrypt.mockResolvedValueOnce({
			plaintext: new TextEncoder().encode(
				JSON.stringify({
					type: "delivery_receipt",
					messageIds: [42, null, MSG_ID_A],
				}),
			),
		});
		pollSpy.mockResolvedValueOnce([makeDeliveryReceiptEnvelope()]);
		const onDeliveryReceipt = vi.fn();

		renderHook(() =>
			useMessages(
				IDENTITY_ID,
				GROUP_ID,
				vi.fn(),
				undefined,
				undefined,
				undefined,
				undefined,
				undefined,
				onDeliveryReceipt,
			),
		);

		await waitFor(() => expect(ackSpy).toHaveBeenCalledWith(TOKEN, ENV_ID));
		expect(onDeliveryReceipt).not.toHaveBeenCalled();
	});

	it("does NOT forward invalid delivery_receipt (non-string messageIds) to onMessage", async () => {
		mockWorker.mlsDecrypt.mockResolvedValueOnce({
			plaintext: new TextEncoder().encode(
				JSON.stringify({
					type: "delivery_receipt",
					messageIds: [42, null, MSG_ID_A],
				}),
			),
		});
		pollSpy.mockResolvedValueOnce([makeDeliveryReceiptEnvelope()]);
		const onMessage = vi.fn();

		renderHook(() =>
			useMessages(
				IDENTITY_ID,
				GROUP_ID,
				onMessage,
				undefined,
				undefined,
				undefined,
				undefined,
				vi.fn(),
			),
		);

		await waitFor(() => expect(ackSpy).toHaveBeenCalledWith(TOKEN, ENV_ID));
		// Drain pending microtasks so Zustand subscription effects settle before assertions.
		await act(async () => {});
		expect(onMessage).not.toHaveBeenCalled();
	});
});

describe("useMessages — replyTo handling", () => {
	it("parses replyTo from a structured text message", async () => {
		mockWorker.mlsDecrypt.mockResolvedValueOnce({
			plaintext: new TextEncoder().encode(
				JSON.stringify({
					type: "text",
					text: "That is a great idea",
					replyTo: {
						messageId: "orig-uuid-1234",
						excerpt: "Original message text",
					},
				}),
			),
		});
		pollSpy.mockResolvedValueOnce([makeEnvelope()]);

		const received: IncomingMessage[] = [];
		renderHook(() => useMessages(IDENTITY_ID, GROUP_ID, (m) => received.push(m)));

		await waitFor(() => expect(received).toHaveLength(1));
		expect(received[0].text).toBe("That is a great idea");
		expect(received[0].replyTo).toEqual({
			messageId: "orig-uuid-1234",
			excerpt: "Original message text",
		});
	});

	it("clamps excerpt to 100 chars", async () => {
		const longExcerpt = "a".repeat(150);
		mockWorker.mlsDecrypt.mockResolvedValueOnce({
			plaintext: new TextEncoder().encode(
				JSON.stringify({
					type: "text",
					text: "Reply",
					replyTo: { messageId: "mid-1", excerpt: longExcerpt },
				}),
			),
		});
		pollSpy.mockResolvedValueOnce([makeEnvelope()]);

		const received: IncomingMessage[] = [];
		renderHook(() => useMessages(IDENTITY_ID, GROUP_ID, (m) => received.push(m)));

		await waitFor(() => expect(received).toHaveLength(1));
		expect(received[0].replyTo?.excerpt).toBe("a".repeat(100));
	});

	it("ignores replyTo with messageId longer than 36 chars", async () => {
		mockWorker.mlsDecrypt.mockResolvedValueOnce({
			plaintext: new TextEncoder().encode(
				JSON.stringify({
					type: "text",
					text: "Reply",
					replyTo: { messageId: "x".repeat(37), excerpt: "some text" },
				}),
			),
		});
		pollSpy.mockResolvedValueOnce([makeEnvelope()]);

		const received: IncomingMessage[] = [];
		renderHook(() => useMessages(IDENTITY_ID, GROUP_ID, (m) => received.push(m)));

		await waitFor(() => expect(received).toHaveLength(1));
		expect(received[0].replyTo).toBeUndefined();
	});

	it("ignores replyTo with empty messageId", async () => {
		mockWorker.mlsDecrypt.mockResolvedValueOnce({
			plaintext: new TextEncoder().encode(
				JSON.stringify({
					type: "text",
					text: "Reply",
					replyTo: { messageId: "", excerpt: "some text" },
				}),
			),
		});
		pollSpy.mockResolvedValueOnce([makeEnvelope()]);

		const received: IncomingMessage[] = [];
		renderHook(() => useMessages(IDENTITY_ID, GROUP_ID, (m) => received.push(m)));

		await waitFor(() => expect(received).toHaveLength(1));
		expect(received[0].replyTo).toBeUndefined();
	});

	it("plain text (non-JSON) message has undefined replyTo", async () => {
		pollSpy.mockResolvedValueOnce([makeEnvelope()]);

		const received: IncomingMessage[] = [];
		renderHook(() => useMessages(IDENTITY_ID, GROUP_ID, (m) => received.push(m)));

		await waitFor(() => expect(received).toHaveLength(1));
		expect(received[0].text).toBe(DECRYPTED_TEXT);
		expect(received[0].replyTo).toBeUndefined();
	});
});

describe("useMessages — edit handling", () => {
	const TARGET_MSG_ID = "eeeeeeee-eeee-eeee-eeee-000000000001";

	function makeEditEnvelope(): Envelope {
		return {
			id: ENV_ID,
			group_id: GROUP_ID,
			sender: SENDER_ID,
			recipient: null,
			message_type: "Application",
			ciphertext: [20, 21, 22],
			epoch: null,
			created_at: "2026-06-15T12:00:00Z",
			expires_at: null,
		};
	}

	afterEach(() => {
		mockWorker.mlsDecrypt.mockResolvedValue({
			plaintext: new TextEncoder().encode(DECRYPTED_TEXT),
		});
	});

	it("invokes onEdit with groupId, targetMessageId, newText, and senderDeviceId", async () => {
		mockWorker.mlsDecrypt.mockResolvedValueOnce({
			plaintext: new TextEncoder().encode(
				JSON.stringify({
					type: "edit",
					targetMessageId: TARGET_MSG_ID,
					newText: "updated text",
				}),
			),
		});
		pollSpy.mockResolvedValueOnce([makeEditEnvelope()]);
		const onEdit = vi.fn();

		renderHook(() =>
			useMessages(
				IDENTITY_ID,
				GROUP_ID,
				vi.fn(),
				undefined,
				undefined,
				undefined,
				undefined,
				undefined,
				undefined,
				onEdit,
			),
		);

		await waitFor(() => {
			expect(onEdit).toHaveBeenCalledWith(GROUP_ID, TARGET_MSG_ID, "updated text", SENDER_ID);
		});
	});

	it("does NOT forward edit envelope to onMessage", async () => {
		mockWorker.mlsDecrypt.mockResolvedValueOnce({
			plaintext: new TextEncoder().encode(
				JSON.stringify({
					type: "edit",
					targetMessageId: TARGET_MSG_ID,
					newText: "updated text",
				}),
			),
		});
		pollSpy.mockResolvedValueOnce([makeEditEnvelope()]);
		const onMessage = vi.fn();

		renderHook(() =>
			useMessages(
				IDENTITY_ID,
				GROUP_ID,
				onMessage,
				undefined,
				undefined,
				undefined,
				undefined,
				undefined,
				vi.fn(),
			),
		);

		await waitFor(() => expect(ackSpy).toHaveBeenCalledWith(TOKEN, ENV_ID));
		await act(async () => {});
		expect(onMessage).not.toHaveBeenCalled();
	});

	it("does NOT call onEdit when targetMessageId is empty string", async () => {
		mockWorker.mlsDecrypt.mockResolvedValueOnce({
			plaintext: new TextEncoder().encode(
				JSON.stringify({
					type: "edit",
					targetMessageId: "",
					newText: "updated text",
				}),
			),
		});
		pollSpy.mockResolvedValueOnce([makeEditEnvelope()]);
		const onEdit = vi.fn();

		renderHook(() =>
			useMessages(
				IDENTITY_ID,
				GROUP_ID,
				vi.fn(),
				undefined,
				undefined,
				undefined,
				undefined,
				undefined,
				undefined,
				onEdit,
			),
		);

		await waitFor(() => expect(ackSpy).toHaveBeenCalledWith(TOKEN, ENV_ID));
		expect(onEdit).not.toHaveBeenCalled();
	});

	it("does NOT call onEdit when targetMessageId exceeds 36 chars", async () => {
		mockWorker.mlsDecrypt.mockResolvedValueOnce({
			plaintext: new TextEncoder().encode(
				JSON.stringify({
					type: "edit",
					targetMessageId: "x".repeat(37),
					newText: "updated text",
				}),
			),
		});
		pollSpy.mockResolvedValueOnce([makeEditEnvelope()]);
		const onEdit = vi.fn();

		renderHook(() =>
			useMessages(
				IDENTITY_ID,
				GROUP_ID,
				vi.fn(),
				undefined,
				undefined,
				undefined,
				undefined,
				undefined,
				undefined,
				onEdit,
			),
		);

		await waitFor(() => expect(ackSpy).toHaveBeenCalledWith(TOKEN, ENV_ID));
		expect(onEdit).not.toHaveBeenCalled();
	});

	it("does NOT call onEdit when newText is empty string", async () => {
		mockWorker.mlsDecrypt.mockResolvedValueOnce({
			plaintext: new TextEncoder().encode(
				JSON.stringify({
					type: "edit",
					targetMessageId: TARGET_MSG_ID,
					newText: "",
				}),
			),
		});
		pollSpy.mockResolvedValueOnce([makeEditEnvelope()]);
		const onEdit = vi.fn();

		renderHook(() =>
			useMessages(
				IDENTITY_ID,
				GROUP_ID,
				vi.fn(),
				undefined,
				undefined,
				undefined,
				undefined,
				undefined,
				undefined,
				onEdit,
			),
		);

		await waitFor(() => expect(ackSpy).toHaveBeenCalledWith(TOKEN, ENV_ID));
		expect(onEdit).not.toHaveBeenCalled();
	});

	it("does NOT call onEdit when newText exceeds 10000 chars", async () => {
		mockWorker.mlsDecrypt.mockResolvedValueOnce({
			plaintext: new TextEncoder().encode(
				JSON.stringify({
					type: "edit",
					targetMessageId: TARGET_MSG_ID,
					newText: "x".repeat(10_001),
				}),
			),
		});
		pollSpy.mockResolvedValueOnce([makeEditEnvelope()]);
		const onEdit = vi.fn();

		renderHook(() =>
			useMessages(
				IDENTITY_ID,
				GROUP_ID,
				vi.fn(),
				undefined,
				undefined,
				undefined,
				undefined,
				undefined,
				undefined,
				onEdit,
			),
		);

		await waitFor(() => expect(ackSpy).toHaveBeenCalledWith(TOKEN, ENV_ID));
		expect(onEdit).not.toHaveBeenCalled();
	});
});

describe("useMessages — delete handling", () => {
	const TARGET_MSG_ID = "dddddddd-dddd-dddd-dddd-000000000001";

	function makeDeleteEnvelope(): Envelope {
		return {
			id: ENV_ID,
			group_id: GROUP_ID,
			sender: SENDER_ID,
			recipient: null,
			message_type: "Application",
			ciphertext: [30, 31, 32],
			epoch: null,
			created_at: "2026-06-16T12:00:00Z",
			expires_at: null,
		};
	}

	afterEach(() => {
		mockWorker.mlsDecrypt.mockResolvedValue({
			plaintext: new TextEncoder().encode(DECRYPTED_TEXT),
		});
	});

	it("invokes onDelete with groupId and targetMessageId", async () => {
		mockWorker.mlsDecrypt.mockResolvedValueOnce({
			plaintext: new TextEncoder().encode(
				JSON.stringify({ type: "delete", targetMessageId: TARGET_MSG_ID }),
			),
		});
		pollSpy.mockResolvedValueOnce([makeDeleteEnvelope()]);
		const onDelete = vi.fn();

		renderHook(() =>
			useMessages(
				IDENTITY_ID,
				GROUP_ID,
				vi.fn(),
				undefined,
				undefined,
				undefined,
				undefined,
				undefined,
				undefined,
				undefined,
				onDelete,
			),
		);

		await waitFor(() => {
			expect(onDelete).toHaveBeenCalledWith(GROUP_ID, TARGET_MSG_ID);
		});
	});

	it("does NOT forward delete envelope to onMessage", async () => {
		mockWorker.mlsDecrypt.mockResolvedValueOnce({
			plaintext: new TextEncoder().encode(
				JSON.stringify({ type: "delete", targetMessageId: TARGET_MSG_ID }),
			),
		});
		pollSpy.mockResolvedValueOnce([makeDeleteEnvelope()]);
		const onMessage = vi.fn();

		renderHook(() =>
			useMessages(
				IDENTITY_ID,
				GROUP_ID,
				onMessage,
				undefined,
				undefined,
				undefined,
				undefined,
				undefined,
				undefined,
				vi.fn(),
			),
		);

		await waitFor(() => expect(ackSpy).toHaveBeenCalledWith(TOKEN, ENV_ID));
		expect(onMessage).not.toHaveBeenCalled();
	});

	it("does NOT call onDelete when targetMessageId is empty string", async () => {
		mockWorker.mlsDecrypt.mockResolvedValueOnce({
			plaintext: new TextEncoder().encode(JSON.stringify({ type: "delete", targetMessageId: "" })),
		});
		pollSpy.mockResolvedValueOnce([makeDeleteEnvelope()]);
		const onDelete = vi.fn();

		renderHook(() =>
			useMessages(
				IDENTITY_ID,
				GROUP_ID,
				vi.fn(),
				undefined,
				undefined,
				undefined,
				undefined,
				undefined,
				undefined,
				undefined,
				onDelete,
			),
		);

		await waitFor(() => expect(ackSpy).toHaveBeenCalledWith(TOKEN, ENV_ID));
		expect(onDelete).not.toHaveBeenCalled();
		await act(async () => {});
	});

	it("does NOT call onDelete when targetMessageId exceeds 36 chars", async () => {
		mockWorker.mlsDecrypt.mockResolvedValueOnce({
			plaintext: new TextEncoder().encode(
				JSON.stringify({ type: "delete", targetMessageId: "x".repeat(37) }),
			),
		});
		pollSpy.mockResolvedValueOnce([makeDeleteEnvelope()]);
		const onDelete = vi.fn();

		renderHook(() =>
			useMessages(
				IDENTITY_ID,
				GROUP_ID,
				vi.fn(),
				undefined,
				undefined,
				undefined,
				undefined,
				undefined,
				undefined,
				undefined,
				onDelete,
			),
		);

		await waitFor(() => expect(ackSpy).toHaveBeenCalledWith(TOKEN, ENV_ID));
		expect(onDelete).not.toHaveBeenCalled();
		// Two-tick drain: first flush microtasks, then wait one event-loop tick so the
		// setInterval-based next poll fires and settles before test cleanup runs.
		await act(async () => {});
		await act(async () => {
			await new Promise<void>((r) => setTimeout(r, 0));
		});
	});

	it("does NOT call onDelete when targetMessageId is missing", async () => {
		mockWorker.mlsDecrypt.mockResolvedValueOnce({
			plaintext: new TextEncoder().encode(JSON.stringify({ type: "delete" })),
		});
		pollSpy.mockResolvedValueOnce([makeDeleteEnvelope()]);
		const onDelete = vi.fn();

		renderHook(() =>
			useMessages(
				IDENTITY_ID,
				GROUP_ID,
				vi.fn(),
				undefined,
				undefined,
				undefined,
				undefined,
				undefined,
				undefined,
				undefined,
				onDelete,
			),
		);

		await waitFor(() => expect(ackSpy).toHaveBeenCalledWith(TOKEN, ENV_ID));
		expect(onDelete).not.toHaveBeenCalled();
		// Two-tick drain: first flush microtasks, then wait one event-loop tick so the
		// setInterval-based next poll fires and settles before test cleanup runs.
		await act(async () => {});
		await act(async () => {
			await new Promise<void>((r) => setTimeout(r, 0));
		});
	});
});

describe("useMessages — pin handling", () => {
	const TARGET_MSG_ID = "eeeeeeee-eeee-eeee-eeee-000000000001";

	function makePinEnvelope(): Envelope {
		return {
			id: ENV_ID,
			group_id: GROUP_ID,
			sender: SENDER_ID,
			recipient: null,
			message_type: "Application",
			ciphertext: [40, 41, 42],
			epoch: null,
			created_at: "2026-06-16T12:00:00Z",
			expires_at: null,
		};
	}

	afterEach(() => {
		mockWorker.mlsDecrypt.mockResolvedValue({
			plaintext: new TextEncoder().encode(DECRYPTED_TEXT),
		});
	});

	it("invokes onPin with groupId, targetMessageId, and 'pin' action", async () => {
		mockWorker.mlsDecrypt.mockResolvedValueOnce({
			plaintext: new TextEncoder().encode(
				JSON.stringify({ type: "pin", targetMessageId: TARGET_MSG_ID }),
			),
		});
		pollSpy.mockResolvedValueOnce([makePinEnvelope()]);
		const onPin = vi.fn();

		renderHook(() =>
			useMessages(
				IDENTITY_ID,
				GROUP_ID,
				vi.fn(),
				undefined,
				undefined,
				undefined,
				undefined,
				undefined,
				undefined,
				undefined,
				undefined,
				onPin,
			),
		);

		await waitFor(() => {
			expect(onPin).toHaveBeenCalledWith(GROUP_ID, TARGET_MSG_ID, "pin");
		});
	});

	it("invokes onPin with groupId, targetMessageId, and 'unpin' action", async () => {
		mockWorker.mlsDecrypt.mockResolvedValueOnce({
			plaintext: new TextEncoder().encode(
				JSON.stringify({ type: "unpin", targetMessageId: TARGET_MSG_ID }),
			),
		});
		pollSpy.mockResolvedValueOnce([makePinEnvelope()]);
		const onPin = vi.fn();

		renderHook(() =>
			useMessages(
				IDENTITY_ID,
				GROUP_ID,
				vi.fn(),
				undefined,
				undefined,
				undefined,
				undefined,
				undefined,
				undefined,
				undefined,
				undefined,
				onPin,
			),
		);

		await waitFor(() => {
			expect(onPin).toHaveBeenCalledWith(GROUP_ID, TARGET_MSG_ID, "unpin");
		});
	});

	it("does NOT forward pin envelope to onMessage", async () => {
		mockWorker.mlsDecrypt.mockResolvedValueOnce({
			plaintext: new TextEncoder().encode(
				JSON.stringify({ type: "pin", targetMessageId: TARGET_MSG_ID }),
			),
		});
		pollSpy.mockResolvedValueOnce([makePinEnvelope()]);
		const onMessage = vi.fn();

		renderHook(() =>
			useMessages(
				IDENTITY_ID,
				GROUP_ID,
				onMessage,
				undefined,
				undefined,
				undefined,
				undefined,
				undefined,
				undefined,
				undefined,
				vi.fn(),
			),
		);

		await waitFor(() => expect(ackSpy).toHaveBeenCalledWith(TOKEN, ENV_ID));
		expect(onMessage).not.toHaveBeenCalled();
		await act(async () => {});
		await act(async () => {
			await new Promise<void>((r) => setTimeout(r, 0));
		});
	});

	it("does NOT call onPin when targetMessageId is missing", async () => {
		mockWorker.mlsDecrypt.mockResolvedValueOnce({
			plaintext: new TextEncoder().encode(JSON.stringify({ type: "pin" })),
		});
		pollSpy.mockResolvedValueOnce([makePinEnvelope()]);
		const onPin = vi.fn();

		renderHook(() =>
			useMessages(
				IDENTITY_ID,
				GROUP_ID,
				vi.fn(),
				undefined,
				undefined,
				undefined,
				undefined,
				undefined,
				undefined,
				undefined,
				undefined,
				onPin,
			),
		);

		await waitFor(() => expect(ackSpy).toHaveBeenCalledWith(TOKEN, ENV_ID));
		expect(onPin).not.toHaveBeenCalled();
		await act(async () => {});
		await act(async () => {
			await new Promise<void>((r) => setTimeout(r, 0));
		});
	});
});

describe("useMessages — TTL in text messages (receiver-side disappearing)", () => {
	it("sets expiresAt from ttl field in structured text message", async () => {
		mockWorker.mlsDecrypt.mockResolvedValueOnce({
			plaintext: new TextEncoder().encode(
				JSON.stringify({ type: "text", text: "vanishing note", ttl: 300 }),
			),
		});
		pollSpy.mockResolvedValueOnce([makeEnvelope()]);

		const received: IncomingMessage[] = [];
		const before = Date.now();
		renderHook(() => useMessages(IDENTITY_ID, GROUP_ID, (m) => received.push(m)));

		await waitFor(() => expect(received).toHaveLength(1));
		const after = Date.now();
		expect(received[0].text).toBe("vanishing note");
		expect(received[0].expiresAt).toBeGreaterThanOrEqual(before + 300_000);
		expect(received[0].expiresAt).toBeLessThanOrEqual(after + 300_000);
	});

	it("ignores ttl = 0 (yields undefined expiresAt)", async () => {
		mockWorker.mlsDecrypt.mockResolvedValueOnce({
			plaintext: new TextEncoder().encode(
				JSON.stringify({ type: "text", text: "zero ttl", ttl: 0 }),
			),
		});
		pollSpy.mockResolvedValueOnce([makeEnvelope()]);

		const received: IncomingMessage[] = [];
		renderHook(() => useMessages(IDENTITY_ID, GROUP_ID, (m) => received.push(m)));

		await waitFor(() => expect(received).toHaveLength(1));
		expect(received[0].expiresAt).toBeUndefined();
	});

	it("ignores ttl > 604800 (1 week max)", async () => {
		mockWorker.mlsDecrypt.mockResolvedValueOnce({
			plaintext: new TextEncoder().encode(
				JSON.stringify({ type: "text", text: "forever", ttl: 604_801 }),
			),
		});
		pollSpy.mockResolvedValueOnce([makeEnvelope()]);

		const received: IncomingMessage[] = [];
		renderHook(() => useMessages(IDENTITY_ID, GROUP_ID, (m) => received.push(m)));

		await waitFor(() => expect(received).toHaveLength(1));
		expect(received[0].expiresAt).toBeUndefined();
	});

	it("ignores non-numeric ttl", async () => {
		mockWorker.mlsDecrypt.mockResolvedValueOnce({
			plaintext: new TextEncoder().encode(
				JSON.stringify({ type: "text", text: "bad ttl", ttl: "300" }),
			),
		});
		pollSpy.mockResolvedValueOnce([makeEnvelope()]);

		const received: IncomingMessage[] = [];
		renderHook(() => useMessages(IDENTITY_ID, GROUP_ID, (m) => received.push(m)));

		await waitFor(() => expect(received).toHaveLength(1));
		expect(received[0].expiresAt).toBeUndefined();
	});

	it("payload ttl overrides server-provided expires_at", async () => {
		const serverExpires = "2099-01-01T00:00:00.000Z";
		mockWorker.mlsDecrypt.mockResolvedValueOnce({
			plaintext: new TextEncoder().encode(
				JSON.stringify({ type: "text", text: "override", ttl: 3600 }),
			),
		});
		pollSpy.mockResolvedValueOnce([makeEnvelope({ expires_at: serverExpires })]);

		const received: IncomingMessage[] = [];
		const before = Date.now();
		renderHook(() => useMessages(IDENTITY_ID, GROUP_ID, (m) => received.push(m)));

		await waitFor(() => expect(received).toHaveLength(1));
		const after = Date.now();
		// expiresAt should be ≈ Date.now() + 1h, NOT the server's 2099 date.
		expect(received[0].expiresAt).toBeGreaterThanOrEqual(before + 3_600_000);
		expect(received[0].expiresAt).toBeLessThanOrEqual(after + 3_600_000);
		expect(received[0].expiresAt).toBeLessThan(new Date("2099-01-01T00:00:00.000Z").getTime());
	});

	it("parses ttl alongside replyTo in the same message", async () => {
		mockWorker.mlsDecrypt.mockResolvedValueOnce({
			plaintext: new TextEncoder().encode(
				JSON.stringify({
					type: "text",
					text: "combo",
					ttl: 86400,
					replyTo: { messageId: "msg-abc", excerpt: "quoted text" },
				}),
			),
		});
		pollSpy.mockResolvedValueOnce([makeEnvelope()]);

		const received: IncomingMessage[] = [];
		const before = Date.now();
		renderHook(() => useMessages(IDENTITY_ID, GROUP_ID, (m) => received.push(m)));

		await waitFor(() => expect(received).toHaveLength(1));
		const after = Date.now();
		expect(received[0].replyTo).toEqual({ messageId: "msg-abc", excerpt: "quoted text" });
		expect(received[0].expiresAt).toBeGreaterThanOrEqual(before + 86_400_000);
		expect(received[0].expiresAt).toBeLessThanOrEqual(after + 86_400_000);
	});
});

describe("useMessages — presence handling", () => {
	function makePresenceEnvelope(): Envelope {
		return {
			id: ENV_ID,
			group_id: GROUP_ID,
			sender: SENDER_ID,
			recipient: null,
			message_type: "Application",
			ciphertext: [50, 51, 52],
			epoch: null,
			created_at: "2026-06-16T12:00:00Z",
			expires_at: null,
		};
	}

	afterEach(() => {
		mockWorker.mlsDecrypt.mockResolvedValue({
			plaintext: new TextEncoder().encode(DECRYPTED_TEXT),
		});
	});

	it("invokes onPresence with groupId and 'online' status", async () => {
		mockWorker.mlsDecrypt.mockResolvedValueOnce({
			plaintext: new TextEncoder().encode(JSON.stringify({ type: "presence", status: "online" })),
		});
		pollSpy.mockResolvedValueOnce([makePresenceEnvelope()]);
		const onPresence = vi.fn();

		const { unmount } = renderHook(() =>
			useMessages(
				IDENTITY_ID,
				GROUP_ID,
				vi.fn(),
				undefined,
				undefined,
				undefined,
				undefined,
				undefined,
				undefined,
				undefined,
				undefined,
				undefined,
				onPresence,
			),
		);

		await waitFor(() => {
			expect(onPresence).toHaveBeenCalledWith(GROUP_ID, "online");
		});
		await act(async () => {
			unmount();
		});
	});

	it("invokes onPresence with groupId and 'offline' status", async () => {
		mockWorker.mlsDecrypt.mockResolvedValueOnce({
			plaintext: new TextEncoder().encode(JSON.stringify({ type: "presence", status: "offline" })),
		});
		pollSpy.mockResolvedValueOnce([makePresenceEnvelope()]);
		const onPresence = vi.fn();

		const { unmount } = renderHook(() =>
			useMessages(
				IDENTITY_ID,
				GROUP_ID,
				vi.fn(),
				undefined,
				undefined,
				undefined,
				undefined,
				undefined,
				undefined,
				undefined,
				undefined,
				undefined,
				onPresence,
			),
		);

		await waitFor(() => {
			expect(onPresence).toHaveBeenCalledWith(GROUP_ID, "offline");
		});
		await act(async () => {
			unmount();
		});
	});

	it("does NOT forward presence envelope to onMessage", async () => {
		mockWorker.mlsDecrypt.mockResolvedValueOnce({
			plaintext: new TextEncoder().encode(JSON.stringify({ type: "presence", status: "online" })),
		});
		pollSpy.mockResolvedValueOnce([makePresenceEnvelope()]);
		const onMessage = vi.fn();

		const { unmount } = renderHook(() =>
			useMessages(
				IDENTITY_ID,
				GROUP_ID,
				onMessage,
				undefined,
				undefined,
				undefined,
				undefined,
				undefined,
				undefined,
				undefined,
				undefined,
				vi.fn(),
			),
		);

		await waitFor(() => expect(ackSpy).toHaveBeenCalledWith(TOKEN, ENV_ID));
		expect(onMessage).not.toHaveBeenCalled();
		await act(async () => {
			unmount();
		});
	});

	it("does NOT call onPresence when status is invalid", async () => {
		mockWorker.mlsDecrypt.mockResolvedValueOnce({
			plaintext: new TextEncoder().encode(JSON.stringify({ type: "presence", status: "away" })),
		});
		pollSpy.mockResolvedValueOnce([makePresenceEnvelope()]);
		const onPresence = vi.fn();

		const { unmount } = renderHook(() =>
			useMessages(
				IDENTITY_ID,
				GROUP_ID,
				vi.fn(),
				undefined,
				undefined,
				undefined,
				undefined,
				undefined,
				undefined,
				undefined,
				undefined,
				undefined,
				onPresence,
			),
		);

		await waitFor(() => expect(ackSpy).toHaveBeenCalledWith(TOKEN, ENV_ID));
		expect(onPresence).not.toHaveBeenCalled();
		await act(async () => {
			unmount();
		});
	});

	it("does NOT call onPresence when status field is missing", async () => {
		mockWorker.mlsDecrypt.mockResolvedValueOnce({
			plaintext: new TextEncoder().encode(JSON.stringify({ type: "presence" })),
		});
		pollSpy.mockResolvedValueOnce([makePresenceEnvelope()]);
		const onPresence = vi.fn();

		const { unmount } = renderHook(() =>
			useMessages(
				IDENTITY_ID,
				GROUP_ID,
				vi.fn(),
				undefined,
				undefined,
				undefined,
				undefined,
				undefined,
				undefined,
				undefined,
				undefined,
				undefined,
				onPresence,
			),
		);

		await waitFor(() => expect(ackSpy).toHaveBeenCalledWith(TOKEN, ENV_ID));
		expect(onPresence).not.toHaveBeenCalled();
		await act(async () => {
			unmount();
		});
	});
});

describe("useMessages — §9.4.2 chunked video parsing", () => {
	function makeVideoPayload(overrides: Record<string, unknown> = {}): Record<string, unknown> {
		return {
			type: "video",
			chunked: true,
			blobId: "test-video-blob-id",
			blobHash: Array.from({ length: 32 }, () => 0xab),
			mediaKey: Array.from({ length: 32 }, () => 0xcd),
			iv: Array.from({ length: 12 }, () => 0xef),
			totalSize: 33_554_432,
			chunkSize: 16 * 1024 * 1024,
			...overrides,
		};
	}

	afterEach(() => {
		mockWorker.mlsDecrypt.mockResolvedValue({
			plaintext: new TextEncoder().encode(DECRYPTED_TEXT),
		});
	});

	it('parses a valid chunked video payload into media.chunked === true and text === "[video]"', async () => {
		mockWorker.mlsDecrypt.mockResolvedValueOnce({
			plaintext: new TextEncoder().encode(JSON.stringify(makeVideoPayload())),
		});
		pollSpy.mockResolvedValueOnce([makeEnvelope()]);

		const received: IncomingMessage[] = [];
		renderHook(() => useMessages(IDENTITY_ID, GROUP_ID, (m) => received.push(m)));

		await waitFor(() => expect(received).toHaveLength(1));
		expect(received[0].text).toBe("[video]");
		expect(received[0].media?.chunked).toBe(true);
		expect(received[0].media?.blobId).toBe("test-video-blob-id");
		expect(received[0].media?.totalSize).toBe(33_554_432);
		expect(received[0].media?.chunkSize).toBe(16 * 1024 * 1024);
	});

	it("falls through to legacy text handling when totalSize is missing (does NOT set media)", async () => {
		const payload = makeVideoPayload();
		payload.totalSize = undefined;
		mockWorker.mlsDecrypt.mockResolvedValueOnce({
			plaintext: new TextEncoder().encode(JSON.stringify(payload)),
		});
		pollSpy.mockResolvedValueOnce([makeEnvelope()]);

		const received: IncomingMessage[] = [];
		renderHook(() => useMessages(IDENTITY_ID, GROUP_ID, (m) => received.push(m)));

		await waitFor(() => expect(received).toHaveLength(1));
		expect(received[0].media).toBeUndefined();
		// Falls through to legacy text handling — the raw JSON string is used as text.
		expect(received[0].text).toBe(JSON.stringify(payload));
	});

	it("falls through to legacy text handling when chunkSize is missing", async () => {
		const payload = makeVideoPayload();
		payload.chunkSize = undefined;
		mockWorker.mlsDecrypt.mockResolvedValueOnce({
			plaintext: new TextEncoder().encode(JSON.stringify(payload)),
		});
		pollSpy.mockResolvedValueOnce([makeEnvelope()]);

		const received: IncomingMessage[] = [];
		renderHook(() => useMessages(IDENTITY_ID, GROUP_ID, (m) => received.push(m)));

		await waitFor(() => expect(received).toHaveLength(1));
		expect(received[0].media).toBeUndefined();
	});

	it("falls through to legacy text handling when chunked is not exactly true", async () => {
		mockWorker.mlsDecrypt.mockResolvedValueOnce({
			plaintext: new TextEncoder().encode(JSON.stringify(makeVideoPayload({ chunked: "true" }))),
		});
		pollSpy.mockResolvedValueOnce([makeEnvelope()]);

		const received: IncomingMessage[] = [];
		renderHook(() => useMessages(IDENTITY_ID, GROUP_ID, (m) => received.push(m)));

		await waitFor(() => expect(received).toHaveLength(1));
		expect(received[0].media).toBeUndefined();
	});

	it("falls through to legacy text handling when blobHash is not an array", async () => {
		mockWorker.mlsDecrypt.mockResolvedValueOnce({
			plaintext: new TextEncoder().encode(
				JSON.stringify(makeVideoPayload({ blobHash: "not-an-array" })),
			),
		});
		pollSpy.mockResolvedValueOnce([makeEnvelope()]);

		const received: IncomingMessage[] = [];
		renderHook(() => useMessages(IDENTITY_ID, GROUP_ID, (m) => received.push(m)));

		await waitFor(() => expect(received).toHaveLength(1));
		expect(received[0].media).toBeUndefined();
	});

	it("acks the chunked video envelope after processing", async () => {
		mockWorker.mlsDecrypt.mockResolvedValueOnce({
			plaintext: new TextEncoder().encode(JSON.stringify(makeVideoPayload())),
		});
		pollSpy.mockResolvedValueOnce([makeEnvelope()]);

		renderHook(() => useMessages(IDENTITY_ID, GROUP_ID, vi.fn()));

		await waitFor(() => {
			expect(ackSpy).toHaveBeenCalledWith(TOKEN, ENV_ID);
		});
	});
});
