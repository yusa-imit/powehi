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
		renderHook(() => useMessages(IDENTITY_ID, GROUP_ID, vi.fn()));

		await waitFor(() => {
			expect(pollSpy).toHaveBeenCalledWith(TOKEN, undefined);
		});
	});

	it("decrypts Application message and invokes onMessage", async () => {
		pollSpy.mockResolvedValueOnce([makeEnvelope()]);

		const received: IncomingMessage[] = [];
		renderHook(() => useMessages(IDENTITY_ID, GROUP_ID, (m) => received.push(m)));

		await waitFor(() => {
			expect(received).toHaveLength(1);
		});

		expect(received[0].text).toBe(DECRYPTED_TEXT);
		expect(received[0].senderId).toBe(SENDER_ID);
		expect(received[0].id).toBe(ENV_ID);
	});

	it("acks Application message after successful decrypt", async () => {
		pollSpy.mockResolvedValueOnce([makeEnvelope()]);

		renderHook(() => useMessages(IDENTITY_ID, GROUP_ID, vi.fn()));

		await waitFor(() => {
			expect(ackSpy).toHaveBeenCalledWith(TOKEN, ENV_ID);
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

	it("does not call onMessage when decrypt fails (swallows error)", async () => {
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
			useMessages(IDENTITY_ID, GROUP_ID, vi.fn(), undefined, undefined, undefined, onReadReceipt),
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
			useMessages(IDENTITY_ID, GROUP_ID, onMessage, undefined, undefined, undefined, vi.fn()),
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
			useMessages(IDENTITY_ID, GROUP_ID, vi.fn(), undefined, undefined, undefined, vi.fn()),
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
			useMessages(IDENTITY_ID, GROUP_ID, vi.fn(), undefined, undefined, undefined, onReadReceipt),
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
			useMessages(IDENTITY_ID, GROUP_ID, vi.fn(), undefined, undefined, undefined, onReadReceipt),
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
			useMessages(IDENTITY_ID, GROUP_ID, vi.fn(), undefined, undefined, undefined, onReadReceipt),
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
			useMessages(IDENTITY_ID, GROUP_ID, onMessage, undefined, undefined, undefined, vi.fn()),
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
					replyTo: { messageId: "orig-uuid-1234", excerpt: "Original message text" },
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
				JSON.stringify({ type: "edit", targetMessageId: TARGET_MSG_ID, newText: "updated text" }),
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
				JSON.stringify({ type: "edit", targetMessageId: TARGET_MSG_ID, newText: "updated text" }),
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
				JSON.stringify({ type: "edit", targetMessageId: "", newText: "updated text" }),
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
				onEdit,
			),
		);

		await waitFor(() => expect(ackSpy).toHaveBeenCalledWith(TOKEN, ENV_ID));
		expect(onEdit).not.toHaveBeenCalled();
	});

	it("does NOT call onEdit when targetMessageId exceeds 36 chars", async () => {
		mockWorker.mlsDecrypt.mockResolvedValueOnce({
			plaintext: new TextEncoder().encode(
				JSON.stringify({ type: "edit", targetMessageId: "x".repeat(37), newText: "updated text" }),
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
				onEdit,
			),
		);

		await waitFor(() => expect(ackSpy).toHaveBeenCalledWith(TOKEN, ENV_ID));
		expect(onEdit).not.toHaveBeenCalled();
	});

	it("does NOT call onEdit when newText is empty string", async () => {
		mockWorker.mlsDecrypt.mockResolvedValueOnce({
			plaintext: new TextEncoder().encode(
				JSON.stringify({ type: "edit", targetMessageId: TARGET_MSG_ID, newText: "" }),
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
				onDelete,
			),
		);

		await waitFor(() => expect(ackSpy).toHaveBeenCalledWith(TOKEN, ENV_ID));
		expect(onDelete).not.toHaveBeenCalled();
		await act(async () => {});
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
				onDelete,
			),
		);

		await waitFor(() => expect(ackSpy).toHaveBeenCalledWith(TOKEN, ENV_ID));
		expect(onDelete).not.toHaveBeenCalled();
		await act(async () => {});
	});
});
