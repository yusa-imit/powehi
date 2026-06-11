import { act, renderHook, waitFor } from "@testing-library/react";
import { type MockInstance, afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import * as MessagesModule from "../api/messages";
import type { Envelope } from "../api/messages";
import { useAuthStore } from "../store/auth";
import * as CryptoWorkerHook from "./useCryptoWorker";
import { type IncomingMessage, useMessages } from "./useMessages";

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
	useAuthStore.setState({ phase: "app", deviceId: "my-device", sessionToken: TOKEN });
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
		useAuthStore.setState({ phase: "login", deviceId: null, sessionToken: null });

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
