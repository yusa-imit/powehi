import { act, renderHook, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import * as MessagesModule from "../api/messages";
import type { Envelope } from "../api/messages";
import { useAuthStore } from "../store/auth";
import * as CryptoWorkerHook from "./useCryptoWorker";
import { type IncomingMessage, useMessages } from "./useMessages";

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
};

let pollSpy: ReturnType<typeof vi.spyOn>;
let ackSpy: ReturnType<typeof vi.spyOn>;

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
	useAuthStore.setState({ phase: "login", deviceId: null, sessionToken: null });
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

	it("acks non-Application messages silently without calling onMessage", async () => {
		pollSpy.mockResolvedValueOnce([makeEnvelope({ message_type: "Welcome" })]);
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
