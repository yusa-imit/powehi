import { act, renderHook, waitFor } from "@testing-library/react";
import { type MockInstance, afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import * as MessagesModule from "../api/messages";
import type { Envelope } from "../api/messages";
import { useAuthStore } from "../store/auth";
import * as CryptoWorkerHook from "./useCryptoWorker";
import { type NewGroupEvent, useWelcomePoller } from "./useWelcomePoller";

const IDENTITY_ID = "identity-001";
const SENDER_ID = "dddddddd-dddd-dddd-dddd-dddddddddddd";
const ENV_ID = "eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee";
const TOKEN = "session-token-abc";
const JOINED_GROUP_ID = "ffffffff-ffff-ffff-ffff-ffffffffffff";

const mockWorker = {
	mlsJoinGroup: vi.fn(async () => ({ groupId: JOINED_GROUP_ID })),
};

let pollSpy: MockInstance<typeof MessagesModule.pollMessages>;
let ackSpy: MockInstance<typeof MessagesModule.ackMessage>;

beforeEach(() => {
	pollSpy = vi.spyOn(MessagesModule, "pollMessages").mockResolvedValue([] as Envelope[]);
	ackSpy = vi.spyOn(MessagesModule, "ackMessage").mockResolvedValue(undefined);

	vi.spyOn(CryptoWorkerHook, "useCryptoWorker").mockReturnValue(
		mockWorker as unknown as ReturnType<typeof CryptoWorkerHook.useCryptoWorker>,
	);
	useAuthStore.setState({ phase: "app", deviceId: "my-device", sessionToken: TOKEN });
});

afterEach(() => {
	vi.restoreAllMocks();
	mockWorker.mlsJoinGroup.mockReset();
	mockWorker.mlsJoinGroup.mockResolvedValue({ groupId: JOINED_GROUP_ID });
	// useAuthStore is a real zustand store the hook subscribes to via useSyncExternalStore;
	// @testing-library/react's auto-cleanup unmount runs as an outer afterEach (registered at
	// module import time), so this reset still lands on a mounted component and must be
	// wrapped in act() to avoid the "not wrapped in act" warning.
	act(() => {
		useAuthStore.setState({ phase: "login", deviceId: null, sessionToken: null });
	});
});

function makeEnvelope(overrides: Partial<Envelope> = {}): Envelope {
	return {
		id: ENV_ID,
		group_id: JOINED_GROUP_ID,
		sender: SENDER_ID,
		recipient: null,
		message_type: "Welcome",
		ciphertext: [1, 2, 3],
		epoch: null,
		created_at: "2026-06-10T12:00:00Z",
		expires_at: null,
		...overrides,
	};
}

describe("useWelcomePoller", () => {
	it("polls immediately on mount", async () => {
		const { unmount } = renderHook(() => useWelcomePoller(IDENTITY_ID, vi.fn()));

		await waitFor(() => {
			expect(pollSpy).toHaveBeenCalledWith(TOKEN, undefined, undefined);
		});
		await act(async () => {
			unmount();
		});
	});

	it("calls mlsJoinGroup and acks envelope on Welcome", async () => {
		pollSpy.mockResolvedValueOnce([makeEnvelope()]);

		const { unmount } = renderHook(() => useWelcomePoller(IDENTITY_ID, vi.fn()));

		await waitFor(() => {
			expect(mockWorker.mlsJoinGroup).toHaveBeenCalledWith(IDENTITY_ID, expect.any(Uint8Array));
		});
		await waitFor(() => {
			expect(ackSpy).toHaveBeenCalledWith(TOKEN, ENV_ID);
		});
		await act(async () => {
			unmount();
		});
	});

	it("fires onNewGroup with correct groupId and senderDeviceId", async () => {
		pollSpy.mockResolvedValueOnce([makeEnvelope()]);

		const received: NewGroupEvent[] = [];
		const { unmount } = renderHook(() => useWelcomePoller(IDENTITY_ID, (e) => received.push(e)));

		await waitFor(() => {
			expect(received).toHaveLength(1);
		});

		expect(received[0].groupId).toBe(JOINED_GROUP_ID);
		expect(received[0].senderDeviceId).toBe(SENDER_ID);
		await act(async () => {
			unmount();
		});
	});

	it("does not fire onNewGroup for Application envelopes", async () => {
		pollSpy.mockResolvedValueOnce([makeEnvelope({ message_type: "Application" })]);
		const onNewGroup = vi.fn();

		const { unmount } = renderHook(() => useWelcomePoller(IDENTITY_ID, onNewGroup));

		await waitFor(() => {
			expect(pollSpy).toHaveBeenCalled();
		});
		await new Promise<void>((r) => setTimeout(r, 10));
		expect(onNewGroup).not.toHaveBeenCalled();
		expect(mockWorker.mlsJoinGroup).not.toHaveBeenCalled();
		await act(async () => {
			unmount();
		});
	});

	it("does not ack Application envelopes (leaves them for useMessages)", async () => {
		pollSpy.mockResolvedValueOnce([makeEnvelope({ message_type: "Application" })]);

		renderHook(() => useWelcomePoller(IDENTITY_ID, vi.fn()));

		await waitFor(() => {
			expect(pollSpy).toHaveBeenCalled();
		});
		await new Promise<void>((r) => setTimeout(r, 10));
		expect(ackSpy).not.toHaveBeenCalled();
	});

	it("acks Commit envelopes silently without firing onNewGroup", async () => {
		pollSpy.mockResolvedValueOnce([makeEnvelope({ message_type: "Commit" })]);
		const onNewGroup = vi.fn();

		renderHook(() => useWelcomePoller(IDENTITY_ID, onNewGroup));

		await waitFor(() => {
			expect(ackSpy).toHaveBeenCalledWith(TOKEN, ENV_ID);
		});
		expect(onNewGroup).not.toHaveBeenCalled();
		expect(mockWorker.mlsJoinGroup).not.toHaveBeenCalled();
	});

	it("acks Proposal envelopes silently without firing onNewGroup", async () => {
		pollSpy.mockResolvedValueOnce([makeEnvelope({ message_type: "Proposal" })]);
		const onNewGroup = vi.fn();

		renderHook(() => useWelcomePoller(IDENTITY_ID, onNewGroup));

		await waitFor(() => {
			expect(ackSpy).toHaveBeenCalledWith(TOKEN, ENV_ID);
		});
		expect(onNewGroup).not.toHaveBeenCalled();
	});

	it("does not ack Welcome when mlsJoinGroup fails", async () => {
		mockWorker.mlsJoinGroup.mockRejectedValueOnce(new Error("stale_welcome"));
		pollSpy.mockResolvedValueOnce([makeEnvelope()]);

		renderHook(() => useWelcomePoller(IDENTITY_ID, vi.fn()));

		await waitFor(() => {
			expect(mockWorker.mlsJoinGroup).toHaveBeenCalled();
		});
		await new Promise<void>((r) => setTimeout(r, 20));
		expect(ackSpy).not.toHaveBeenCalled();
	});

	it("logs a content-free diagnostic when mlsJoinGroup fails", async () => {
		const consoleSpy = vi.spyOn(console, "error").mockImplementation(() => {});
		mockWorker.mlsJoinGroup.mockRejectedValueOnce(new Error("stale_welcome"));
		pollSpy.mockResolvedValueOnce([makeEnvelope()]);

		renderHook(() => useWelcomePoller(IDENTITY_ID, vi.fn()));

		await waitFor(() => {
			expect(consoleSpy).toHaveBeenCalledWith("welcome_join_failed", "Error", "stale_welcome");
		});
		consoleSpy.mockRestore();
	});

	it("does not ack when onNewGroup callback throws (ack-after-callback ordering)", async () => {
		pollSpy.mockResolvedValueOnce([makeEnvelope()]);
		const throwingCallback = vi.fn().mockImplementation(() => {
			throw new Error("setChats panic");
		});

		renderHook(() => useWelcomePoller(IDENTITY_ID, throwingCallback));

		await waitFor(() => {
			expect(throwingCallback).toHaveBeenCalled();
		});
		await new Promise<void>((r) => setTimeout(r, 20));
		// Ack must NOT have been sent because callback threw before ackMessage was reached.
		expect(ackSpy).not.toHaveBeenCalled();
	});

	it("advances the fetch cursor past a page this poller neither acks nor joins (cycle 352 livelock fix — an all-Application-plus-failed-Welcome page must not pin the cursor, or 'no new group ever arrives' forever)", async () => {
		vi.useFakeTimers();
		try {
			vi.setSystemTime(0);
			mockWorker.mlsJoinGroup.mockRejectedValueOnce(new Error("stale_welcome"));
			const page = [
				// Left for useMessages — never acked by this hook.
				makeEnvelope({
					id: "skip-app",
					message_type: "Application",
					created_at: "2026-06-10T12:00:01Z",
				}),
				// Fails to join — never acked either.
				makeEnvelope({
					id: "skip-welcome-failed",
					message_type: "Welcome",
					created_at: "2026-06-10T12:00:02Z",
				}),
			];
			pollSpy.mockResolvedValueOnce(page);

			renderHook(() => useWelcomePoller(IDENTITY_ID, vi.fn()));
			await act(async () => {
				await vi.advanceTimersByTimeAsync(0);
			});
			expect(pollSpy).toHaveBeenNthCalledWith(1, TOKEN, undefined, undefined);
			expect(ackSpy).not.toHaveBeenCalled();

			pollSpy.mockResolvedValueOnce([]);
			await act(async () => {
				await vi.advanceTimersByTimeAsync(3_000);
			});
			// Regression would re-send (TOKEN, undefined, undefined) here, identical
			// to call 1 — pinning delivery of every future Welcome forever.
			expect(pollSpy).toHaveBeenNthCalledWith(
				2,
				TOKEN,
				"2026-06-10T12:00:02Z",
				"skip-welcome-failed",
			);
		} finally {
			vi.useRealTimers();
		}
	});

	it("does not poll when sessionToken is absent", async () => {
		useAuthStore.setState({ phase: "login", deviceId: null, sessionToken: null });

		await act(async () => {
			renderHook(() => useWelcomePoller(IDENTITY_ID, vi.fn()));
		});

		expect(pollSpy).not.toHaveBeenCalled();
	});

	it("does not poll when identityId is null", async () => {
		await act(async () => {
			renderHook(() => useWelcomePoller(null, vi.fn()));
		});

		expect(pollSpy).not.toHaveBeenCalled();
	});

	it("stops polling after unmount", async () => {
		vi.useFakeTimers();
		try {
			const { unmount } = renderHook(() => useWelcomePoller(IDENTITY_ID, vi.fn()));

			await act(async () => {
				vi.advanceTimersByTime(0);
				await Promise.resolve();
				await Promise.resolve();
			});

			const countBefore = pollSpy.mock.calls.length;
			unmount();

			vi.advanceTimersByTime(30_000);
			await Promise.resolve();

			expect(pollSpy.mock.calls.length).toBeLessThanOrEqual(countBefore + 1);
		} finally {
			vi.useRealTimers();
		}
	});
});
