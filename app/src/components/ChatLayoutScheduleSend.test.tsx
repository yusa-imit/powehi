import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { db } from "../db/schema";
import * as CryptoWorkerHook from "../hooks/useCryptoWorker";
import * as UseMessagesModule from "../hooks/useMessages";
import { useAuthStore } from "../store/auth";
import { ChatLayout } from "./ChatLayout";

const MOCK_WORKER = {
	mlsGroupMembers: vi.fn(async () => [
		{ leafIndex: 0, sigKeyHex: "aa".repeat(64) },
		{ leafIndex: 1, sigKeyHex: "bb".repeat(64) },
	]),
	mlsComputeSafetyNumber: vi.fn(async () => ({
		safetyNumber:
			"689053 337949 184798 288064 134849 362568 560227 765408 921198 315305 693006 807986",
	})),
	mlsEncrypt: vi.fn(async () => ({ ciphertext: new Uint8Array([0xde, 0xad]) })),
	mlsDecrypt: vi.fn(async () => ({ plaintext: new Uint8Array() })),
	encryptDbField: vi.fn(async (v: string) => v),
	decryptDbField: vi.fn(async (v: string) => v),
};

describe("ChatLayout — scheduled send", () => {
	beforeEach(async () => {
		await db.verifiedContacts.clear();
		// Scheduled-message persistence (this file's fix) now writes to db.messages keyed by
		// the default active chat's (Maya) fixed mlsGroupId — clear so a leftover row from an
		// earlier test doesn't rehydrate into the next test's initial render, same bug class
		// fixed across ChatLayout*.test.tsx (cycle 335).
		await db.messages.clear();
		vi.spyOn(CryptoWorkerHook, "useCryptoWorker").mockReturnValue(
			MOCK_WORKER as unknown as ReturnType<typeof CryptoWorkerHook.useCryptoWorker>,
		);
		vi.spyOn(UseMessagesModule, "useMessages").mockImplementation(() => {});
	});

	afterEach(async () => {
		vi.useRealTimers();
		await act(async () => {});
		// Unmount BEFORE restoring mocks — several new tests in this file set a real
		// deviceId/sessionToken and exercise the fireScheduled sweep's Dexie writes, which can
		// still have effects/timers pending at test end. Restoring useMessages to its real
		// implementation on an already-unmounted tree (rather than a still-mounted one) avoids
		// a stray post-restore re-render hitting the real hook with a different hook-call shape
		// than the mocked no-op, which otherwise crashes as an unhandled exception between tests.
		cleanup();
		vi.restoreAllMocks();
		useAuthStore.setState({ phase: "login", deviceId: null, sessionToken: null });
	});

	it("send-later button is hidden when composer is empty", async () => {
		await act(async () => {
			render(<ChatLayout />);
		});
		expect(screen.queryByTestId("send-later-btn")).not.toBeInTheDocument();
	});

	it("send-later button appears when text is typed", async () => {
		await act(async () => {
			render(<ChatLayout />);
		});
		const textarea = screen.getByPlaceholderText(/Message.*encrypted/);
		await act(async () => {
			fireEvent.change(textarea, { target: { value: "Hello future" } });
		});
		expect(screen.getByTestId("send-later-btn")).toBeInTheDocument();
	});

	it("clicking send-later opens the schedule picker", async () => {
		await act(async () => {
			render(<ChatLayout />);
		});
		const textarea = screen.getByPlaceholderText(/Message.*encrypted/);
		await act(async () => {
			fireEvent.change(textarea, { target: { value: "Test" } });
		});
		await act(async () => {
			fireEvent.click(screen.getByTestId("send-later-btn"));
		});
		expect(screen.getByTestId("schedule-picker")).toBeInTheDocument();
	});

	it("schedule picker has a datetime-local input", async () => {
		await act(async () => {
			render(<ChatLayout />);
		});
		const textarea = screen.getByPlaceholderText(/Message.*encrypted/);
		await act(async () => {
			fireEvent.change(textarea, { target: { value: "Test" } });
		});
		fireEvent.click(screen.getByTestId("send-later-btn"));
		expect(screen.getByTestId("schedule-datetime-input")).toBeInTheDocument();
	});

	it("clicking the cancel button in the picker closes it", async () => {
		await act(async () => {
			render(<ChatLayout />);
		});
		const textarea = screen.getByPlaceholderText(/Message.*encrypted/);
		await act(async () => {
			fireEvent.change(textarea, { target: { value: "Test" } });
		});
		fireEvent.click(screen.getByTestId("send-later-btn"));
		expect(screen.getByTestId("schedule-picker")).toBeInTheDocument();
		fireEvent.click(screen.getByTestId("schedule-cancel"));
		expect(screen.queryByTestId("schedule-picker")).not.toBeInTheDocument();
	});

	it("scheduling a message creates a bubble with a scheduled badge", async () => {
		await act(async () => {
			render(<ChatLayout />);
		});
		const textarea = screen.getByPlaceholderText(/Message.*encrypted/) as HTMLTextAreaElement;
		await act(async () => {
			fireEvent.change(textarea, { target: { value: "Scheduled hello" } });
		});
		fireEvent.click(screen.getByTestId("send-later-btn"));

		// Set a future datetime value and confirm.
		const future = new Date(Date.now() + 3_600_000);
		const pad = (n: number) => String(n).padStart(2, "0");
		const dt = `${future.getFullYear()}-${pad(future.getMonth() + 1)}-${pad(future.getDate())}T${pad(future.getHours())}:${pad(future.getMinutes())}`;
		const input = screen.getByTestId("schedule-datetime-input") as HTMLInputElement;
		await act(async () => {
			fireEvent.change(input, { target: { value: dt } });
		});
		await act(async () => {
			fireEvent.click(screen.getByTestId("schedule-confirm"));
		});

		expect(screen.getByText("Scheduled hello")).toBeInTheDocument();
		expect(screen.getByTestId("scheduled-badge")).toBeInTheDocument();
	});

	it("schedule picker closes after confirming a schedule", async () => {
		await act(async () => {
			render(<ChatLayout />);
		});
		const textarea = screen.getByPlaceholderText(/Message.*encrypted/);
		await act(async () => {
			fireEvent.change(textarea, { target: { value: "Soon" } });
		});
		fireEvent.click(screen.getByTestId("send-later-btn"));

		const future = new Date(Date.now() + 3_600_000);
		const pad = (n: number) => String(n).padStart(2, "0");
		const dt = `${future.getFullYear()}-${pad(future.getMonth() + 1)}-${pad(future.getDate())}T${pad(future.getHours())}:${pad(future.getMinutes())}`;
		await act(async () => {
			fireEvent.change(screen.getByTestId("schedule-datetime-input"), { target: { value: dt } });
		});
		await act(async () => {
			fireEvent.click(screen.getByTestId("schedule-confirm"));
		});

		expect(screen.queryByTestId("schedule-picker")).not.toBeInTheDocument();
	});

	it("composer is cleared after scheduling", async () => {
		await act(async () => {
			render(<ChatLayout />);
		});
		const textarea = screen.getByPlaceholderText(/Message.*encrypted/) as HTMLTextAreaElement;
		await act(async () => {
			fireEvent.change(textarea, { target: { value: "Later message" } });
		});
		fireEvent.click(screen.getByTestId("send-later-btn"));

		const future = new Date(Date.now() + 3_600_000);
		const pad = (n: number) => String(n).padStart(2, "0");
		const dt = `${future.getFullYear()}-${pad(future.getMonth() + 1)}-${pad(future.getDate())}T${pad(future.getHours())}:${pad(future.getMinutes())}`;
		await act(async () => {
			fireEvent.change(screen.getByTestId("schedule-datetime-input"), { target: { value: dt } });
		});
		await act(async () => {
			fireEvent.click(screen.getByTestId("schedule-confirm"));
		});

		expect(textarea.value).toBe("");
	});

	it("scheduled message shows a cancel button", async () => {
		await act(async () => {
			render(<ChatLayout />);
		});
		const textarea = screen.getByPlaceholderText(/Message.*encrypted/);
		await act(async () => {
			fireEvent.change(textarea, { target: { value: "Cancel me" } });
		});
		fireEvent.click(screen.getByTestId("send-later-btn"));

		const future = new Date(Date.now() + 3_600_000);
		const pad = (n: number) => String(n).padStart(2, "0");
		const dt = `${future.getFullYear()}-${pad(future.getMonth() + 1)}-${pad(future.getDate())}T${pad(future.getHours())}:${pad(future.getMinutes())}`;
		await act(async () => {
			fireEvent.change(screen.getByTestId("schedule-datetime-input"), { target: { value: dt } });
		});
		await act(async () => {
			fireEvent.click(screen.getByTestId("schedule-confirm"));
		});

		expect(screen.getByTestId("cancel-scheduled-btn")).toBeInTheDocument();
	});

	it("clicking cancel removes the scheduled message", async () => {
		await act(async () => {
			render(<ChatLayout />);
		});
		const textarea = screen.getByPlaceholderText(/Message.*encrypted/);
		await act(async () => {
			fireEvent.change(textarea, { target: { value: "Removable" } });
		});
		fireEvent.click(screen.getByTestId("send-later-btn"));

		const future = new Date(Date.now() + 3_600_000);
		const pad = (n: number) => String(n).padStart(2, "0");
		const dt = `${future.getFullYear()}-${pad(future.getMonth() + 1)}-${pad(future.getDate())}T${pad(future.getHours())}:${pad(future.getMinutes())}`;
		await act(async () => {
			fireEvent.change(screen.getByTestId("schedule-datetime-input"), { target: { value: dt } });
		});
		await act(async () => {
			fireEvent.click(screen.getByTestId("schedule-confirm"));
		});

		expect(screen.getByText("Removable")).toBeInTheDocument();
		await act(async () => {
			fireEvent.click(screen.getByTestId("cancel-scheduled-btn"));
		});
		expect(screen.queryByText("Removable")).not.toBeInTheDocument();
	});

	it("scheduled badge shows a time string", async () => {
		await act(async () => {
			render(<ChatLayout />);
		});
		const textarea = screen.getByPlaceholderText(/Message.*encrypted/);
		await act(async () => {
			fireEvent.change(textarea, { target: { value: "Time check" } });
		});
		fireEvent.click(screen.getByTestId("send-later-btn"));

		const future = new Date(Date.now() + 3_600_000);
		const pad = (n: number) => String(n).padStart(2, "0");
		const dt = `${future.getFullYear()}-${pad(future.getMonth() + 1)}-${pad(future.getDate())}T${pad(future.getHours())}:${pad(future.getMinutes())}`;
		await act(async () => {
			fireEvent.change(screen.getByTestId("schedule-datetime-input"), { target: { value: dt } });
		});
		await act(async () => {
			fireEvent.click(screen.getByTestId("schedule-confirm"));
		});

		const badge = screen.getByTestId("scheduled-badge");
		expect(badge.textContent).toMatch(/Scheduled\s*·/);
	});

	it("scheduled message fires when timer reaches scheduled time", async () => {
		vi.useFakeTimers();
		await act(async () => {
			render(<ChatLayout />);
		});
		const textarea = screen.getByPlaceholderText(/Message.*encrypted/);
		await act(async () => {
			fireEvent.change(textarea, { target: { value: "Fire me" } });
		});
		fireEvent.click(screen.getByTestId("send-later-btn"));

		// Schedule 2 minutes in the future — far enough that HH:MM format gives a clearly future time.
		const future = new Date(Date.now() + 120_000);
		const pad = (n: number) => String(n).padStart(2, "0");
		const dt = `${future.getFullYear()}-${pad(future.getMonth() + 1)}-${pad(future.getDate())}T${pad(future.getHours())}:${pad(future.getMinutes())}`;
		await act(async () => {
			fireEvent.change(screen.getByTestId("schedule-datetime-input"), { target: { value: dt } });
		});
		await act(async () => {
			fireEvent.click(screen.getByTestId("schedule-confirm"));
		});

		// Badge should exist before time elapses.
		expect(screen.getByTestId("scheduled-badge")).toBeInTheDocument();

		// Advance fake time past the scheduled time + one sweep interval (10s) to trigger the sweep.
		await act(async () => {
			vi.advanceTimersByTime(130_000);
		});

		// After act, the sweep has run and the scheduledFor field is cleared.
		expect(screen.queryByTestId("scheduled-badge")).not.toBeInTheDocument();
	});

	it("multiple scheduled messages can be queued independently", async () => {
		await act(async () => {
			render(<ChatLayout />);
		});

		const scheduleOne = async (text: string) => {
			const textarea = screen.getByPlaceholderText(/Message.*encrypted/);
			await act(async () => {
				fireEvent.change(textarea, { target: { value: text } });
			});
			fireEvent.click(screen.getByTestId("send-later-btn"));
			const future = new Date(Date.now() + 3_600_000);
			const pad = (n: number) => String(n).padStart(2, "0");
			const dt = `${future.getFullYear()}-${pad(future.getMonth() + 1)}-${pad(future.getDate())}T${pad(future.getHours())}:${pad(future.getMinutes())}`;
			await act(async () => {
				fireEvent.change(screen.getByTestId("schedule-datetime-input"), { target: { value: dt } });
			});
			await act(async () => {
				fireEvent.click(screen.getByTestId("schedule-confirm"));
			});
		};

		await scheduleOne("First");
		await scheduleOne("Second");

		expect(screen.getByText("First")).toBeInTheDocument();
		expect(screen.getByText("Second")).toBeInTheDocument();
		const badges = screen.getAllByTestId("scheduled-badge");
		expect(badges).toHaveLength(2);
	});

	it("scheduling a message persists a row to Dexie with scheduledFor and an empty ciphertextB64 sentinel", async () => {
		useAuthStore.setState({ phase: "app", deviceId: "my-device-sched", sessionToken: "tok-sched" });
		await act(async () => {
			render(<ChatLayout />);
		});
		const textarea = screen.getByPlaceholderText(/Message.*encrypted/);
		await act(async () => {
			fireEvent.change(textarea, { target: { value: "Persist me" } });
		});
		fireEvent.click(screen.getByTestId("send-later-btn"));

		const future = new Date(Date.now() + 3_600_000);
		const pad = (n: number) => String(n).padStart(2, "0");
		const dt = `${future.getFullYear()}-${pad(future.getMonth() + 1)}-${pad(future.getDate())}T${pad(future.getHours())}:${pad(future.getMinutes())}`;
		await act(async () => {
			fireEvent.change(screen.getByTestId("schedule-datetime-input"), { target: { value: dt } });
		});
		await act(async () => {
			fireEvent.click(screen.getByTestId("schedule-confirm"));
		});

		await waitFor(async () => {
			const rows = await db.messages
				.where("groupId")
				.equals("11111111-1111-1111-1111-111111111111")
				.toArray();
			const row = rows.find((r) => r.scheduledFor !== undefined);
			expect(row).toBeDefined();
			expect(row?.ciphertextB64).toBe("");
			expect(row?.senderDeviceId).toBe("my-device-sched");
		});
	});

	it("cancelling a scheduled message deletes its persisted Dexie row", async () => {
		useAuthStore.setState({ phase: "app", deviceId: "my-device-sched", sessionToken: "tok-sched" });
		await act(async () => {
			render(<ChatLayout />);
		});
		const textarea = screen.getByPlaceholderText(/Message.*encrypted/);
		await act(async () => {
			fireEvent.change(textarea, { target: { value: "Cancel me too" } });
		});
		fireEvent.click(screen.getByTestId("send-later-btn"));

		const future = new Date(Date.now() + 3_600_000);
		const pad = (n: number) => String(n).padStart(2, "0");
		const dt = `${future.getFullYear()}-${pad(future.getMonth() + 1)}-${pad(future.getDate())}T${pad(future.getHours())}:${pad(future.getMinutes())}`;
		await act(async () => {
			fireEvent.change(screen.getByTestId("schedule-datetime-input"), { target: { value: dt } });
		});
		await act(async () => {
			fireEvent.click(screen.getByTestId("schedule-confirm"));
		});

		await waitFor(async () => {
			const rows = await db.messages
				.where("groupId")
				.equals("11111111-1111-1111-1111-111111111111")
				.toArray();
			expect(rows.some((r) => r.scheduledFor !== undefined)).toBe(true);
		});

		await act(async () => {
			fireEvent.click(screen.getByTestId("cancel-scheduled-btn"));
		});

		await waitFor(async () => {
			const rows = await db.messages
				.where("groupId")
				.equals("11111111-1111-1111-1111-111111111111")
				.toArray();
			expect(rows.some((r) => r.scheduledFor !== undefined)).toBe(false);
		});
	});

	it("firing a scheduled message clears scheduledFor in the persisted Dexie row", async () => {
		useAuthStore.setState({ phase: "app", deviceId: "my-device-sched", sessionToken: "tok-sched" });
		vi.useFakeTimers();
		await act(async () => {
			render(<ChatLayout />);
		});
		const textarea = screen.getByPlaceholderText(/Message.*encrypted/);
		await act(async () => {
			fireEvent.change(textarea, { target: { value: "Fire and persist" } });
		});
		fireEvent.click(screen.getByTestId("send-later-btn"));

		const future = new Date(Date.now() + 120_000);
		const pad = (n: number) => String(n).padStart(2, "0");
		const dt = `${future.getFullYear()}-${pad(future.getMonth() + 1)}-${pad(future.getDate())}T${pad(future.getHours())}:${pad(future.getMinutes())}`;
		await act(async () => {
			fireEvent.change(screen.getByTestId("schedule-datetime-input"), { target: { value: dt } });
		});
		await act(async () => {
			fireEvent.click(screen.getByTestId("schedule-confirm"));
		});

		await act(async () => {
			vi.advanceTimersByTime(130_000);
		});
		// fake-indexeddb schedules IDBRequest success callbacks via a real setTimeout(0)
		// internally — switch back to real timers so the pending clearMessageScheduled
		// write (fired synchronously, not awaited, inside the sweep's interval callback)
		// actually settles, same pattern as elsewhere in this file switching timers.
		vi.useRealTimers();

		await waitFor(async () => {
			const rows = await db.messages
				.where("groupId")
				.equals("11111111-1111-1111-1111-111111111111")
				.toArray();
			const row = rows.find((r) => r.plaintextB64);
			expect(row).toBeDefined();
			expect(row?.scheduledFor).toBeUndefined();
		});
	});

	it("rehydrates a persisted scheduled message (with its badge) from Dexie on mount", async () => {
		useAuthStore.setState({ phase: "app", deviceId: "my-device-sched", sessionToken: "tok-sched" });
		const scheduledFor = Date.now() + 3_600_000;
		await db.messages.put({
			id: "sched-seeded-1",
			groupId: "11111111-1111-1111-1111-111111111111",
			ciphertextB64: "",
			senderDeviceId: "my-device-sched",
			epochSeq: 1,
			receivedAt: Date.now(),
			plaintextB64: btoa("Seeded scheduled"),
			scheduledFor,
		});

		await act(async () => {
			render(<ChatLayout />);
		});

		expect(await screen.findByText("Seeded scheduled")).toBeInTheDocument();
		expect(screen.getByTestId("scheduled-badge")).toBeInTheDocument();
	});
});
