import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { db } from "../db/schema";
import * as CryptoWorkerHook from "../hooks/useCryptoWorker";
import * as UseMessagesModule from "../hooks/useMessages";
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
		vi.spyOn(CryptoWorkerHook, "useCryptoWorker").mockReturnValue(
			MOCK_WORKER as unknown as ReturnType<typeof CryptoWorkerHook.useCryptoWorker>,
		);
		vi.spyOn(UseMessagesModule, "useMessages").mockImplementation(() => {});
	});

	afterEach(async () => {
		vi.useRealTimers();
		await act(async () => {});
		vi.restoreAllMocks();
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
});
