/**
 * Slow mode for group chats.
 * Admins can set a per-message cooldown delay (Off / 5s / 30s / 1m / 5m / 1h).
 * While the cooldown is active, the send button is replaced with a countdown badge.
 */
import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { db } from "../db/schema";
import * as CryptoWorkerHook from "../hooks/useCryptoWorker";
import * as AuthStore from "../store/auth";
import { ChatLayout } from "./ChatLayout";

const DESIGN_TEAM_GROUP_ID = "44444444-4444-4444-4444-444444444444";

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

async function openDesignTeamInfo() {
	fireEvent.click(screen.getByRole("button", { name: /design team/i }));
	fireEvent.click(screen.getByRole("button", { name: /info/i }));
	// Selecting a group chat kicks off ChatLayout's db.groups.get(...) rehydration effect
	// (slowModeDelay/disappearingTtl/etc.) plus InfoPanel's getVerifiedContact() read; both go
	// through fake-indexeddb, which schedules its callbacks via real setTimeout internally, so
	// under `vi.useFakeTimers()` a plain microtask flush isn't enough — advance the fake timers
	// too, inside act(), so the resulting setState doesn't land outside an act() boundary.
	await act(async () => {
		if (vi.isFakeTimers()) {
			await vi.runOnlyPendingTimersAsync();
			await vi.runOnlyPendingTimersAsync();
			await vi.runOnlyPendingTimersAsync();
		}
	});
}

describe("ChatLayout — slow mode", () => {
	beforeEach(async () => {
		await db.verifiedContacts.clear();
		vi.spyOn(CryptoWorkerHook, "useCryptoWorker").mockReturnValue(
			MOCK_WORKER as unknown as ReturnType<typeof CryptoWorkerHook.useCryptoWorker>,
		);
		vi.useFakeTimers({ shouldAdvanceTime: false });
	});

	afterEach(async () => {
		// Pending countdown/interval timers fire state updates on flush (e.g. the 1s
		// countdown ticker started by "countdown decrements over time"); must be wrapped in
		// act() to avoid the "not wrapped in act" warning.
		if (vi.isFakeTimers()) {
			await act(async () => {
				await vi.runOnlyPendingTimersAsync();
			});
		}
		vi.useRealTimers();
		cleanup();
		vi.restoreAllMocks();
	});

	it("slow-mode section appears in group InfoPanel", async () => {
		render(<ChatLayout />);
		await openDesignTeamInfo();
		expect(screen.getByText(/slow mode/i)).toBeInTheDocument();
	});

	it("slow-mode section is NOT shown for DM chats", async () => {
		render(<ChatLayout />);
		fireEvent.click(screen.getByRole("button", { name: /maya akana/i }));
		fireEvent.click(screen.getByRole("button", { name: /info/i }));
		// InfoPanel kicks off an async getVerifiedContact() read on mount; flush it inside
		// act() so the resulting setState doesn't land outside an act() boundary.
		await act(async () => {
			if (vi.isFakeTimers()) {
				await vi.runOnlyPendingTimersAsync();
			}
		});
		expect(screen.queryByText(/slow mode/i)).not.toBeInTheDocument();
	});

	it("admin sees a select to change the delay", async () => {
		vi.spyOn(AuthStore.useAuthStore, "getState").mockReturnValue({
			myHandle: "finn",
		} as ReturnType<typeof AuthStore.useAuthStore.getState>);
		render(<ChatLayout />);
		await openDesignTeamInfo();
		expect(screen.getByTestId("slow-mode-select")).toBeInTheDocument();
	});

	it("non-admin sees the read-only delay row (no select)", async () => {
		vi.spyOn(AuthStore.useAuthStore, "getState").mockReturnValue({
			myHandle: "maya",
		} as ReturnType<typeof AuthStore.useAuthStore.getState>);
		render(<ChatLayout />);
		await openDesignTeamInfo();
		expect(screen.queryByTestId("slow-mode-select")).not.toBeInTheDocument();
		expect(screen.getByTestId("slow-mode-member-row")).toBeInTheDocument();
	});

	it("admin can set slow mode to 30s via the select", async () => {
		vi.spyOn(AuthStore.useAuthStore, "getState").mockReturnValue({
			myHandle: "finn",
		} as ReturnType<typeof AuthStore.useAuthStore.getState>);
		render(<ChatLayout />);
		await openDesignTeamInfo();
		const sel = screen.getByTestId("slow-mode-select") as HTMLSelectElement;
		fireEvent.change(sel, { target: { value: "30" } });
		expect(sel.value).toBe("30");
	});

	it("slow-mode banner appears in composer when delay > 0", async () => {
		vi.spyOn(AuthStore.useAuthStore, "getState").mockReturnValue({
			myHandle: "finn",
		} as ReturnType<typeof AuthStore.useAuthStore.getState>);
		render(<ChatLayout />);
		await openDesignTeamInfo();
		fireEvent.change(screen.getByTestId("slow-mode-select"), { target: { value: "30" } });
		fireEvent.click(screen.getByRole("button", { name: /close/i }));
		expect(screen.getByTestId("slow-mode-banner")).toBeInTheDocument();
		expect(screen.getByTestId("slow-mode-banner")).toHaveTextContent("30s between messages");
	});

	it("slow-mode banner is absent when delay is Off", async () => {
		render(<ChatLayout />);
		fireEvent.click(screen.getByRole("button", { name: /design team/i }));
		// Selecting a group chat kicks off ChatLayout's db.groups.get(...) rehydration effect,
		// which resolves as a microtask after this synchronous click; flush it inside act() so
		// the resulting setState doesn't land outside an act() boundary.
		await act(async () => {});
		expect(screen.queryByTestId("slow-mode-banner")).not.toBeInTheDocument();
	});

	it("sending a message while slow mode is active shows countdown badge", async () => {
		vi.spyOn(AuthStore.useAuthStore, "getState").mockReturnValue({
			myHandle: "finn",
		} as ReturnType<typeof AuthStore.useAuthStore.getState>);
		render(<ChatLayout />);
		await openDesignTeamInfo();
		fireEvent.change(screen.getByTestId("slow-mode-select"), { target: { value: "5" } });
		fireEvent.click(screen.getByRole("button", { name: /close/i }));

		const textarea = screen.getByTestId("composer-textarea");
		fireEvent.change(textarea, { target: { value: "hello slow" } });
		fireEvent.click(screen.getByRole("button", { name: /send message/i }));

		// After send, the cooldown badge replaces the send button synchronously.
		expect(screen.getByTestId("slow-mode-countdown")).toBeInTheDocument();
		expect(screen.getByTestId("slow-mode-countdown").textContent).toMatch(/\ds/);
	});

	it("send button is absent during cooldown (countdown shown instead)", async () => {
		vi.spyOn(AuthStore.useAuthStore, "getState").mockReturnValue({
			myHandle: "finn",
		} as ReturnType<typeof AuthStore.useAuthStore.getState>);
		render(<ChatLayout />);
		await openDesignTeamInfo();
		fireEvent.change(screen.getByTestId("slow-mode-select"), { target: { value: "5" } });
		fireEvent.click(screen.getByRole("button", { name: /close/i }));

		fireEvent.change(screen.getByTestId("composer-textarea"), { target: { value: "test" } });
		fireEvent.click(screen.getByRole("button", { name: /send message/i }));

		// The send button is replaced by the countdown badge.
		expect(screen.queryByRole("button", { name: /send message/i })).not.toBeInTheDocument();
	});

	it("countdown decrements over time", async () => {
		vi.spyOn(AuthStore.useAuthStore, "getState").mockReturnValue({
			myHandle: "finn",
		} as ReturnType<typeof AuthStore.useAuthStore.getState>);
		render(<ChatLayout />);
		await openDesignTeamInfo();
		fireEvent.change(screen.getByTestId("slow-mode-select"), { target: { value: "5" } });
		fireEvent.click(screen.getByRole("button", { name: /close/i }));

		fireEvent.change(screen.getByTestId("composer-textarea"), { target: { value: "tick test" } });
		fireEvent.click(screen.getByRole("button", { name: /send message/i }));

		expect(screen.getByTestId("slow-mode-countdown")).toBeInTheDocument();
		const initialSec = Number.parseInt(
			screen.getByTestId("slow-mode-countdown").textContent ?? "0",
		);

		await act(async () => {
			vi.advanceTimersByTime(1500);
		});

		const laterSec = Number.parseInt(screen.getByTestId("slow-mode-countdown").textContent ?? "0");
		expect(laterSec).toBeLessThan(initialSec);
	});

	it("slow mode selector default value is Off (0)", async () => {
		vi.spyOn(AuthStore.useAuthStore, "getState").mockReturnValue({
			myHandle: "finn",
		} as ReturnType<typeof AuthStore.useAuthStore.getState>);
		render(<ChatLayout />);
		await openDesignTeamInfo();
		const sel = screen.getByTestId("slow-mode-select") as HTMLSelectElement;
		expect(sel.value).toBe("0");
	});

	it("persists the chosen slow-mode delay to Dexie GroupRow so it survives a reload", async () => {
		vi.useRealTimers();
		await db.groups.clear();
		await db.groups.add({
			id: DESIGN_TEAM_GROUP_ID,
			name: "Design Team",
			mlsStateB64: "",
			lastActivity: Date.now(),
		});
		vi.spyOn(AuthStore.useAuthStore, "getState").mockReturnValue({
			myHandle: "finn",
		} as ReturnType<typeof AuthStore.useAuthStore.getState>);
		render(<ChatLayout />);
		await openDesignTeamInfo();
		fireEvent.change(screen.getByTestId("slow-mode-select"), { target: { value: "60" } });
		await waitFor(async () => {
			const row = await db.groups.get(DESIGN_TEAM_GROUP_ID);
			expect(row?.slowModeDelay).toBe(60);
		});
	});

	it("rehydrates a persisted slow-mode delay from Dexie when switching to that chat", async () => {
		vi.useRealTimers();
		await db.groups.clear();
		await db.groups.add({
			id: DESIGN_TEAM_GROUP_ID,
			name: "Design Team",
			mlsStateB64: "",
			lastActivity: Date.now(),
			slowModeDelay: 300,
		});
		vi.spyOn(AuthStore.useAuthStore, "getState").mockReturnValue({
			myHandle: "finn",
		} as ReturnType<typeof AuthStore.useAuthStore.getState>);
		render(<ChatLayout />);
		await openDesignTeamInfo();
		await waitFor(() => {
			const sel = screen.getByTestId("slow-mode-select") as HTMLSelectElement;
			expect(sel.value).toBe("300");
		});
	});
});
