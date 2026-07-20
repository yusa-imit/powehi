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

function openDesignTeamInfo() {
	fireEvent.click(screen.getByRole("button", { name: /design team/i }));
	fireEvent.click(screen.getByRole("button", { name: /info/i }));
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
		if (vi.isFakeTimers()) {
			await vi.runOnlyPendingTimersAsync();
		}
		vi.useRealTimers();
		cleanup();
		vi.restoreAllMocks();
	});

	it("slow-mode section appears in group InfoPanel", () => {
		render(<ChatLayout />);
		openDesignTeamInfo();
		expect(screen.getByText(/slow mode/i)).toBeInTheDocument();
	});

	it("slow-mode section is NOT shown for DM chats", () => {
		render(<ChatLayout />);
		fireEvent.click(screen.getByRole("button", { name: /maya akana/i }));
		fireEvent.click(screen.getByRole("button", { name: /info/i }));
		expect(screen.queryByText(/slow mode/i)).not.toBeInTheDocument();
	});

	it("admin sees a select to change the delay", () => {
		vi.spyOn(AuthStore.useAuthStore, "getState").mockReturnValue({
			myHandle: "finn",
		} as ReturnType<typeof AuthStore.useAuthStore.getState>);
		render(<ChatLayout />);
		openDesignTeamInfo();
		expect(screen.getByTestId("slow-mode-select")).toBeInTheDocument();
	});

	it("non-admin sees the read-only delay row (no select)", () => {
		vi.spyOn(AuthStore.useAuthStore, "getState").mockReturnValue({
			myHandle: "maya",
		} as ReturnType<typeof AuthStore.useAuthStore.getState>);
		render(<ChatLayout />);
		openDesignTeamInfo();
		expect(screen.queryByTestId("slow-mode-select")).not.toBeInTheDocument();
		expect(screen.getByTestId("slow-mode-member-row")).toBeInTheDocument();
	});

	it("admin can set slow mode to 30s via the select", () => {
		vi.spyOn(AuthStore.useAuthStore, "getState").mockReturnValue({
			myHandle: "finn",
		} as ReturnType<typeof AuthStore.useAuthStore.getState>);
		render(<ChatLayout />);
		openDesignTeamInfo();
		const sel = screen.getByTestId("slow-mode-select") as HTMLSelectElement;
		fireEvent.change(sel, { target: { value: "30" } });
		expect(sel.value).toBe("30");
	});

	it("slow-mode banner appears in composer when delay > 0", () => {
		vi.spyOn(AuthStore.useAuthStore, "getState").mockReturnValue({
			myHandle: "finn",
		} as ReturnType<typeof AuthStore.useAuthStore.getState>);
		render(<ChatLayout />);
		openDesignTeamInfo();
		fireEvent.change(screen.getByTestId("slow-mode-select"), { target: { value: "30" } });
		fireEvent.click(screen.getByRole("button", { name: /close/i }));
		expect(screen.getByTestId("slow-mode-banner")).toBeInTheDocument();
		expect(screen.getByTestId("slow-mode-banner")).toHaveTextContent("30s between messages");
	});

	it("slow-mode banner is absent when delay is Off", () => {
		render(<ChatLayout />);
		fireEvent.click(screen.getByRole("button", { name: /design team/i }));
		expect(screen.queryByTestId("slow-mode-banner")).not.toBeInTheDocument();
	});

	it("sending a message while slow mode is active shows countdown badge", () => {
		vi.spyOn(AuthStore.useAuthStore, "getState").mockReturnValue({
			myHandle: "finn",
		} as ReturnType<typeof AuthStore.useAuthStore.getState>);
		render(<ChatLayout />);
		openDesignTeamInfo();
		fireEvent.change(screen.getByTestId("slow-mode-select"), { target: { value: "5" } });
		fireEvent.click(screen.getByRole("button", { name: /close/i }));

		const textarea = screen.getByTestId("composer-textarea");
		fireEvent.change(textarea, { target: { value: "hello slow" } });
		fireEvent.click(screen.getByRole("button", { name: /send message/i }));

		// After send, the cooldown badge replaces the send button synchronously.
		expect(screen.getByTestId("slow-mode-countdown")).toBeInTheDocument();
		expect(screen.getByTestId("slow-mode-countdown").textContent).toMatch(/\ds/);
	});

	it("send button is absent during cooldown (countdown shown instead)", () => {
		vi.spyOn(AuthStore.useAuthStore, "getState").mockReturnValue({
			myHandle: "finn",
		} as ReturnType<typeof AuthStore.useAuthStore.getState>);
		render(<ChatLayout />);
		openDesignTeamInfo();
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
		openDesignTeamInfo();
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

	it("slow mode selector default value is Off (0)", () => {
		vi.spyOn(AuthStore.useAuthStore, "getState").mockReturnValue({
			myHandle: "finn",
		} as ReturnType<typeof AuthStore.useAuthStore.getState>);
		render(<ChatLayout />);
		openDesignTeamInfo();
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
		openDesignTeamInfo();
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
		openDesignTeamInfo();
		await waitFor(() => {
			const sel = screen.getByTestId("slow-mode-select") as HTMLSelectElement;
			expect(sel.value).toBe("300");
		});
	});
});
