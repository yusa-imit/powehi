/**
 * Per-chat background theme.
 * Users can pick from 6 preset themes (or reset to default) in the InfoPanel.
 * The theme is local-only — never sent to server, never in MLS payload, never logged.
 */
import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { db } from "../db/schema";
import * as CryptoWorkerHook from "../hooks/useCryptoWorker";
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

async function openMayaInfo() {
	fireEvent.click(screen.getByRole("button", { name: /maya akana/i }));
	fireEvent.click(screen.getByRole("button", { name: /info/i }));
	// Selecting a chat kicks off ChatLayout's db.groups.get(...) rehydration effect plus
	// InfoPanel's getVerifiedContact() read; both resolve as a microtask after this
	// synchronous click, so flush them inside act() to avoid the resulting setState
	// landing outside an act() boundary.
	await act(async () => {});
}

async function openDesignTeamInfo() {
	fireEvent.click(screen.getByRole("button", { name: /design team/i }));
	fireEvent.click(screen.getByRole("button", { name: /info/i }));
	// Selecting a chat kicks off ChatLayout's db.groups.get(...) rehydration effect plus
	// InfoPanel's getVerifiedContact() read; both resolve as a microtask after this
	// synchronous click, so flush them inside act() to avoid the resulting setState
	// landing outside an act() boundary.
	await act(async () => {});
}

describe("ChatLayout — per-chat theme", () => {
	beforeEach(async () => {
		await db.verifiedContacts.clear();
		vi.spyOn(CryptoWorkerHook, "useCryptoWorker").mockReturnValue(
			MOCK_WORKER as unknown as ReturnType<typeof CryptoWorkerHook.useCryptoWorker>,
		);
	});

	afterEach(() => {
		cleanup();
		vi.restoreAllMocks();
	});

	it("chat theme section is present in DM InfoPanel", async () => {
		render(<ChatLayout />);
		await openMayaInfo();
		expect(screen.getByTestId("chat-theme-section")).toBeInTheDocument();
	});

	it("chat theme section is present in group InfoPanel", async () => {
		render(<ChatLayout />);
		await openDesignTeamInfo();
		expect(screen.getByTestId("chat-theme-section")).toBeInTheDocument();
	});

	it("theme label shows 'Default' when no theme is set", async () => {
		render(<ChatLayout />);
		await openMayaInfo();
		expect(screen.getByTestId("chat-theme-label")).toHaveTextContent("Default");
	});

	it("default swatch is present", async () => {
		render(<ChatLayout />);
		await openMayaInfo();
		expect(screen.getByTestId("chat-theme-swatch-default")).toBeInTheDocument();
	});

	it("all 6 preset swatches are rendered", async () => {
		render(<ChatLayout />);
		await openMayaInfo();
		for (const key of ["warm", "ocean", "forest", "rose", "lavender", "slate"]) {
			expect(screen.getByTestId(`chat-theme-swatch-${key}`)).toBeInTheDocument();
		}
	});

	it("clicking a theme swatch updates the label", async () => {
		render(<ChatLayout />);
		await openMayaInfo();
		fireEvent.click(screen.getByTestId("chat-theme-swatch-ocean"));
		expect(screen.getByTestId("chat-theme-label")).toHaveTextContent("Ocean");
	});

	it("clicking the default swatch resets the label to Default", async () => {
		render(<ChatLayout />);
		await openMayaInfo();
		fireEvent.click(screen.getByTestId("chat-theme-swatch-warm"));
		expect(screen.getByTestId("chat-theme-label")).toHaveTextContent("Warm");
		fireEvent.click(screen.getByTestId("chat-theme-swatch-default"));
		expect(screen.getByTestId("chat-theme-label")).toHaveTextContent("Default");
	});

	it("message list scroll area changes background when a theme is applied", async () => {
		render(<ChatLayout />);
		await openMayaInfo();
		const scrollEl = screen.getByTestId("message-list-scroll");
		const defaultBg = scrollEl.style.background;
		fireEvent.click(screen.getByTestId("chat-theme-swatch-forest"));
		// Close panel so message list is visible and re-renders with new bg
		fireEvent.click(screen.getByRole("button", { name: /close/i }));
		const themedBg = screen.getByTestId("message-list-scroll").style.background;
		expect(themedBg).not.toBe(defaultBg);
	});

	it("message list background resets to default when theme is cleared", async () => {
		render(<ChatLayout />);
		await openMayaInfo();
		fireEvent.click(screen.getByTestId("chat-theme-swatch-rose"));
		fireEvent.click(screen.getByRole("button", { name: /close/i }));
		const themed = screen.getByTestId("message-list-scroll").style.background;
		fireEvent.click(screen.getByRole("button", { name: /info/i }));
		fireEvent.click(screen.getByTestId("chat-theme-swatch-default"));
		fireEvent.click(screen.getByRole("button", { name: /close/i }));
		const reset = screen.getByTestId("message-list-scroll").style.background;
		expect(reset).not.toBe(themed);
	});

	it("theme is per-chat — switching chats shows independent themes", async () => {
		render(<ChatLayout />);
		// Set ocean theme for Maya
		await openMayaInfo();
		fireEvent.click(screen.getByTestId("chat-theme-swatch-ocean"));
		fireEvent.click(screen.getByRole("button", { name: /close/i }));
		const mayaBg = screen.getByTestId("message-list-scroll").style.background;

		// Switch to Design Team (no theme)
		await openDesignTeamInfo();
		fireEvent.click(screen.getByRole("button", { name: /close/i }));
		const teamBg = screen.getByTestId("message-list-scroll").style.background;

		expect(mayaBg).not.toBe(teamBg);
	});

	it("theme persists when switching away and back", async () => {
		render(<ChatLayout />);
		await openMayaInfo();
		fireEvent.click(screen.getByTestId("chat-theme-swatch-lavender"));
		fireEvent.click(screen.getByRole("button", { name: /close/i }));
		const before = screen.getByTestId("message-list-scroll").style.background;

		// Switch to another chat
		fireEvent.click(screen.getByRole("button", { name: /design team/i }));
		// Switch back to Maya
		fireEvent.click(screen.getByRole("button", { name: /maya akana/i }));
		// Flush the db.groups.get(...) rehydration effect kicked off by the chat switches
		// above, so the resulting setState doesn't land outside an act() boundary.
		await act(async () => {});
		const after = screen.getByTestId("message-list-scroll").style.background;
		expect(after).toBe(before);
	});

	it("persists the chosen theme to Dexie GroupRow so it survives a reload", async () => {
		const MAYA_GROUP_ID = "11111111-1111-1111-1111-111111111111";
		await db.groups.clear();
		await db.groups.add({
			id: MAYA_GROUP_ID,
			name: "Maya Akana",
			mlsStateB64: "",
			lastActivity: Date.now(),
		});
		render(<ChatLayout />);
		await openMayaInfo();
		fireEvent.click(screen.getByTestId("chat-theme-swatch-forest"));
		await waitFor(async () => {
			const row = await db.groups.get(MAYA_GROUP_ID);
			expect(row?.chatTheme).toBe("forest");
		});
	});

	it("rehydrates a persisted theme from Dexie when switching to that chat", async () => {
		const MAYA_GROUP_ID = "11111111-1111-1111-1111-111111111111";
		await db.groups.clear();
		await db.groups.add({
			id: MAYA_GROUP_ID,
			name: "Maya Akana",
			mlsStateB64: "",
			lastActivity: Date.now(),
			chatTheme: "slate",
		});
		render(<ChatLayout />);
		await openMayaInfo();
		await waitFor(() => expect(screen.getByTestId("chat-theme-label")).toHaveTextContent("Slate"));
	});

	it("theme swatches have descriptive aria-labels", async () => {
		render(<ChatLayout />);
		await openMayaInfo();
		expect(screen.getByLabelText("Default theme")).toBeInTheDocument();
		expect(screen.getByLabelText("Warm theme")).toBeInTheDocument();
		expect(screen.getByLabelText("Slate theme")).toBeInTheDocument();
	});
});
