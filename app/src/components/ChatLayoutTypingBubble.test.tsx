import { fireEvent, render, screen, waitFor } from "@testing-library/react";
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

describe("ChatLayout — typing bubble in message list", () => {
	beforeEach(async () => {
		await db.verifiedContacts.clear();
		vi.spyOn(CryptoWorkerHook, "useCryptoWorker").mockReturnValue(
			MOCK_WORKER as unknown as ReturnType<typeof CryptoWorkerHook.useCryptoWorker>,
		);
		vi.spyOn(UseMessagesModule, "useMessages").mockImplementation(() => {});
	});

	afterEach(() => {
		vi.restoreAllMocks();
	});

	it("typing bubble is visible when the active chat has typing:true (seed: Sam)", async () => {
		render(<ChatLayout />);
		// Sam has typing: true in seed data
		const samBtn = screen.getAllByRole("button", { name: /sam/i })[0];
		fireEvent.click(samBtn);
		await waitFor(() => expect(screen.getByTestId("typing-bubble")).toBeInTheDocument());
	});

	it("typing bubble has data-testid 'typing-bubble'", async () => {
		render(<ChatLayout />);
		fireEvent.click(screen.getAllByRole("button", { name: /sam/i })[0]);
		await waitFor(() => expect(screen.getByTestId("typing-bubble")).toBeInTheDocument());
	});

	it("typing bubble contains the animated dots (typing-dots)", async () => {
		render(<ChatLayout />);
		fireEvent.click(screen.getAllByRole("button", { name: /sam/i })[0]);
		await waitFor(() => expect(screen.getByTestId("typing-bubble")).toBeInTheDocument());
		const bubble = screen.getByTestId("typing-bubble");
		expect(bubble.querySelector('[data-testid="typing-dots"]')).toBeTruthy();
	});

	it("typing bubble shows the partner's initial avatar (S for Sam)", async () => {
		render(<ChatLayout />);
		fireEvent.click(screen.getAllByRole("button", { name: /sam/i })[0]);
		await waitFor(() => expect(screen.getByTestId("typing-bubble")).toBeInTheDocument());
		const bubble = screen.getByTestId("typing-bubble");
		expect(bubble.textContent).toContain("S");
	});

	it("typing bubble is absent when switching to a chat with typing:false", async () => {
		render(<ChatLayout />);
		// Jordan has typing: false in seed data
		fireEvent.click(screen.getByRole("button", { name: /jordan/i }));
		expect(screen.queryByTestId("typing-bubble")).not.toBeInTheDocument();
	});

	it("typing bubble disappears when switching away from typing chat", async () => {
		render(<ChatLayout />);
		// First open Sam (typing: true)
		fireEvent.click(screen.getAllByRole("button", { name: /sam/i })[0]);
		await waitFor(() => expect(screen.getByTestId("typing-bubble")).toBeInTheDocument());
		// Switch to Jordan (typing: false)
		fireEvent.click(screen.getByRole("button", { name: /jordan/i }));
		expect(screen.queryByTestId("typing-bubble")).not.toBeInTheDocument();
	});

	it("sidebar typing-dots are still present when chat has typing:true", () => {
		render(<ChatLayout />);
		// Sam (typing: true) should show typing-dots in the sidebar
		const dots = screen.getAllByTestId("typing-dots");
		expect(dots.length).toBeGreaterThan(0);
	});
});
