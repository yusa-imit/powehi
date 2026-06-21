import { fireEvent, render, screen, waitFor } from "@testing-library/react";
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

describe("ChatLayout — per-chat sound toggle", () => {
	beforeEach(async () => {
		await db.verifiedContacts.clear();
		vi.spyOn(CryptoWorkerHook, "useCryptoWorker").mockReturnValue(
			MOCK_WORKER as unknown as ReturnType<typeof CryptoWorkerHook.useCryptoWorker>,
		);
	});

	afterEach(() => {
		vi.restoreAllMocks();
	});

	it("Sound row in InfoPanel shows 'On' by default", async () => {
		render(<ChatLayout />);
		fireEvent.click(screen.getByRole("button", { name: /jordan/i }));
		fireEvent.click(screen.getByRole("button", { name: /info/i }));
		const soundBtn = screen.getByRole("button", { name: /sound/i });
		expect(soundBtn).toHaveTextContent("On");
	});

	it("Sound toggle flips to 'Off' when clicked", async () => {
		render(<ChatLayout />);
		fireEvent.click(screen.getByRole("button", { name: /jordan/i }));
		fireEvent.click(screen.getByRole("button", { name: /info/i }));
		const soundBtn = screen.getByRole("button", { name: /sound/i });
		fireEvent.click(soundBtn);
		await waitFor(() =>
			expect(screen.getByRole("button", { name: /sound/i })).toHaveTextContent("Off"),
		);
	});

	it("Sound toggle flips back to 'On' when clicked again", async () => {
		render(<ChatLayout />);
		fireEvent.click(screen.getByRole("button", { name: /jordan/i }));
		fireEvent.click(screen.getByRole("button", { name: /info/i }));
		const soundBtn = () => screen.getByRole("button", { name: /sound/i });
		fireEvent.click(soundBtn());
		await waitFor(() => expect(soundBtn()).toHaveTextContent("Off"));
		fireEvent.click(soundBtn());
		await waitFor(() => expect(soundBtn()).toHaveTextContent("On"));
	});

	it("sound is chat-specific — toggling Jordan leaves Maya's sound On", async () => {
		render(<ChatLayout />);
		// Mute Jordan's sound
		fireEvent.click(screen.getByRole("button", { name: /jordan/i }));
		fireEvent.click(screen.getByRole("button", { name: /info/i }));
		fireEvent.click(screen.getByRole("button", { name: /sound/i }));
		await waitFor(() =>
			expect(screen.getByRole("button", { name: /sound/i })).toHaveTextContent("Off"),
		);
		// Switch to Maya — InfoPanel updates to Maya's data
		fireEvent.click(screen.getAllByRole("button", { name: /maya akana/i })[0]);
		// Maya's sound row must still show "On"
		await waitFor(() =>
			expect(screen.getByRole("button", { name: /sound/i })).toHaveTextContent("On"),
		);
	});

	it("sound and mute are independent — both can be toggled separately", async () => {
		render(<ChatLayout />);
		fireEvent.click(screen.getByRole("button", { name: /jordan/i }));
		fireEvent.click(screen.getByRole("button", { name: /info/i }));
		// Toggle only sound Off
		fireEvent.click(screen.getByRole("button", { name: /sound/i }));
		await waitFor(() =>
			expect(screen.getByRole("button", { name: /sound/i })).toHaveTextContent("Off"),
		);
		// Mute remains Off (unaffected)
		expect(screen.getByRole("button", { name: /mute/i })).toHaveTextContent("Off");
	});
});
