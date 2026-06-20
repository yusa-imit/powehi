import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { db } from "../db/schema";
import * as CryptoWorkerHook from "../hooks/useCryptoWorker";
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

describe("ChatLayout — draft message saving", () => {
	beforeEach(async () => {
		await db.verifiedContacts.clear();
		vi.spyOn(CryptoWorkerHook, "useCryptoWorker").mockReturnValue(
			MOCK_WORKER as unknown as ReturnType<typeof CryptoWorkerHook.useCryptoWorker>,
		);
		useAuthStore.setState({
			sessionToken: "tok-draft",
			identityId: "id-draft",
			deviceId: "dev-draft",
		});
	});

	afterEach(() => {
		vi.restoreAllMocks();
	});

	it("draft is preserved when switching chats", async () => {
		render(<ChatLayout />);
		const textarea = screen.getByPlaceholderText(/encrypted/i);
		fireEvent.change(textarea, { target: { value: "hello maya" } });
		expect(textarea).toHaveValue("hello maya");

		fireEvent.click(screen.getByRole("button", { name: /jordan/i }));
		fireEvent.click(screen.getAllByRole("button", { name: /maya akana/i })[0]);

		await waitFor(() => {
			expect(screen.getByPlaceholderText(/encrypted/i)).toHaveValue("hello maya");
		});
	});

	it("chat 2 composer is empty when selected (no cross-contamination)", async () => {
		render(<ChatLayout />);
		const textarea = screen.getByPlaceholderText(/encrypted/i);
		fireEvent.change(textarea, { target: { value: "only for maya" } });

		fireEvent.click(screen.getByRole("button", { name: /jordan/i }));

		await waitFor(() => {
			expect(screen.getByPlaceholderText(/encrypted/i)).toHaveValue("");
		});
	});

	it("draft is cleared after sending", async () => {
		render(<ChatLayout />);
		const textarea = screen.getByPlaceholderText(/encrypted/i);
		fireEvent.change(textarea, { target: { value: "to be sent" } });

		fireEvent.keyDown(textarea, { key: "Enter", shiftKey: false });

		fireEvent.click(screen.getByRole("button", { name: /jordan/i }));
		fireEvent.click(screen.getAllByRole("button", { name: /maya akana/i })[0]);

		await waitFor(() => {
			expect(screen.getByPlaceholderText(/encrypted/i)).toHaveValue("");
		});
	});

	it("different chats have independent drafts", async () => {
		render(<ChatLayout />);
		const textarea = screen.getByPlaceholderText(/encrypted/i);
		fireEvent.change(textarea, { target: { value: "hello" } });

		fireEvent.click(screen.getByRole("button", { name: /jordan/i }));
		await waitFor(() => {
			expect(screen.getByPlaceholderText(/encrypted/i)).toHaveValue("");
		});
		fireEvent.change(screen.getByPlaceholderText(/encrypted/i), { target: { value: "world" } });

		fireEvent.click(screen.getAllByRole("button", { name: /maya akana/i })[0]);
		await waitFor(() => {
			expect(screen.getByPlaceholderText(/encrypted/i)).toHaveValue("hello");
		});

		fireEvent.click(screen.getByRole("button", { name: /jordan/i }));
		await waitFor(() => {
			expect(screen.getByPlaceholderText(/encrypted/i)).toHaveValue("world");
		});
	});

	it("draft is empty initially for a fresh chat (no saved draft)", () => {
		render(<ChatLayout />);
		expect(screen.getByPlaceholderText(/encrypted/i)).toHaveValue("");
	});
});
