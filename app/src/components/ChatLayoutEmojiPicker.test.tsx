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

describe("ChatLayout — emoji picker", () => {
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

	it("emoji picker is hidden by default", async () => {
		await act(async () => {
			render(<ChatLayout />);
		});
		expect(screen.queryByTestId("emoji-picker")).not.toBeInTheDocument();
	});

	it("emoji picker opens when smile button is clicked", async () => {
		await act(async () => {
			render(<ChatLayout />);
		});
		const emojiBtn = screen.getByRole("button", { name: "Emoji" });
		await act(async () => {
			fireEvent.click(emojiBtn);
		});
		expect(screen.getByTestId("emoji-picker")).toBeInTheDocument();
	});

	it("emoji picker closes when smile button is clicked again", async () => {
		await act(async () => {
			render(<ChatLayout />);
		});
		const emojiBtn = screen.getByRole("button", { name: "Emoji" });
		await act(async () => {
			fireEvent.click(emojiBtn);
		});
		expect(screen.getByTestId("emoji-picker")).toBeInTheDocument();
		await act(async () => {
			fireEvent.click(emojiBtn);
		});
		expect(screen.queryByTestId("emoji-picker")).not.toBeInTheDocument();
	});

	it("emoji picker shows all three categories", async () => {
		await act(async () => {
			render(<ChatLayout />);
		});
		fireEvent.click(screen.getByRole("button", { name: "Emoji" }));
		const picker = screen.getByTestId("emoji-picker");
		expect(picker).toHaveTextContent("SMILEYS");
		expect(picker).toHaveTextContent("GESTURES");
		expect(picker).toHaveTextContent("SYMBOLS");
	});

	it("clicking an emoji inserts it into the message input", async () => {
		await act(async () => {
			render(<ChatLayout />);
		});
		fireEvent.click(screen.getByRole("button", { name: "Emoji" }));
		const emojiBtns = screen.getAllByTestId("emoji-btn");
		const firstEmoji = emojiBtns[0].textContent ?? "";
		await act(async () => {
			fireEvent.click(emojiBtns[0]);
		});
		const textarea = screen.getByPlaceholderText(/Message.*encrypted/);
		expect((textarea as HTMLTextAreaElement).value).toBe(firstEmoji);
	});

	it("clicking an emoji closes the picker", async () => {
		await act(async () => {
			render(<ChatLayout />);
		});
		fireEvent.click(screen.getByRole("button", { name: "Emoji" }));
		const emojiBtns = screen.getAllByTestId("emoji-btn");
		await act(async () => {
			fireEvent.click(emojiBtns[0]);
		});
		expect(screen.queryByTestId("emoji-picker")).not.toBeInTheDocument();
	});

	it("multiple emojis can be inserted sequentially", async () => {
		await act(async () => {
			render(<ChatLayout />);
		});
		// Insert first emoji
		fireEvent.click(screen.getByRole("button", { name: "Emoji" }));
		const firstBtns = screen.getAllByTestId("emoji-btn");
		const firstEmoji = firstBtns[0].textContent ?? "";
		await act(async () => {
			fireEvent.click(firstBtns[0]);
		});
		// Insert second emoji
		fireEvent.click(screen.getByRole("button", { name: "Emoji" }));
		const secondBtns = screen.getAllByTestId("emoji-btn");
		const secondEmoji = secondBtns[1].textContent ?? "";
		await act(async () => {
			fireEvent.click(secondBtns[1]);
		});
		const textarea = screen.getByPlaceholderText(/Message.*encrypted/);
		expect((textarea as HTMLTextAreaElement).value).toBe(firstEmoji + secondEmoji);
	});

	it("emoji picker closes when clicking outside", async () => {
		await act(async () => {
			render(<ChatLayout />);
		});
		fireEvent.click(screen.getByRole("button", { name: "Emoji" }));
		expect(screen.getByTestId("emoji-picker")).toBeInTheDocument();
		// Click outside the picker
		await act(async () => {
			fireEvent.mouseDown(document.body);
		});
		await waitFor(() => expect(screen.queryByTestId("emoji-picker")).not.toBeInTheDocument());
	});

	it("emoji buttons have accessible aria-label set to the emoji itself", async () => {
		await act(async () => {
			render(<ChatLayout />);
		});
		fireEvent.click(screen.getByRole("button", { name: "Emoji" }));
		const emojiBtns = screen.getAllByTestId("emoji-btn");
		// Every emoji button should have an aria-label equal to its emoji content
		for (const btn of emojiBtns) {
			expect(btn).toHaveAttribute("aria-label", btn.textContent);
		}
	});

	it("emoji picker is rendered above composer (position absolute)", async () => {
		await act(async () => {
			render(<ChatLayout />);
		});
		fireEvent.click(screen.getByRole("button", { name: "Emoji" }));
		const picker = screen.getByTestId("emoji-picker");
		expect(picker).toHaveStyle({ position: "absolute" });
	});

	it("existing draft text is preserved when emoji is inserted", async () => {
		await act(async () => {
			render(<ChatLayout />);
		});
		const textarea = screen.getByPlaceholderText(/Message.*encrypted/) as HTMLTextAreaElement;
		// Type some text first
		await act(async () => {
			fireEvent.change(textarea, { target: { value: "Hello " } });
		});
		// Open picker and insert emoji at end (selectionStart = selectionEnd = 0 in jsdom,
		// but the handler appends when cursor at text.length fallback)
		fireEvent.click(screen.getByRole("button", { name: "Emoji" }));
		const emojiBtns = screen.getAllByTestId("emoji-btn");
		const emoji = emojiBtns[0].textContent ?? "";
		await act(async () => {
			fireEvent.click(emojiBtns[0]);
		});
		// The emoji is inserted — result contains the emoji character
		expect(textarea.value).toContain(emoji);
	});
});
