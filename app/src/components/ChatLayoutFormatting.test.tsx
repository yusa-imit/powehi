import { act, cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { db } from "../db/schema";
import * as CryptoWorkerHook from "../hooks/useCryptoWorker";
import * as UseMessagesModule from "../hooks/useMessages";
import type { IncomingMessage } from "../hooks/useMessages";
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

const JORDAN_GROUP_ID = "33333333-3333-3333-3333-333333333333";
let captureIncoming: ((msg: IncomingMessage) => void) | null = null;

async function switchToJordanAndDeliver(text: string, id = "fmt-test-id") {
	fireEvent.click(screen.getByRole("button", { name: /jordan/i }));
	await act(async () => {
		captureIncoming?.({
			id,
			senderId: "peer-device-fmt",
			groupId: JORDAN_GROUP_ID,
			text,
			ciphertextB64: "Zg==",
			epochSeq: 1,
		});
	});
}

describe("ChatLayout — inline text formatting (bold / italic / code)", () => {
	beforeEach(async () => {
		await db.verifiedContacts.clear();
		await db.messages.clear();
		vi.spyOn(CryptoWorkerHook, "useCryptoWorker").mockReturnValue(
			MOCK_WORKER as unknown as ReturnType<typeof CryptoWorkerHook.useCryptoWorker>,
		);
		vi.spyOn(UseMessagesModule, "useMessages").mockImplementation((_id, _gid, onMsg) => {
			captureIncoming = onMsg;
		});
	});

	afterEach(() => {
		cleanup();
		vi.restoreAllMocks();
		captureIncoming = null;
	});

	it("seed message with **bold** in Maya chat renders <strong> with data-testid='fmt-bold'", () => {
		render(<ChatLayout />);
		const boldEl = screen.getAllByTestId("fmt-bold")[0];
		expect(boldEl.tagName).toBe("STRONG");
		expect(boldEl.textContent).toBe("bring your charger");
	});

	it("seed message with *italic* renders <em> with data-testid='fmt-italic'", () => {
		render(<ChatLayout />);
		const emEl = screen.getAllByTestId("fmt-italic")[0];
		expect(emEl.tagName).toBe("EM");
		expect(emEl.textContent).toBe("only one");
	});

	it("seed message with `code` renders <code> with data-testid='fmt-code'", () => {
		render(<ChatLayout />);
		const codeEl = screen.getAllByTestId("fmt-code")[0];
		expect(codeEl.tagName).toBe("CODE");
		expect(codeEl.textContent).toBe("outlet");
	});

	it("**bold** in incoming message renders <strong>", async () => {
		render(<ChatLayout />);
		await switchToJordanAndDeliver("This is **important** info.");
		const el = screen.getByTestId("fmt-bold");
		expect(el.tagName).toBe("STRONG");
		expect(el.textContent).toBe("important");
	});

	it("*italic* in incoming message renders <em>", async () => {
		render(<ChatLayout />);
		await switchToJordanAndDeliver("This is *really* cool.");
		const el = screen.getByTestId("fmt-italic");
		expect(el.tagName).toBe("EM");
		expect(el.textContent).toBe("really");
	});

	it("`code` in incoming message renders <code>", async () => {
		render(<ChatLayout />);
		await switchToJordanAndDeliver("Run `npm install` to set up.");
		const el = screen.getByTestId("fmt-code");
		expect(el.tagName).toBe("CODE");
		expect(el.textContent).toBe("npm install");
	});

	it("plain text with no markers renders without fmt-bold/italic/code elements", async () => {
		render(<ChatLayout />);
		await switchToJordanAndDeliver("Hello, world!");
		expect(screen.queryByTestId("fmt-bold")).toBeNull();
		expect(screen.queryByTestId("fmt-italic")).toBeNull();
		expect(screen.queryByTestId("fmt-code")).toBeNull();
	});

	it("unmatched single * stays as plain text (no element rendered)", async () => {
		render(<ChatLayout />);
		await switchToJordanAndDeliver("Price is 10*2 dollars.");
		expect(screen.queryByTestId("fmt-italic")).toBeNull();
	});

	it("**bold** and URL in same message both render correctly", async () => {
		render(<ChatLayout />);
		await switchToJordanAndDeliver("Check **this** at https://example.com for details.");
		expect(screen.getByTestId("fmt-bold").textContent).toBe("this");
		expect(screen.getByTestId("message-link")).toHaveAttribute("href", "https://example.com");
	});

	it("code element has monospace font-family style", async () => {
		render(<ChatLayout />);
		await switchToJordanAndDeliver("Use `git status` here.");
		const el = screen.getByTestId("fmt-code");
		expect(el.style.fontFamily).toBe("monospace");
	});

	it("mixed bold and italic in same message both render", async () => {
		render(<ChatLayout />);
		await switchToJordanAndDeliver("**Bold** and *italic* together.");
		expect(screen.getByTestId("fmt-bold").textContent).toBe("Bold");
		expect(screen.getByTestId("fmt-italic").textContent).toBe("italic");
	});

	it("existing URL linkification still works after formatting change", async () => {
		render(<ChatLayout />);
		await switchToJordanAndDeliver("See https://powehi.app/docs for the docs.");
		const link = screen.getByTestId("message-link");
		expect(link).toHaveAttribute("target", "_blank");
		expect(link).toHaveAttribute("rel", "noopener noreferrer");
	});
});
