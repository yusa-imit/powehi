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

// Jordan's chat has no seed URLs — clean slate for link tests.
const JORDAN_GROUP_ID = "33333333-3333-3333-3333-333333333333";
let captureIncoming: ((msg: IncomingMessage) => void) | null = null;

/** Switch to Jordan's chat (no seed URL messages) and deliver an incoming message there. */
async function switchToJordanAndDeliver(text: string, id = "link-test-id") {
	fireEvent.click(screen.getByRole("button", { name: /jordan/i }));
	await act(async () => {
		captureIncoming?.({
			id,
			senderId: "peer-device-link",
			groupId: JORDAN_GROUP_ID,
			text,
			ciphertextB64: "Zg==",
			epochSeq: 1,
		});
	});
}

describe("ChatLayout — URL linkification in message text", () => {
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

	it("seed message with URL in Maya chat shows a link on initial render", () => {
		render(<ChatLayout />);
		const link = screen.getByTestId("message-link");
		expect(link.tagName).toBe("A");
		expect(link).toHaveAttribute("href", "https://example.com/menu");
	});

	it("https:// URL in incoming message text becomes a clickable <a> link", async () => {
		render(<ChatLayout />);
		await switchToJordanAndDeliver("Check this out: https://example.com/page");
		const link = screen.getByTestId("message-link");
		expect(link.tagName).toBe("A");
		expect(link).toHaveAttribute("href", "https://example.com/page");
	});

	it("link has target='_blank' so it opens in a new tab", async () => {
		render(<ChatLayout />);
		await switchToJordanAndDeliver("Visit https://powehi.app for more info.");
		const link = screen.getByTestId("message-link");
		expect(link).toHaveAttribute("target", "_blank");
	});

	it("link has rel='noopener noreferrer' to prevent opener hijacking", async () => {
		render(<ChatLayout />);
		await switchToJordanAndDeliver("See https://powehi.app/docs for docs.");
		const link = screen.getByTestId("message-link");
		expect(link).toHaveAttribute("rel", "noopener noreferrer");
	});

	it("http:// URL is also linkified (not just https://)", async () => {
		render(<ChatLayout />);
		await switchToJordanAndDeliver("Old site: http://example.com/legacy");
		const link = screen.getByTestId("message-link");
		expect(link).toHaveAttribute("href", "http://example.com/legacy");
	});

	it("plain text without a URL has no <a> link", async () => {
		render(<ChatLayout />);
		await switchToJordanAndDeliver("Just plain text, no links here.");
		expect(screen.queryByTestId("message-link")).not.toBeInTheDocument();
	});

	it("javascript: URI is NOT linkified (XSS prevention)", async () => {
		render(<ChatLayout />);
		await switchToJordanAndDeliver("javascript:alert(1)");
		expect(screen.queryByTestId("message-link")).not.toBeInTheDocument();
	});

	it("data: URI is NOT linkified (XSS prevention)", async () => {
		render(<ChatLayout />);
		await switchToJordanAndDeliver("data:text/html,<h1>xss</h1>");
		expect(screen.queryByTestId("message-link")).not.toBeInTheDocument();
	});

	it("URL at the start of a message is linkified", async () => {
		render(<ChatLayout />);
		await switchToJordanAndDeliver("https://start-url.example.com is a cool site");
		const link = screen.getByTestId("message-link");
		expect(link).toHaveAttribute("href", "https://start-url.example.com");
	});

	it("URL at the end of a message is linkified", async () => {
		render(<ChatLayout />);
		await switchToJordanAndDeliver("Read the docs at https://docs.example.com");
		const link = screen.getByTestId("message-link");
		expect(link).toHaveAttribute("href", "https://docs.example.com");
	});

	it("multiple URLs in a single message each get their own <a> link", async () => {
		render(<ChatLayout />);
		await switchToJordanAndDeliver(
			"First: https://alpha.example.com and second: https://beta.example.com",
		);
		const links = screen.getAllByTestId("message-link");
		expect(links).toHaveLength(2);
		expect(links[0]).toHaveAttribute("href", "https://alpha.example.com");
		expect(links[1]).toHaveAttribute("href", "https://beta.example.com");
	});

	it("trailing period is stripped from URL so the sentence reads correctly", async () => {
		render(<ChatLayout />);
		await switchToJordanAndDeliver("Visit https://example.com/page. See you there.");
		const link = screen.getByTestId("message-link");
		expect(link).toHaveAttribute("href", "https://example.com/page");
	});
});
