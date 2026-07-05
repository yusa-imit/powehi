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

function openInfoPanel(chatName: RegExp | string) {
	const chatBtn = screen.getAllByRole("button", { name: chatName })[0];
	fireEvent.click(chatBtn);
	fireEvent.click(screen.getByRole("button", { name: /info/i }));
}

describe("ChatLayout — chat export", () => {
	let capturedContent: string | undefined;
	let anchorClickSpy: ReturnType<typeof vi.spyOn>;
	const OriginalBlob = globalThis.Blob;

	beforeEach(async () => {
		await db.verifiedContacts.clear();
		vi.spyOn(CryptoWorkerHook, "useCryptoWorker").mockReturnValue(
			MOCK_WORKER as unknown as ReturnType<typeof CryptoWorkerHook.useCryptoWorker>,
		);
		vi.spyOn(UseMessagesModule, "useMessages").mockImplementation(() => {});

		capturedContent = undefined;

		// Intercept Blob construction to capture the raw string content
		vi.stubGlobal(
			"Blob",
			vi.fn((parts: (string | BufferSource)[], opts?: BlobPropertyBag) => {
				if (parts && parts.length > 0 && typeof parts[0] === "string") {
					capturedContent = parts[0];
				}
				return new OriginalBlob(parts, opts);
			}),
		);

		vi.stubGlobal("URL", {
			createObjectURL: vi.fn(() => "blob:mock-url"),
			revokeObjectURL: vi.fn(),
		});
		anchorClickSpy = vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => {});
	});

	afterEach(() => {
		vi.restoreAllMocks();
		vi.unstubAllGlobals();
	});

	it("Export Chat button is visible in InfoPanel", () => {
		render(<ChatLayout />);
		openInfoPanel(/jordan/i);
		expect(screen.getByTestId("export-chat-button")).toBeInTheDocument();
	});

	it("Export Chat button has correct label", () => {
		render(<ChatLayout />);
		openInfoPanel(/jordan/i);
		expect(screen.getByTestId("export-chat-button")).toHaveTextContent("Export Chat");
	});

	it("Clicking Export Chat shows confirm dialog with Cancel, JSON, Text buttons", async () => {
		render(<ChatLayout />);
		openInfoPanel(/jordan/i);
		fireEvent.click(screen.getByTestId("export-chat-button"));
		await waitFor(() => expect(screen.getByTestId("export-chat-confirm")).toBeInTheDocument());
		expect(screen.getByTestId("export-cancel")).toBeInTheDocument();
		expect(screen.getByTestId("export-as-json")).toBeInTheDocument();
		expect(screen.getByTestId("export-as-text")).toBeInTheDocument();
	});

	it("Cancel closes the confirm dialog and restores the Export Chat button", async () => {
		render(<ChatLayout />);
		openInfoPanel(/jordan/i);
		fireEvent.click(screen.getByTestId("export-chat-button"));
		await waitFor(() => expect(screen.getByTestId("export-chat-confirm")).toBeInTheDocument());
		fireEvent.click(screen.getByTestId("export-cancel"));
		await waitFor(() =>
			expect(screen.queryByTestId("export-chat-confirm")).not.toBeInTheDocument(),
		);
		expect(screen.getByTestId("export-chat-button")).toBeInTheDocument();
	});

	it("Clicking JSON triggers a download and closes confirm", async () => {
		render(<ChatLayout />);
		openInfoPanel(/jordan/i);
		fireEvent.click(screen.getByTestId("export-chat-button"));
		await waitFor(() => expect(screen.getByTestId("export-chat-confirm")).toBeInTheDocument());
		fireEvent.click(screen.getByTestId("export-as-json"));
		await waitFor(() =>
			expect(screen.queryByTestId("export-chat-confirm")).not.toBeInTheDocument(),
		);
		expect(URL.createObjectURL).toHaveBeenCalledOnce();
		expect(URL.revokeObjectURL).toHaveBeenCalledWith("blob:mock-url");
		expect(anchorClickSpy).toHaveBeenCalledOnce();
	});

	it("Clicking Text triggers a download and closes confirm", async () => {
		render(<ChatLayout />);
		openInfoPanel(/jordan/i);
		fireEvent.click(screen.getByTestId("export-chat-button"));
		await waitFor(() => expect(screen.getByTestId("export-chat-confirm")).toBeInTheDocument());
		fireEvent.click(screen.getByTestId("export-as-text"));
		await waitFor(() =>
			expect(screen.queryByTestId("export-chat-confirm")).not.toBeInTheDocument(),
		);
		expect(URL.createObjectURL).toHaveBeenCalledOnce();
		expect(anchorClickSpy).toHaveBeenCalledOnce();
	});

	it("JSON export does not contain mlsGroupId or mlsIdentityId", async () => {
		render(<ChatLayout />);
		openInfoPanel(/jordan/i);
		fireEvent.click(screen.getByTestId("export-chat-button"));
		await waitFor(() => expect(screen.getByTestId("export-chat-confirm")).toBeInTheDocument());
		fireEvent.click(screen.getByTestId("export-as-json"));
		await waitFor(() => expect(capturedContent).toBeDefined());
		expect(capturedContent).not.toContain("mlsGroupId");
		expect(capturedContent).not.toContain("mlsIdentityId");
		expect(capturedContent).not.toContain("pqBindingHex");
	});

	it("JSON export contains chat name and messages array", async () => {
		render(<ChatLayout />);
		openInfoPanel(/jordan/i);
		fireEvent.click(screen.getByTestId("export-chat-button"));
		await waitFor(() => expect(screen.getByTestId("export-chat-confirm")).toBeInTheDocument());
		fireEvent.click(screen.getByTestId("export-as-json"));
		await waitFor(() => expect(capturedContent).toBeDefined());
		const json = JSON.parse(capturedContent ?? "");
		expect(json).toHaveProperty("chat");
		expect(json).toHaveProperty("messages");
		expect(Array.isArray(json.messages)).toBe(true);
		expect(json.chat).toHaveProperty("name");
	});

	it("Text export has line-per-message format", async () => {
		render(<ChatLayout />);
		openInfoPanel(/jordan/i);
		fireEvent.click(screen.getByTestId("export-chat-button"));
		await waitFor(() => expect(screen.getByTestId("export-chat-confirm")).toBeInTheDocument());
		fireEvent.click(screen.getByTestId("export-as-text"));
		await waitFor(() => expect(capturedContent).toBeDefined());
		const lines = (capturedContent ?? "").split("\n");
		expect(lines.length).toBeGreaterThan(0);
		// Each non-empty line follows "Sender: body" or "Sender (time): body" pattern
		for (const line of lines) {
			if (line.trim()) {
				expect(line).toMatch(/^.+:.+/);
			}
		}
	});

	it("Chat messages remain visible after export (non-destructive)", async () => {
		render(<ChatLayout />);
		openInfoPanel(/jordan/i);
		fireEvent.click(screen.getByTestId("export-chat-button"));
		await waitFor(() => expect(screen.getByTestId("export-chat-confirm")).toBeInTheDocument());
		fireEvent.click(screen.getByTestId("export-as-json"));
		await waitFor(() =>
			expect(screen.queryByTestId("export-chat-confirm")).not.toBeInTheDocument(),
		);
		// Messages still in the chat after export
		expect(screen.getByText("split for last night")).toBeInTheDocument();
	});

	it("Export button does not interfere with Clear Messages flow", () => {
		render(<ChatLayout />);
		openInfoPanel(/jordan/i);
		// Both buttons visible simultaneously
		expect(screen.getByTestId("export-chat-button")).toBeInTheDocument();
		expect(screen.getByTestId("clear-messages-button")).toBeInTheDocument();
	});
});
