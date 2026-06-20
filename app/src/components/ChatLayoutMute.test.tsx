import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
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

// Jordan's mlsGroupId from SEED_CHATS
const JORDAN_GROUP_ID = "33333333-3333-3333-3333-333333333333";

describe("ChatLayout — per-chat mute", () => {
	beforeEach(async () => {
		await db.verifiedContacts.clear();
		vi.spyOn(CryptoWorkerHook, "useCryptoWorker").mockReturnValue(
			MOCK_WORKER as unknown as ReturnType<typeof CryptoWorkerHook.useCryptoWorker>,
		);
	});

	afterEach(() => {
		vi.restoreAllMocks();
	});

	it("Mute toggle in InfoPanel shows 'On' after clicking", async () => {
		render(<ChatLayout />);
		fireEvent.click(screen.getByRole("button", { name: /jordan/i }));
		fireEvent.click(screen.getByRole("button", { name: /info/i }));
		const muteBtn = screen.getByRole("button", { name: /mute/i });
		expect(muteBtn).toHaveTextContent("Off");
		fireEvent.click(muteBtn);
		await waitFor(() =>
			expect(screen.getByRole("button", { name: /mute/i })).toHaveTextContent("On"),
		);
	});

	it("muted chat shows bell-off icon in sidebar", async () => {
		render(<ChatLayout />);
		fireEvent.click(screen.getByRole("button", { name: /jordan/i }));
		fireEvent.click(screen.getByRole("button", { name: /info/i }));
		fireEvent.click(screen.getByRole("button", { name: /mute/i }));
		await waitFor(() => expect(screen.getAllByTestId("muted-icon")).toHaveLength(1));
	});

	it("Mute toggle flips back to 'Off' when clicked again", async () => {
		render(<ChatLayout />);
		fireEvent.click(screen.getByRole("button", { name: /jordan/i }));
		fireEvent.click(screen.getByRole("button", { name: /info/i }));
		const muteBtn = () => screen.getByRole("button", { name: /mute/i });
		fireEvent.click(muteBtn());
		await waitFor(() => expect(muteBtn()).toHaveTextContent("On"));
		fireEvent.click(muteBtn());
		await waitFor(() => expect(muteBtn()).toHaveTextContent("Off"));
		expect(screen.queryByTestId("muted-icon")).not.toBeInTheDocument();
	});

	it("incoming message to muted background chat does NOT increment unread badge", async () => {
		let capturedOnMessage: ((msg: IncomingMessage) => void) | undefined;
		vi.spyOn(UseMessagesModule, "useMessages").mockImplementation((_id, _gid, onMsg) => {
			capturedOnMessage = onMsg;
		});
		render(<ChatLayout />);
		// Select Jordan to clear its existing 2-unread count
		fireEvent.click(screen.getByRole("button", { name: /jordan/i }));
		// Open InfoPanel and mute Jordan
		fireEvent.click(screen.getByRole("button", { name: /info/i }));
		fireEvent.click(screen.getByRole("button", { name: /mute/i }));
		await waitFor(() =>
			expect(screen.getByRole("button", { name: /mute/i })).toHaveTextContent("On"),
		);
		// Switch to Maya — Jordan becomes a muted background chat
		fireEvent.click(screen.getAllByRole("button", { name: /maya akana/i })[0]);
		// Dispatch incoming message for Jordan's MLS group
		await act(async () => {
			capturedOnMessage?.({
				id: "mute-suppress-uuid-0001",
				senderId: "peer-device-mute",
				groupId: JORDAN_GROUP_ID,
				text: "This should be silent",
				ciphertextB64: "Zg==",
				epochSeq: 1,
			});
		});
		// Jordan's unread badge must NOT appear — mute suppressed the increment
		expect(screen.queryByTestId("unread-badge")).not.toBeInTheDocument();
	});

	it("incoming message to unmuted background chat DOES increment unread badge", async () => {
		let capturedOnMessage: ((msg: IncomingMessage) => void) | undefined;
		vi.spyOn(UseMessagesModule, "useMessages").mockImplementation((_id, _gid, onMsg) => {
			capturedOnMessage = onMsg;
		});
		render(<ChatLayout />);
		// Select Jordan to clear its unread, then return to Maya
		fireEvent.click(screen.getByRole("button", { name: /jordan/i }));
		fireEvent.click(screen.getAllByRole("button", { name: /maya akana/i })[0]);
		// Dispatch incoming message for Jordan's MLS group (Jordan is unmuted)
		await act(async () => {
			capturedOnMessage?.({
				id: "mute-allow-uuid-0002",
				senderId: "peer-device-mute",
				groupId: JORDAN_GROUP_ID,
				text: "This should count",
				ciphertextB64: "Zg==",
				epochSeq: 2,
			});
		});
		// Jordan's unread badge must appear
		await waitFor(() => expect(screen.getByTestId("unread-badge")).toBeInTheDocument());
	});

	it("mute is chat-specific — muting Jordan leaves Maya unmuted", async () => {
		render(<ChatLayout />);
		// Mute Jordan
		fireEvent.click(screen.getByRole("button", { name: /jordan/i }));
		fireEvent.click(screen.getByRole("button", { name: /info/i }));
		fireEvent.click(screen.getByRole("button", { name: /mute/i }));
		await waitFor(() =>
			expect(screen.getByRole("button", { name: /mute/i })).toHaveTextContent("On"),
		);
		// Switch to Maya — InfoPanel stays open and now shows Maya's data
		fireEvent.click(screen.getAllByRole("button", { name: /maya akana/i })[0]);
		// Maya's Mute toggle must still show "Off"
		await waitFor(() =>
			expect(screen.getByRole("button", { name: /mute/i })).toHaveTextContent("Off"),
		);
	});
});
