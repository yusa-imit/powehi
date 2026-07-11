import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
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

const MAYA_GROUP_ID = "11111111-1111-1111-1111-111111111111";
const JORDAN_GROUP_ID = "33333333-3333-3333-3333-333333333333";

let captureIncoming: ((msg: IncomingMessage) => void) | null = null;
let captureOnPin: ((gId: string, targetMessageId: string, action: "pin" | "unpin") => void) | null =
	null;

describe("ChatLayout — sidebar pinned-message indicator", () => {
	beforeEach(async () => {
		await db.verifiedContacts.clear();
		vi.spyOn(CryptoWorkerHook, "useCryptoWorker").mockReturnValue(
			MOCK_WORKER as unknown as ReturnType<typeof CryptoWorkerHook.useCryptoWorker>,
		);
		vi.spyOn(UseMessagesModule, "useMessages").mockImplementation(
			(
				_id,
				_gid,
				onMsg,
				_onPq,
				_onTyping,
				_onReaction,
				_onReactionRemove,
				_onReadReceipt,
				_onDelivery,
				_onEdit,
				_onDelete,
				onPin,
			) => {
				captureIncoming = onMsg;
				captureOnPin = onPin ?? null;
			},
		);
	});

	afterEach(() => {
		cleanup();
		vi.restoreAllMocks();
		captureIncoming = null;
		captureOnPin = null;
	});

	it("has no pinned-message-indicator by default (no chat has a pinned message)", () => {
		render(<ChatLayout />);
		expect(screen.queryByTestId("pinned-message-indicator")).not.toBeInTheDocument();
	});

	it("shows pinned-message-indicator in sidebar once a message is pinned", async () => {
		render(<ChatLayout />);
		const msgId = "env-sidebar-pin-001";
		await act(async () => {
			captureIncoming?.({
				id: msgId,
				senderId: "device-maya",
				groupId: MAYA_GROUP_ID,
				text: "sidebar_indicator_test",
				ciphertextB64: "abc",
				epochSeq: 2001,
			});
			captureOnPin?.(MAYA_GROUP_ID, msgId, "pin");
		});
		await waitFor(() => expect(screen.getByTestId("pinned-message-indicator")).toBeInTheDocument());
	});

	it("pinned-message-indicator disappears again after unpin", async () => {
		render(<ChatLayout />);
		const msgId = "env-sidebar-unpin-001";
		await act(async () => {
			captureIncoming?.({
				id: msgId,
				senderId: "device-maya",
				groupId: MAYA_GROUP_ID,
				text: "sidebar_unpin_test",
				ciphertextB64: "abc",
				epochSeq: 2002,
			});
			captureOnPin?.(MAYA_GROUP_ID, msgId, "pin");
		});
		await waitFor(() => expect(screen.getByTestId("pinned-message-indicator")).toBeInTheDocument());
		await act(async () => {
			captureOnPin?.(MAYA_GROUP_ID, msgId, "unpin");
		});
		await waitFor(() =>
			expect(screen.queryByTestId("pinned-message-indicator")).not.toBeInTheDocument(),
		);
	});

	it("pinned-message-indicator is chat-specific — pinning in Maya does not mark Jordan's row", async () => {
		render(<ChatLayout />);
		const msgId = "env-sidebar-scope-001";
		await act(async () => {
			captureIncoming?.({
				id: msgId,
				senderId: "device-maya",
				groupId: MAYA_GROUP_ID,
				text: "sidebar_scope_test",
				ciphertextB64: "abc",
				epochSeq: 2003,
			});
			captureOnPin?.(MAYA_GROUP_ID, msgId, "pin");
		});
		await waitFor(() => expect(screen.getAllByTestId("pinned-message-indicator")).toHaveLength(1));

		const jordanRow = screen.getByRole("button", { name: /jordan/i });
		expect(
			jordanRow.querySelector('[data-testid="pinned-message-indicator"]'),
		).not.toBeInTheDocument();
	});

	it("pinned-message-indicator is independent from pin-top-indicator (different chat features)", async () => {
		render(<ChatLayout />);
		const msgId = "env-sidebar-independence-001";
		await act(async () => {
			captureIncoming?.({
				id: msgId,
				senderId: "device-maya",
				groupId: JORDAN_GROUP_ID,
				text: "sidebar_independence_test",
				ciphertextB64: "abc",
				epochSeq: 2004,
			});
			captureOnPin?.(JORDAN_GROUP_ID, msgId, "pin");
		});
		await waitFor(() => expect(screen.getByTestId("pinned-message-indicator")).toBeInTheDocument());
		expect(screen.queryByTestId("pin-top-indicator")).not.toBeInTheDocument();

		fireEvent.click(screen.getByRole("button", { name: /jordan/i }));
		fireEvent.click(screen.getByRole("button", { name: /info/i }));
		const pinToTopRow = await screen.findByRole("button", { name: /pin to top/i });
		fireEvent.click(pinToTopRow);
		fireEvent.click(screen.getByRole("button", { name: /close/i }));

		await waitFor(() => {
			expect(screen.getByTestId("pin-top-indicator")).toBeInTheDocument();
			expect(screen.getByTestId("pinned-message-indicator")).toBeInTheDocument();
		});
	});
});
