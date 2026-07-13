import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import * as GroupsApiModule from "../api/groups";
import * as MessagesApiModule from "../api/messages";
import { db } from "../db/schema";
import * as CryptoWorkerHook from "../hooks/useCryptoWorker";
import * as UseMessagesModule from "../hooks/useMessages";
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
	mlsCreateGroup: vi.fn(async () => ({ groupId: "group-seenby-0001" })),
	mlsEncrypt: vi.fn(async () => ({ ciphertext: new Uint8Array([0xde, 0xad]) })),
	mlsDecrypt: vi.fn(async () => ({ plaintext: new Uint8Array() })),
	encryptDbField: vi.fn(async (v: string) => v),
	decryptDbField: vi.fn(async (v: string) => v),
};

let captureOnReadReceipt:
	| ((gId: string, messageIds: string[], readAt: number, senderDeviceId: string) => void)
	| null = null;

/** Creates a group chat via the real "New group" UI flow, selects it, and returns its name. */
async function createAndSelectGroup(name: string) {
	fireEvent.click(screen.getByRole("button", { name: /new group/i }));
	fireEvent.change(screen.getByTestId("group-name-input"), { target: { value: name } });
	fireEvent.click(screen.getByTestId("create-group-submit"));
	await waitFor(() => {
		expect(screen.getByText(name)).toBeInTheDocument();
	});
	fireEvent.click(screen.getByRole("button", { name: new RegExp(name, "i") }));
	await waitFor(() => {
		expect(screen.getByTestId("group-status")).toBeInTheDocument();
	});
}

describe("ChatLayout — group read receipts (per-member 'Seen by N')", () => {
	beforeEach(async () => {
		await db.verifiedContacts.clear();
		await db.groups.clear();
		vi.spyOn(CryptoWorkerHook, "useCryptoWorker").mockReturnValue(
			MOCK_WORKER as unknown as ReturnType<typeof CryptoWorkerHook.useCryptoWorker>,
		);
		vi.spyOn(GroupsApiModule, "createGroup").mockResolvedValue(undefined);
		useAuthStore.setState({
			sessionToken: "tok-seenby-test",
			identityId: "id-seenby-test",
			phase: "app",
			deviceId: "dev-seenby-test",
		});
		vi.spyOn(UseMessagesModule, "useMessages").mockImplementation(
			(_id, _gid, _onMsg, _onPq, _onTyping, _onReaction, _onReactionRemove, onReadReceipt) => {
				captureOnReadReceipt = onReadReceipt ?? null;
			},
		);
	});

	afterEach(() => {
		cleanup();
		vi.restoreAllMocks();
		captureOnReadReceipt = null;
		useAuthStore.setState({ sessionToken: null, identityId: null, phase: "login", deviceId: null });
	});

	it("shows 'Seen by 2' after two distinct group members each send a read_receipt", async () => {
		vi.spyOn(MessagesApiModule, "sendMessage").mockResolvedValue("grp-seenby-msg-001");
		render(<ChatLayout />);
		await createAndSelectGroup("Seen By Group");

		const textarea = screen.getByPlaceholderText(/Message.*—\s*encrypted/i);
		await act(async () => {
			fireEvent.change(textarea, { target: { value: "hello group" } });
			fireEvent.click(screen.getByRole("button", { name: /send message/i }));
		});

		await act(async () => {
			captureOnReadReceipt?.(
				"group-seenby-0001",
				["grp-seenby-msg-001"],
				Date.now(),
				"dev-member-a",
			);
		});
		await waitFor(() => {
			expect(screen.getByTestId("seen-by-indicator")).toHaveTextContent("Seen by 1");
		});

		await act(async () => {
			captureOnReadReceipt?.(
				"group-seenby-0001",
				["grp-seenby-msg-001"],
				Date.now(),
				"dev-member-b",
			);
		});
		await waitFor(() => {
			expect(screen.getByTestId("seen-by-indicator")).toHaveTextContent("Seen by 2");
		});
	});

	it("does not double-count a repeated read_receipt from the same device", async () => {
		vi.spyOn(MessagesApiModule, "sendMessage").mockResolvedValue("grp-seenby-msg-002");
		render(<ChatLayout />);
		await createAndSelectGroup("Dedup Group");

		const textarea = screen.getByPlaceholderText(/Message.*—\s*encrypted/i);
		await act(async () => {
			fireEvent.change(textarea, { target: { value: "hello again" } });
			fireEvent.click(screen.getByRole("button", { name: /send message/i }));
		});

		for (let i = 0; i < 2; i++) {
			await act(async () => {
				captureOnReadReceipt?.(
					"group-seenby-0001",
					["grp-seenby-msg-002"],
					Date.now(),
					"dev-member-a",
				);
			});
		}
		await waitFor(() => {
			expect(screen.getByTestId("seen-by-indicator")).toHaveTextContent("Seen by 1");
		});
	});

	it("hovering the 'Seen by N' indicator reveals a tooltip listing each reader", async () => {
		vi.spyOn(MessagesApiModule, "sendMessage").mockResolvedValue("grp-seenby-msg-003");
		render(<ChatLayout />);
		await createAndSelectGroup("Tooltip Group");

		const textarea = screen.getByPlaceholderText(/Message.*—\s*encrypted/i);
		await act(async () => {
			fireEvent.change(textarea, { target: { value: "who saw this" } });
			fireEvent.click(screen.getByRole("button", { name: /send message/i }));
		});

		await act(async () => {
			captureOnReadReceipt?.(
				"group-seenby-0001",
				["grp-seenby-msg-003"],
				Date.now(),
				"dev-member-tooltip",
			);
		});
		await waitFor(() => {
			expect(screen.getByTestId("seen-by-indicator")).toBeInTheDocument();
		});

		expect(screen.queryByTestId("seen-by-tooltip")).not.toBeInTheDocument();
		fireEvent.mouseEnter(screen.getByTestId("seen-by-indicator").parentElement as Element);
		expect(screen.getByTestId("seen-by-tooltip")).toHaveTextContent("dev-memb");
	});

	it("a DM (non-group) chat never renders the 'Seen by' indicator, even with multiple receipts", async () => {
		vi.spyOn(MessagesApiModule, "sendMessage").mockResolvedValue("dm-seenby-msg-001");
		render(<ChatLayout />);
		// Default active chat ("maya") is a DM, not a group.
		const textarea = screen.getByPlaceholderText(/Message.*—\s*encrypted/i);
		await act(async () => {
			fireEvent.change(textarea, { target: { value: "dm message" } });
			fireEvent.click(screen.getByRole("button", { name: /send message/i }));
		});

		await act(async () => {
			captureOnReadReceipt?.(
				"11111111-1111-1111-1111-111111111111",
				["dm-seenby-msg-001"],
				Date.now(),
				"device-peer-1",
			);
		});
		await act(async () => {
			captureOnReadReceipt?.(
				"11111111-1111-1111-1111-111111111111",
				["dm-seenby-msg-001"],
				Date.now(),
				"device-peer-2",
			);
		});

		await waitFor(() => {
			const readIndicators = screen
				.queryAllByTestId("read-indicator")
				.filter((el) => el.getAttribute("aria-label") === "Read");
			expect(readIndicators.length).toBeGreaterThanOrEqual(1);
		});
		expect(screen.queryByTestId("seen-by-indicator")).not.toBeInTheDocument();
	});
});
