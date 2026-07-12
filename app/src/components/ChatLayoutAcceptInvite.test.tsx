/**
 * Tests for the invite-accept → chat-list wiring flow (moved here from
 * App.test.tsx, cycle 262 "AcceptInviteModal chat-list wiring gap").
 *
 * ChatLayout now owns invite-code detection (URL hash + Tauri deep-link) and
 * renders AcceptInviteModal directly so it can drive `chats` state and
 * mirror the new group into Dexie the same way handleNewGroup/
 * handleGroupCreated already do for the Welcome-poller and CreateGroupModal
 * flows. App.tsx no longer performs any of this — it only chooses between
 * <Login /> and <ChatLayout /> based on auth phase.
 */
import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import * as GroupsApiModule from "../api/groups";
import * as InvitesApiModule from "../api/invites";
import * as KeyPackagesApiModule from "../api/key_packages";
import * as MessagesApiModule from "../api/messages";
import { db } from "../db/schema";
import * as CryptoWorkerHook from "../hooks/useCryptoWorker";
import * as UseDeepLinkModule from "../hooks/useDeepLink";
import { useAuthStore } from "../store/auth";
import { ChatLayout } from "./ChatLayout";

// ── Constants ────────────────────────────────────────────────────────────────

const INVITE_CODE = "a".repeat(32);
// Same senderDeviceId shape used by the existing Welcome-poller Dexie test
// (ChatLayout.test.tsx) so the derived "Contact <shortId>" naming matches.
const INVITER_DEVICE_ID = "peer-device-9999";
const MOCK_GROUP_ID = "invite-accept-group-00000000-0000-0000-0000";

// ── Crypto worker mock ───────────────────────────────────────────────────────
// Covers both AcceptInviteModal's MLS handshake calls and ChatLayout's own
// safety-number / Dexie-field-encryption calls used elsewhere on render.
// The PQ extension calls (mlsPqExtractAndVerifyEncapKey etc.) are deliberately
// left unmocked — AcceptInviteModal treats PQ failure as best-effort graceful
// degradation, so the accept flow still completes successfully without them.
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
	mlsCreateGroup: vi.fn(async () => ({ groupId: MOCK_GROUP_ID })),
	mlsAddMember: vi.fn(async () => ({ welcome: new Uint8Array(200) })),
};

// ── Setup ────────────────────────────────────────────────────────────────────

beforeEach(async () => {
	await db.verifiedContacts.clear();
	await db.messages.clear();
	await db.groups.clear();

	// Clear the URL hash so invite codes don't bleed across tests.
	history.replaceState(null, "", "/");

	useAuthStore.setState({
		phase: "app",
		deviceId: "my-device-id",
		sessionToken: "tok-invite-test",
		identityId: "identity-invite-test",
	});

	vi.spyOn(CryptoWorkerHook, "useCryptoWorker").mockReturnValue(
		MOCK_WORKER as unknown as ReturnType<typeof CryptoWorkerHook.useCryptoWorker>,
	);
	vi.spyOn(InvitesApiModule, "redeemInvite").mockResolvedValue({
		device_id: INVITER_DEVICE_ID,
	});
	vi.spyOn(KeyPackagesApiModule, "fetchKeyPackage").mockResolvedValue(new Uint8Array(200));
	vi.spyOn(GroupsApiModule, "createGroup").mockResolvedValue(undefined);
	vi.spyOn(GroupsApiModule, "addMember").mockResolvedValue(undefined);
	// Step 6 of AcceptInviteModal.handleAccept is unconditional (unlike the
	// best-effort PQ extension below it) — without this mock the accept flow
	// hangs on a real fetch() in the jsdom test environment.
	vi.spyOn(MessagesApiModule, "sendWelcome").mockResolvedValue(undefined);
	vi.spyOn(MessagesApiModule, "sendMessage").mockResolvedValue("mock-envelope-id");
});

afterEach(() => {
	// Explicit unmount BEFORE restoring mocks / resetting the auth store.
	// Vitest runs afterEach hooks in reverse registration order, so
	// Testing Library's own auto-cleanup (registered at import time) would
	// otherwise run AFTER this hook. Resetting useAuthStore first would then
	// re-render the still-mounted ChatLayout with useDeepLink already
	// restored to its real implementation — a hook-count mismatch against
	// the mocked (0-internal-hooks) render that mounted it, crashing with
	// "Cannot set properties of undefined (setting 'current')" in useRef.
	cleanup();
	vi.restoreAllMocks();
	useAuthStore.setState({
		phase: "login",
		deviceId: null,
		sessionToken: null,
		identityId: null,
	});
	history.replaceState(null, "", "/");
});

// ── Invite hash detection (moved from App.test.tsx) ────────────────────────

describe("ChatLayout — invite hash detection", () => {
	it("shows AcceptInviteModal when the URL has a valid invite hash", async () => {
		history.pushState(null, "", `/#${"a".repeat(32)}`);

		await act(async () => {
			render(<ChatLayout />);
		});

		expect(screen.getByRole("dialog", { name: /accept contact invite/i })).toBeInTheDocument();
	});

	it("does not show AcceptInviteModal for an invalid hash", async () => {
		history.pushState(null, "", "/#not-a-valid-code");

		await act(async () => {
			render(<ChatLayout />);
		});

		expect(screen.queryByRole("dialog", { name: /accept contact invite/i })).toBeNull();
	});
});

// ── Tauri deep-link invite (moved from App.test.tsx) ────────────────────────

describe("ChatLayout — Tauri deep-link invite", () => {
	it("opens AcceptInviteModal when a deep-link delivers an invite code", async () => {
		let capturedCallback: ((code: string) => void) | undefined;
		vi.spyOn(UseDeepLinkModule, "useDeepLink").mockImplementation((cb) => {
			capturedCallback = cb;
		});

		await act(async () => {
			render(<ChatLayout />);
		});

		await act(async () => {
			capturedCallback?.("a".repeat(32));
		});

		expect(screen.getByRole("dialog", { name: /accept contact invite/i })).toBeInTheDocument();
	});

	it("clears the modal when onClose is called after a deep-link invite", async () => {
		let capturedCallback: ((code: string) => void) | undefined;
		vi.spyOn(UseDeepLinkModule, "useDeepLink").mockImplementation((cb) => {
			capturedCallback = cb;
		});

		await act(async () => {
			render(<ChatLayout />);
		});
		await act(async () => {
			capturedCallback?.("c".repeat(32));
		});

		const dialog = screen.getByRole("dialog", { name: /accept contact invite/i });
		expect(dialog).toBeInTheDocument();

		const closeBtn = dialog.querySelector("button[aria-label]");
		await act(async () => {
			closeBtn?.dispatchEvent(new MouseEvent("click", { bubbles: true }));
		});

		expect(screen.queryByRole("dialog", { name: /accept contact invite/i })).toBeNull();
	});
});

// ── Chat-list wiring (the actual bug being fixed) ───────────────────────────

describe("ChatLayout — accept invite adds the chat to the sidebar (chat-list wiring gap)", () => {
	it("adds the new chat to the sidebar and persists a GroupRow to Dexie after accepting an invite", async () => {
		history.pushState(null, "", `/#${INVITE_CODE}`);

		await act(async () => {
			render(<ChatLayout />);
		});
		expect(screen.getByRole("dialog", { name: /accept contact invite/i })).toBeInTheDocument();

		await act(async () => {
			fireEvent.click(screen.getByRole("button", { name: /connect/i }));
		});

		await waitFor(() => screen.getByTestId("open-chat-btn"));
		await act(async () => {
			fireEvent.click(screen.getByTestId("open-chat-btn"));
		});

		// Modal closes and the new chat ("Contact peer-dev" — derived from the
		// first 8 chars of the inviter's deviceId) appears in the sidebar.
		expect(screen.queryByRole("dialog", { name: /accept contact invite/i })).toBeNull();
		await waitFor(() => {
			expect(screen.getAllByText("Contact peer-dev").length).toBeGreaterThan(0);
		});

		const row = await db.groups.get(MOCK_GROUP_ID);
		expect(row).toBeDefined();
		expect(row?.name).toBe("Contact peer-dev");
		expect(row?.mlsStateB64).toBe("");
	});

	it("navigates into the new chat (clears unread) after clicking Open chat", async () => {
		history.pushState(null, "", `/#${INVITE_CODE}`);

		await act(async () => {
			render(<ChatLayout />);
		});
		await act(async () => {
			fireEvent.click(screen.getByRole("button", { name: /connect/i }));
		});
		await waitFor(() => screen.getByTestId("open-chat-btn"));
		await act(async () => {
			fireEvent.click(screen.getByTestId("open-chat-btn"));
		});

		// The conversation header now shows the newly-accepted contact as active.
		await waitFor(() => {
			const header = screen.getByRole("banner");
			expect(header).toHaveTextContent(/contact peer-dev/i);
		});
	});
});
