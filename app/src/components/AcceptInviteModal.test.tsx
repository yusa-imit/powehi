import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import {
	type MockInstance,
	afterEach,
	beforeAll,
	beforeEach,
	describe,
	expect,
	it,
	vi,
} from "vitest";
import * as GroupsApi from "../api/groups";
import * as InvitesApi from "../api/invites";
import * as MessagesApi from "../api/messages";
import * as CryptoWorkerHook from "../hooks/useCryptoWorker";
import { useAuthStore } from "../store/auth";
import { AcceptInviteModal } from "./AcceptInviteModal";

// ── Constants ────────────────────────────────────────────────────────────────

const INVITE_CODE = "a".repeat(32);
const INVITER_DEVICE_ID = "inviter-device-00000000-0000-0000-0000";
const MOCK_GROUP_ID = "mock-group-id-00000000-0000-0000-0000-000000000000";
const MOCK_KEY_PACKAGE = Array.from({ length: 200 }, (_, i) => i % 256);

async function sha256Hex(bytes: number[]): Promise<string> {
	const digest = await crypto.subtle.digest("SHA-256", new Uint8Array(bytes));
	return Array.from(new Uint8Array(digest))
		.map((b) => b.toString(16).padStart(2, "0"))
		.join("");
}

// The real SHA-256 hex digest of MOCK_KEY_PACKAGE — computed once so tests can
// exercise the actual verification path (AcceptInviteModal calls crypto.subtle
// itself), rather than mocking it away.
let MOCK_KEY_PACKAGE_HASH: string;
beforeAll(async () => {
	MOCK_KEY_PACKAGE_HASH = await sha256Hex(MOCK_KEY_PACKAGE);
});

// ── Crypto worker mock ───────────────────────────────────────────────────────

const mockCryptoWorker = {
	mlsCreateGroup: vi.fn(async (_id: string) => ({ groupId: MOCK_GROUP_ID })),
	mlsAddMember: vi.fn(async () => ({ welcome: new Uint8Array(200) })),
	mlsGroupMembers: vi.fn(async () => [
		{ leafIndex: 0, sigKeyHex: "aa".repeat(32) },
		{ leafIndex: 1, sigKeyHex: "bb".repeat(32) },
	]),
	mlsPqExtractAndVerifyEncapKey: vi.fn(async () => ({
		encapKey: new Uint8Array(1184),
		signature: new Uint8Array(64),
	})),
	mlKem768EncapV2: vi.fn(async () => ({
		ciphertext: new Uint8Array(1088),
		sharedSecretHandle: "mock-ss-enc-handle-0",
	})),
	mlsEncrypt: vi.fn(async () => ({ ciphertext: new Uint8Array(64) })),
	mlsPqDeriveBinding: vi.fn(async () => ({ bindingHex: "c702693eff3c46bd" })),
};

// ── Spies ────────────────────────────────────────────────────────────────────

let redeemInviteSpy: MockInstance<typeof InvitesApi.redeemInvite>;
let createGroupSpy: MockInstance<typeof GroupsApi.createGroup>;
let addMemberSpy: MockInstance<typeof GroupsApi.addMember>;
let sendWelcomeSpy: MockInstance<typeof MessagesApi.sendWelcome>;
let sendMessageSpy: MockInstance<typeof MessagesApi.sendMessage>;

// ── Helpers ──────────────────────────────────────────────────────────────────

function renderModal(overrides?: Partial<Parameters<typeof AcceptInviteModal>[0]>) {
	const onClose = vi.fn();
	const onAccepted = vi.fn();
	render(
		<AcceptInviteModal
			inviteCode={INVITE_CODE}
			keyPackageHash={MOCK_KEY_PACKAGE_HASH}
			onClose={onClose}
			onAccepted={onAccepted}
			{...overrides}
		/>,
	);
	return { onClose, onAccepted };
}

// ── Setup ────────────────────────────────────────────────────────────────────

beforeEach(() => {
	useAuthStore.setState({
		phase: "app",
		deviceId: "my-device-id",
		sessionToken: "tok-test",
		identityId: "identity-abc",
	});
	vi.spyOn(CryptoWorkerHook, "useCryptoWorker").mockReturnValue(
		mockCryptoWorker as unknown as ReturnType<typeof CryptoWorkerHook.useCryptoWorker>,
	);
	redeemInviteSpy = vi.spyOn(InvitesApi, "redeemInvite").mockResolvedValue({
		device_id: INVITER_DEVICE_ID,
		key_package: MOCK_KEY_PACKAGE,
	});
	createGroupSpy = vi.spyOn(GroupsApi, "createGroup").mockResolvedValue(undefined);
	addMemberSpy = vi.spyOn(GroupsApi, "addMember").mockResolvedValue(undefined);
	sendWelcomeSpy = vi.spyOn(MessagesApi, "sendWelcome").mockResolvedValue(undefined);
	sendMessageSpy = vi.spyOn(MessagesApi, "sendMessage").mockResolvedValue("mock-envelope-id");
});

afterEach(() => {
	useAuthStore.setState({
		phase: "login",
		deviceId: null,
		sessionToken: null,
		identityId: null,
		pqDecapKeyHandle: null,
	});
	vi.restoreAllMocks();
});

// ── Tests ────────────────────────────────────────────────────────────────────

describe("AcceptInviteModal — render", () => {
	it("renders the dialog with Connect button in idle state", () => {
		renderModal();
		expect(screen.getByRole("dialog", { name: /accept contact invite/i })).toBeInTheDocument();
		expect(screen.getByRole("button", { name: /connect/i })).toBeInTheDocument();
	});

	it("renders the E2EE notice", () => {
		renderModal();
		expect(screen.getByText(/end-to-end encrypted/i)).toBeInTheDocument();
	});

	it("calls onClose when Close button (X) is clicked", () => {
		const { onClose } = renderModal();
		fireEvent.click(screen.getByRole("button", { name: /close/i }));
		expect(onClose).toHaveBeenCalledOnce();
	});
});

describe("AcceptInviteModal — accept flow success", () => {
	it("shows loading state while accepting", async () => {
		redeemInviteSpy.mockImplementation(
			() =>
				new Promise((r) =>
					setTimeout(() => r({ device_id: INVITER_DEVICE_ID, key_package: MOCK_KEY_PACKAGE }), 50),
				),
		);
		renderModal();

		fireEvent.click(screen.getByRole("button", { name: /connect/i }));
		expect(await screen.findByText(/establishing encrypted channel/i)).toBeInTheDocument();

		// Drain the rest of the flow (the 50ms delayed redeemInvite above, plus
		// every subsequent real crypto.subtle.digest/mocked step) before the test
		// ends — otherwise this test's own in-flight promise chain keeps running
		// in the background and can call createGroup/addMember against a LATER
		// test's freshly-created spies once its 50ms timer fires mid-test there.
		await waitFor(() => {
			expect(screen.getByText(/encrypted channel established/i)).toBeInTheDocument();
		});
	});

	it("shows success state after full accept flow", async () => {
		renderModal();

		await act(async () => {
			fireEvent.click(screen.getByRole("button", { name: /connect/i }));
		});

		await waitFor(() => {
			expect(screen.getByText(/encrypted channel established/i)).toBeInTheDocument();
		});
	});

	it("calls redeemInvite with the invite code in the request body", async () => {
		renderModal();

		await act(async () => {
			fireEvent.click(screen.getByRole("button", { name: /connect/i }));
		});

		await waitFor(() =>
			expect(screen.getByText(/encrypted channel established/i)).toBeInTheDocument(),
		);
		expect(redeemInviteSpy).toHaveBeenCalledWith("tok-test", INVITE_CODE);
	});

	it("calls createGroup and addMember with opaque UUIDs (no plaintext)", async () => {
		renderModal();

		await act(async () => {
			fireEvent.click(screen.getByRole("button", { name: /connect/i }));
		});

		await waitFor(() =>
			expect(screen.getByText(/encrypted channel established/i)).toBeInTheDocument(),
		);
		expect(createGroupSpy).toHaveBeenCalledWith("tok-test", MOCK_GROUP_ID);
		expect(addMemberSpy).toHaveBeenCalledWith("tok-test", MOCK_GROUP_ID, INVITER_DEVICE_ID, 1);
	});

	it("passes the redeemed KeyPackage bytes to mlsAddMember once verified", async () => {
		renderModal();

		await act(async () => {
			fireEvent.click(screen.getByRole("button", { name: /connect/i }));
		});

		await waitFor(() =>
			expect(screen.getByText(/encrypted channel established/i)).toBeInTheDocument(),
		);
		expect(mockCryptoWorker.mlsAddMember).toHaveBeenCalledWith(
			"identity-abc",
			MOCK_GROUP_ID,
			new Uint8Array(MOCK_KEY_PACKAGE),
		);
	});

	it("calls onAccepted with the groupId when Open chat is clicked", async () => {
		const { onAccepted } = renderModal();

		await act(async () => {
			fireEvent.click(screen.getByRole("button", { name: /connect/i }));
		});

		await waitFor(() => screen.getByTestId("open-chat-btn"));
		fireEvent.click(screen.getByTestId("open-chat-btn"));
		expect(onAccepted).toHaveBeenCalledWith(MOCK_GROUP_ID, INVITER_DEVICE_ID);
	});
});

describe("AcceptInviteModal — error paths", () => {
	it("shows 'expired' error when redeemInvite returns invite_not_found", async () => {
		redeemInviteSpy.mockRejectedValue(new Error("invite_not_found"));
		renderModal();

		await act(async () => {
			fireEvent.click(screen.getByRole("button", { name: /connect/i }));
		});

		await waitFor(() => {
			expect(screen.getByText(/already been used or has expired/i)).toBeInTheDocument();
		});
	});

	it("shows 'verification_failed' error when the redeemed KeyPackage doesn't match the invite hash", async () => {
		// Simulates a server substituting a different KeyPackage than the one
		// the inviter actually reserved — the hash embedded in the invite URL
		// (never seen by the server) won't match what comes back.
		redeemInviteSpy.mockResolvedValue({
			device_id: INVITER_DEVICE_ID,
			key_package: [9, 9, 9, 9],
		});
		renderModal();

		await act(async () => {
			fireEvent.click(screen.getByRole("button", { name: /connect/i }));
		});

		await waitFor(() => {
			expect(
				screen.getByText(/could not verify this contact.s encryption key/i),
			).toBeInTheDocument();
		});
		// Must abort before ever creating a group or sending a Welcome.
		expect(createGroupSpy).not.toHaveBeenCalled();
		expect(sendWelcomeSpy).not.toHaveBeenCalled();
	});

	it("shows generic error when createGroup fails", async () => {
		createGroupSpy.mockRejectedValue(new Error("http_500"));
		renderModal();

		await act(async () => {
			fireEvent.click(screen.getByRole("button", { name: /connect/i }));
		});

		await waitFor(() => {
			expect(screen.getByText(/could not complete the connection/i)).toBeInTheDocument();
		});
	});

	it("shows 'no_identity' error when identityId is null", async () => {
		useAuthStore.setState({ identityId: null });
		renderModal();

		await act(async () => {
			fireEvent.click(screen.getByRole("button", { name: /connect/i }));
		});

		await waitFor(() => {
			expect(screen.getByText(/secure session not fully initialised/i)).toBeInTheDocument();
		});
	});

	it("Welcome bytes are never logged — sendWelcome receives opaque Uint8Array only", async () => {
		const consoleSpy = vi.spyOn(console, "log").mockImplementation(() => {});
		renderModal();

		await act(async () => {
			fireEvent.click(screen.getByRole("button", { name: /connect/i }));
		});

		await waitFor(() =>
			expect(screen.getByText(/encrypted channel established/i)).toBeInTheDocument(),
		);
		// sendWelcome must be called with a Uint8Array (opaque bytes) — never logged plaintext
		expect(sendWelcomeSpy).toHaveBeenCalled();
		const [, , welcomeArg] = sendWelcomeSpy.mock.calls[0];
		expect(welcomeArg).toBeInstanceOf(Uint8Array);
		expect(consoleSpy).not.toHaveBeenCalledWith(expect.anything(), welcomeArg);
	});
});

describe("AcceptInviteModal — PQ binding (§5.3 Phase B)", () => {
	it("shows PQ badge after successful pq_init exchange", async () => {
		renderModal();

		await act(async () => {
			fireEvent.click(screen.getByRole("button", { name: /connect/i }));
		});

		await waitFor(() =>
			expect(screen.getByText(/encrypted channel established/i)).toBeInTheDocument(),
		);
		// PQ badge is shown with the binding hex value
		expect(screen.getByText("PQ")).toBeInTheDocument();
		expect(screen.getByText("c702693eff3c46bd")).toBeInTheDocument();
	});

	it("sends pq_init Application message after Welcome (pq_init carries ML-KEM ciphertext)", async () => {
		renderModal();

		await act(async () => {
			fireEvent.click(screen.getByRole("button", { name: /connect/i }));
		});

		await waitFor(() =>
			expect(screen.getByText(/encrypted channel established/i)).toBeInTheDocument(),
		);
		// sendMessage is called with the MLS-encrypted pq_init payload
		expect(sendMessageSpy).toHaveBeenCalledWith("tok-test", MOCK_GROUP_ID, expect.any(Uint8Array));
		// pq_init ciphertext body must be an opaque Uint8Array — never a JSON string
		const [, , ctArg] = sendMessageSpy.mock.calls[0];
		expect(ctArg).toBeInstanceOf(Uint8Array);
	});

	it("degrades gracefully when peer has no PQ extension", async () => {
		// Simulate no PQ key in the KeyPackage
		mockCryptoWorker.mlsPqExtractAndVerifyEncapKey.mockRejectedValue(new Error("no_pq_extension"));
		renderModal();

		await act(async () => {
			fireEvent.click(screen.getByRole("button", { name: /connect/i }));
		});

		await waitFor(() =>
			expect(screen.getByText(/encrypted channel established/i)).toBeInTheDocument(),
		);
		// No PQ badge — graceful degradation
		expect(screen.queryByText("PQ")).not.toBeInTheDocument();
		// No pq_init message sent
		expect(sendMessageSpy).not.toHaveBeenCalled();
	});
});
