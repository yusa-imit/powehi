import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import * as InvitesModule from "../api/invites";
import * as CryptoWorkerHook from "../hooks/useCryptoWorker";
import { useAuthStore } from "../store/auth";
import { InviteModal } from "./InviteModal";

// ── Mocks ─────────────────────────────────────────────────────────────────────

vi.mock("../api/invites", () => ({
	createInvite: vi.fn(),
	buildInviteUrl: vi.fn(
		(origin: string, code: string, keyPackageHash: string) =>
			`${origin}/i/connect#${code}.${keyPackageHash}`,
	),
	redeemInvite: vi.fn(),
	extractInviteData: vi.fn(),
}));

const QR_DATA_URL =
	"data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==";

vi.mock("qrcode", () => ({
	default: {
		toDataURL: vi
			.fn()
			.mockResolvedValue(
				"data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==",
			),
	},
}));

const createInviteSpy = vi.spyOn(InvitesModule, "createInvite");

const TOKEN = "test-session-token";
const CODE = "aabbccdd00112233aabbccdd00112233";
const MOCK_KEY_PACKAGE = new Uint8Array(Array.from({ length: 64 }, (_, i) => i));

async function sha256Hex(bytes: Uint8Array<ArrayBuffer>): Promise<string> {
	const digest = await crypto.subtle.digest("SHA-256", bytes);
	return Array.from(new Uint8Array(digest))
		.map((b) => b.toString(16).padStart(2, "0"))
		.join("");
}

// The invite URL's #fragment must carry the *real* hash InviteModal computes
// locally (never a server-supplied one) — computed once against the actual
// Web Crypto API rather than mocked away.
let HASH: string;
let INVITE_URL: string;
beforeAll(async () => {
	HASH = await sha256Hex(MOCK_KEY_PACKAGE);
	INVITE_URL = `http://localhost:3000/i/connect#${CODE}.${HASH}`;
});

const mockCryptoWorker = {
	mlsGetKeyPackage: vi.fn(async () => ({
		keyPackage: MOCK_KEY_PACKAGE,
		pqDecapKeyHandle: "mock-pq-handle",
	})),
};

beforeEach(() => {
	useAuthStore.setState({ sessionToken: TOKEN, phase: "app", identityId: "identity-abc" });
	vi.spyOn(CryptoWorkerHook, "useCryptoWorker").mockReturnValue(
		mockCryptoWorker as unknown as ReturnType<typeof CryptoWorkerHook.useCryptoWorker>,
	);
	Object.defineProperty(window, "location", {
		value: { origin: "http://localhost:3000" },
		writable: true,
	});
	Object.assign(navigator, {
		clipboard: { writeText: vi.fn().mockResolvedValue(undefined) },
	});
	createInviteSpy.mockResolvedValue({ code: CODE });
});

afterEach(() => {
	vi.clearAllMocks();
});

// ── Rendering ─────────────────────────────────────────────────────────────────

describe("InviteModal rendering", () => {
	it("renders when open=true", () => {
		render(<InviteModal open={true} onClose={vi.fn()} />);
		expect(screen.getByRole("dialog")).toBeDefined();
	});

	it("does not render when open=false", () => {
		render(<InviteModal open={false} onClose={vi.fn()} />);
		expect(screen.queryByRole("dialog")).toBeNull();
	});

	it("shows Create invite link button in idle state", () => {
		render(<InviteModal open={true} onClose={vi.fn()} />);
		expect(screen.getByText("Create invite link")).toBeDefined();
	});
});

// ── Create flow ───────────────────────────────────────────────────────────────

describe("InviteModal create flow", () => {
	it("generates a fresh KeyPackage and calls createInvite with it", async () => {
		render(<InviteModal open={true} onClose={vi.fn()} />);
		await act(async () => {
			fireEvent.click(screen.getByText("Create invite link"));
		});
		await waitFor(() => {
			expect(screen.getByTestId("invite-url")).toBeDefined();
		});
		expect(mockCryptoWorker.mlsGetKeyPackage).toHaveBeenCalledWith("identity-abc");
		expect(createInviteSpy).toHaveBeenCalledWith(TOKEN, MOCK_KEY_PACKAGE);
	});

	it("shows error state when identityId is missing (crypto not initialised)", async () => {
		useAuthStore.setState({ identityId: null });
		render(<InviteModal open={true} onClose={vi.fn()} />);
		await act(async () => {
			fireEvent.click(screen.getByText("Create invite link"));
		});
		await waitFor(() => {
			expect(screen.getByText(/Could not create invite link/)).toBeDefined();
		});
		expect(createInviteSpy).not.toHaveBeenCalled();
	});

	it("shows invite URL after successful creation", async () => {
		render(<InviteModal open={true} onClose={vi.fn()} />);
		await act(async () => {
			fireEvent.click(screen.getByText("Create invite link"));
		});
		await waitFor(() => {
			expect(screen.getByTestId("invite-url")).toBeDefined();
		});
		const urlEl = screen.getByTestId("invite-url");
		expect(urlEl.textContent).toContain(CODE);
	});

	it("places code in URL fragment not path (security invariant)", async () => {
		render(<InviteModal open={true} onClose={vi.fn()} />);
		await act(async () => {
			fireEvent.click(screen.getByText("Create invite link"));
		});
		await waitFor(() => {
			expect(screen.getByTestId("invite-url")).toBeDefined();
		});
		const urlText = screen.getByTestId("invite-url").textContent ?? "";
		const parsed = new URL(urlText);
		expect(parsed.hash).toBe(`#${CODE}.${HASH}`);
		expect(parsed.pathname).not.toContain(CODE);
	});

	it("shows error state when createInvite throws", async () => {
		createInviteSpy.mockRejectedValueOnce(new Error("rate_limited"));
		render(<InviteModal open={true} onClose={vi.fn()} />);
		await act(async () => {
			fireEvent.click(screen.getByText("Create invite link"));
		});
		await waitFor(() => {
			expect(screen.getByText(/Could not create invite link/)).toBeDefined();
		});
	});
});

// ── Copy flow ─────────────────────────────────────────────────────────────────

describe("InviteModal copy flow", () => {
	it("copies full invite URL to clipboard", async () => {
		render(<InviteModal open={true} onClose={vi.fn()} />);
		await act(async () => {
			fireEvent.click(screen.getByText("Create invite link"));
		});
		await waitFor(() => {
			expect(screen.getByLabelText("Copy invite link")).toBeDefined();
		});
		await act(async () => {
			fireEvent.click(screen.getByLabelText("Copy invite link"));
		});
		expect(navigator.clipboard.writeText).toHaveBeenCalledWith(INVITE_URL);
	});

	it("shows Copied! feedback after copy", async () => {
		render(<InviteModal open={true} onClose={vi.fn()} />);
		await act(async () => {
			fireEvent.click(screen.getByText("Create invite link"));
		});
		await waitFor(() => {
			expect(screen.getByLabelText("Copy invite link")).toBeDefined();
		});
		await act(async () => {
			fireEvent.click(screen.getByLabelText("Copy invite link"));
		});
		expect(screen.getByText("Copied!")).toBeDefined();
	});
});

// ── Close ─────────────────────────────────────────────────────────────────────

describe("InviteModal close", () => {
	it("calls onClose when close button clicked", () => {
		const onClose = vi.fn();
		render(<InviteModal open={true} onClose={onClose} />);
		fireEvent.click(screen.getByLabelText("Close"));
		expect(onClose).toHaveBeenCalledOnce();
	});

	it("calls onClose when backdrop clicked", () => {
		const onClose = vi.fn();
		render(<InviteModal open={true} onClose={onClose} />);
		fireEvent.click(screen.getByRole("dialog"));
		expect(onClose).toHaveBeenCalledOnce();
	});
});

// ── QR code ───────────────────────────────────────────────────────────────────

describe("InviteModal QR code", () => {
	it("renders QR code image after invite link is created", async () => {
		render(<InviteModal open={true} onClose={vi.fn()} />);
		await act(async () => {
			fireEvent.click(screen.getByText("Create invite link"));
		});
		await waitFor(() => {
			expect(screen.getByTestId("invite-qr")).toBeDefined();
		});
	});

	it("QR code image has descriptive alt text for accessibility", async () => {
		render(<InviteModal open={true} onClose={vi.fn()} />);
		await act(async () => {
			fireEvent.click(screen.getByText("Create invite link"));
		});
		await waitFor(() => {
			const img = screen.getByTestId("invite-qr");
			expect(img.getAttribute("alt")).toBe("QR code for invite link");
		});
	});

	it("QR code src is a data URL — never an external URL (security invariant)", async () => {
		render(<InviteModal open={true} onClose={vi.fn()} />);
		await act(async () => {
			fireEvent.click(screen.getByText("Create invite link"));
		});
		await waitFor(() => {
			const img = screen.getByTestId("invite-qr") as HTMLImageElement;
			expect(img.src).toBe(QR_DATA_URL);
			expect(img.src).toMatch(/^data:/);
			expect(img.src).not.toMatch(/^https?:\/\//);
		});
	});
});
