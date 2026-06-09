import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import * as InvitesModule from "../api/invites";
import { useAuthStore } from "../store/auth";
import { InviteModal } from "./InviteModal";

// ── Mocks ─────────────────────────────────────────────────────────────────────

vi.mock("../api/invites", () => ({
	createInvite: vi.fn(),
	buildInviteUrl: vi.fn((origin: string, code: string) => `${origin}/i/connect#${code}`),
	redeemInvite: vi.fn(),
	extractInviteCode: vi.fn(),
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
const INVITE_URL = `http://localhost:3000/i/connect#${CODE}`;

beforeEach(() => {
	useAuthStore.setState({ sessionToken: TOKEN, phase: "app" });
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
	it("calls createInvite with session token on button click", async () => {
		render(<InviteModal open={true} onClose={vi.fn()} />);
		await act(async () => {
			fireEvent.click(screen.getByText("Create invite link"));
		});
		expect(createInviteSpy).toHaveBeenCalledWith(TOKEN);
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
		expect(parsed.hash).toBe(`#${CODE}`);
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
