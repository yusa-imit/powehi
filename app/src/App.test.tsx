import { act, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { App } from "./App";
import * as UseDeepLinkModule from "./hooks/useDeepLink";
import { useAuthStore } from "./store/auth";

// Reset Zustand store to login phase between tests.
beforeEach(() => {
	useAuthStore.setState({ phase: "login", deviceId: null, sessionToken: null, identityId: null });
	// Clear URL hash so tests don't bleed invite codes into each other.
	history.replaceState(null, "", "/");
});

afterEach(() => {
	vi.restoreAllMocks();
});

describe("App — login phase", () => {
	it("renders the Login screen when phase is login", () => {
		render(<App />);
		// Title from design spec (Instrument Serif italic heading)
		expect(screen.getByText(/past the horizon/i)).toBeInTheDocument();
	});

	it("renders the tagline on the Login screen", () => {
		render(<App />);
		expect(screen.getByText(/only you/i)).toBeInTheDocument();
	});

	it("renders encrypted footer note", () => {
		render(<App />);
		expect(screen.getByText(/end-to-end encrypted from the first byte/i)).toBeInTheDocument();
	});

	it("renders handle and password inputs", () => {
		render(<App />);
		expect(screen.getByLabelText(/handle/i)).toBeInTheDocument();
		expect(screen.getByLabelText(/password/i)).toBeInTheDocument();
	});

	it("renders the sign in button", () => {
		render(<App />);
		expect(screen.getByRole("button", { name: /sign in/i })).toBeInTheDocument();
	});
});

describe("App — app phase", () => {
	it("renders ChatLayout sidebar when phase is app", () => {
		useAuthStore.setState({ phase: "app", deviceId: "mock-device-id" });
		render(<App />);
		// The sidebar encryption banner has a unique uppercase text node.
		// Use getAllByText because multiple nodes match "end-to-end encrypted"
		// (sidebar banner + message list notice).
		const banners = screen.getAllByText(/end-to-end encrypted/i);
		expect(banners.length).toBeGreaterThanOrEqual(1);
	});

	it("renders the search input in chat sidebar", () => {
		useAuthStore.setState({ phase: "app", deviceId: "mock-device-id" });
		render(<App />);
		expect(screen.getByPlaceholderText(/search chats/i)).toBeInTheDocument();
	});
});

describe("App — invite hash detection", () => {
	it("shows AcceptInviteModal when authenticated and URL has a valid invite hash", async () => {
		// Set a valid 32 hex-char invite code in the fragment before mounting.
		history.pushState(null, "", `/#${"a".repeat(32)}`);
		useAuthStore.setState({ phase: "app", deviceId: "mock-device-id", identityId: "id-1" });

		await act(async () => {
			render(<App />);
		});

		expect(screen.getByRole("dialog", { name: /accept contact invite/i })).toBeInTheDocument();
	});

	it("does not show AcceptInviteModal when not authenticated", () => {
		history.pushState(null, "", `/#${"b".repeat(32)}`);
		// phase stays "login"

		render(<App />);

		expect(screen.queryByRole("dialog", { name: /accept contact invite/i })).toBeNull();
	});

	it("does not show AcceptInviteModal for an invalid hash", async () => {
		history.pushState(null, "", "/#not-a-valid-code");
		useAuthStore.setState({ phase: "app", deviceId: "mock-device-id", identityId: "id-1" });

		await act(async () => {
			render(<App />);
		});

		expect(screen.queryByRole("dialog", { name: /accept contact invite/i })).toBeNull();
	});
});

describe("App — Tauri deep-link invite", () => {
	it("opens AcceptInviteModal when authenticated and deep-link delivers an invite code", async () => {
		let capturedCallback: ((code: string) => void) | undefined;
		vi.spyOn(UseDeepLinkModule, "useDeepLink").mockImplementation((cb) => {
			capturedCallback = cb;
		});

		useAuthStore.setState({ phase: "app", deviceId: "dev-1", identityId: "id-1" });

		await act(async () => {
			render(<App />);
		});

		await act(async () => {
			capturedCallback?.("a".repeat(32));
		});

		expect(screen.getByRole("dialog", { name: /accept contact invite/i })).toBeInTheDocument();
	});

	it("ignores deep-link invite code when not authenticated (phase=login)", async () => {
		let capturedCallback: ((code: string) => void) | undefined;
		vi.spyOn(UseDeepLinkModule, "useDeepLink").mockImplementation((cb) => {
			capturedCallback = cb;
		});

		// phase stays "login"
		render(<App />);

		act(() => {
			capturedCallback?.("b".repeat(32));
		});

		expect(screen.queryByRole("dialog", { name: /accept contact invite/i })).toBeNull();
	});

	it("clears the modal when onClose is called after deep-link invite", async () => {
		let capturedCallback: ((code: string) => void) | undefined;
		vi.spyOn(UseDeepLinkModule, "useDeepLink").mockImplementation((cb) => {
			capturedCallback = cb;
		});

		useAuthStore.setState({ phase: "app", deviceId: "dev-1", identityId: "id-1" });

		await act(async () => {
			render(<App />);
		});
		await act(async () => {
			capturedCallback?.("c".repeat(32));
		});

		const dialog = screen.getByRole("dialog", { name: /accept contact invite/i });
		expect(dialog).toBeInTheDocument();

		// Close via the X button
		const closeBtn = dialog.querySelector("button[aria-label]");
		await act(async () => {
			closeBtn?.dispatchEvent(new MouseEvent("click", { bubbles: true }));
		});

		expect(screen.queryByRole("dialog", { name: /accept contact invite/i })).toBeNull();
	});
});
