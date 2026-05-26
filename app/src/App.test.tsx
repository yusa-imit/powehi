import { render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it } from "vitest";
import { App } from "./App";
import { useAuthStore } from "./store/auth";

// Reset Zustand store to login phase between tests.
beforeEach(() => {
	useAuthStore.setState({ phase: "login", deviceId: null });
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

	it("renders the send button", () => {
		render(<App />);
		expect(screen.getByRole("button", { name: /send/i })).toBeInTheDocument();
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
