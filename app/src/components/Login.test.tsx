import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { useAuthStore } from "../store/auth";
import { Login } from "./Login";

// Mock the crypto worker — no WASM in unit tests.
vi.mock("../hooks/useCryptoWorker", () => ({
	useCryptoWorker: () => null,
}));

// Mock API calls — no network in unit tests.
vi.mock("../api/auth", () => ({
	hashHandle: async (h: string) => new Uint8Array(32).fill(h.charCodeAt(0)),
	regInit: vi.fn(),
	regFinish: vi.fn(),
	loginInit: vi.fn(),
	loginFinish: vi.fn(),
	uploadKeyPackage: vi.fn(),
	fromJsonArray: (a: number[]) => new Uint8Array(a),
}));

// fake-indexeddb is loaded globally in test-setup.ts.

afterEach(cleanup);
beforeEach(() => {
	useAuthStore.setState({ phase: "login", deviceId: null, sessionToken: null });
});

describe("Login component", () => {
	it("renders a heading with Powehi name", () => {
		render(<Login />);
		expect(screen.getByRole("heading", { name: /powehi/i })).toBeInTheDocument();
	});

	it("renders handle and password inputs", () => {
		render(<Login />);
		expect(screen.getByLabelText(/handle/i)).toBeInTheDocument();
		expect(screen.getByLabelText(/password/i)).toBeInTheDocument();
	});

	it("renders the Sign in button", () => {
		render(<Login />);
		expect(screen.getByRole("button", { name: /sign in/i })).toBeInTheDocument();
	});

	it("shows error and does NOT advance phase when handle is empty", async () => {
		render(<Login />);
		fireEvent.click(screen.getByRole("button", { name: /sign in/i }));
		await waitFor(() => {
			expect(screen.getByText(/handle and password are required/i)).toBeInTheDocument();
		});
		expect(useAuthStore.getState().phase).toBe("login");
	});

	it("shows error and does NOT advance phase when password is empty", async () => {
		render(<Login />);
		fireEvent.change(screen.getByLabelText(/handle/i), { target: { value: "alice" } });
		fireEvent.click(screen.getByRole("button", { name: /sign in/i }));
		await waitFor(() => {
			expect(screen.getByText(/handle and password are required/i)).toBeInTheDocument();
		});
		expect(useAuthStore.getState().phase).toBe("login");
	});

	it("shows no-device error when sign-in attempted without a registered device", async () => {
		render(<Login />);
		fireEvent.change(screen.getByLabelText(/handle/i), { target: { value: "alice" } });
		fireEvent.change(screen.getByLabelText(/password/i), {
			target: { value: "password123!" },
		});
		fireEvent.click(screen.getByRole("button", { name: /sign in/i }));
		await waitFor(() => {
			expect(screen.getByText(/no device registered on this browser/i)).toBeInTheDocument();
		});
		expect(useAuthStore.getState().phase).toBe("login");
	});

	it("shows crypto unavailable error on create-account when worker is null", async () => {
		render(<Login />);
		// Switch to create-account mode
		fireEvent.click(screen.getByText(/new to powehi/i));
		fireEvent.change(screen.getByLabelText(/handle/i), { target: { value: "alice" } });
		fireEvent.change(screen.getByLabelText(/password/i), {
			target: { value: "password123!" },
		});
		fireEvent.click(screen.getByRole("button", { name: /create account/i }));
		await waitFor(() => {
			expect(screen.getByText(/encryption module unavailable/i)).toBeInTheDocument();
		});
		expect(useAuthStore.getState().phase).toBe("login");
	});

	it("toggles to create-account mode showing zero-knowledge subtitle", () => {
		render(<Login />);
		const toggleBtn = screen.getByText(/new to powehi/i);
		fireEvent.click(toggleBtn);
		expect(screen.getByText(/zero knowledge/i)).toBeInTheDocument();
	});

	it("toggles back to sign-in mode showing sign-in subtitle", () => {
		render(<Login />);
		fireEvent.click(screen.getByText(/new to powehi/i));
		fireEvent.click(screen.getByText(/already have an account/i));
		expect(screen.getByText(/sign in securely/i)).toBeInTheDocument();
	});

	it("shows encrypted footer with lock icon", () => {
		render(<Login />);
		expect(screen.getByText(/end-to-end encrypted from the first byte/i)).toBeInTheDocument();
	});
});
