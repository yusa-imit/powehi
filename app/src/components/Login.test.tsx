import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { useAuthStore } from "../store/auth";
import { Login } from "./Login";

// Mock the crypto worker — no WASM in unit tests.
vi.mock("../hooks/useCryptoWorker", () => ({
	useCryptoWorker: () => null,
}));

beforeEach(() => {
	useAuthStore.setState({ phase: "login", deviceId: null });
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

	it("advances to app phase when handle and password are provided (no worker)", async () => {
		render(<Login />);
		fireEvent.change(screen.getByLabelText(/handle/i), { target: { value: "alice" } });
		fireEvent.change(screen.getByLabelText(/password/i), {
			target: { value: "password123!" },
		});
		fireEvent.click(screen.getByRole("button", { name: /sign in/i }));
		await waitFor(() => {
			expect(useAuthStore.getState().phase).toBe("app");
		});
	});

	it("shows encrypted footer with lock icon", () => {
		render(<Login />);
		expect(screen.getByText(/end-to-end encrypted from the first byte/i)).toBeInTheDocument();
	});
});
