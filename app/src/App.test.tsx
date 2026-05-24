import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { App } from "./App";

describe("App", () => {
	it("renders the app name", () => {
		render(<App />);
		expect(screen.getByRole("heading", { name: /pōwehi/i })).toBeInTheDocument();
	});

	it("renders the tagline", () => {
		render(<App />);
		expect(screen.getByText(/end-to-end encrypted/i)).toBeInTheDocument();
	});
});
