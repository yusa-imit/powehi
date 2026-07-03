import { act, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { db } from "../db/schema";
import * as CryptoWorkerHook from "../hooks/useCryptoWorker";
import * as UseMessagesModule from "../hooks/useMessages";
import { ChatLayout } from "./ChatLayout";

const MOCK_WORKER = {
	mlsGroupMembers: vi.fn(async () => []),
	mlsComputeSafetyNumber: vi.fn(async () => ({ safetyNumber: "000000 000000" })),
	mlsEncrypt: vi.fn(async () => ({ ciphertext: new Uint8Array([0xde, 0xad]) })),
	mlsDecrypt: vi.fn(async () => ({ plaintext: new Uint8Array() })),
	encryptDbField: vi.fn(async (v: string) => v),
	decryptDbField: vi.fn(async (v: string) => v),
};

describe("ChatLayout — custom user status", () => {
	beforeEach(async () => {
		await db.verifiedContacts.clear();
		vi.spyOn(CryptoWorkerHook, "useCryptoWorker").mockReturnValue(
			MOCK_WORKER as unknown as ReturnType<typeof CryptoWorkerHook.useCryptoWorker>,
		);
		vi.spyOn(UseMessagesModule, "useMessages").mockImplementation(() => undefined);
	});

	afterEach(() => {
		vi.restoreAllMocks();
	});

	it("user status bar is always visible in the sidebar", async () => {
		render(<ChatLayout />);
		expect(screen.getByTestId("user-status-bar")).toBeInTheDocument();
	});

	it("shows placeholder text when no status is set", async () => {
		render(<ChatLayout />);
		expect(screen.getByTestId("user-status-placeholder")).toHaveTextContent("Set a status...");
	});

	it("edit status button opens the status editor", async () => {
		render(<ChatLayout />);
		await act(async () => {
			fireEvent.click(screen.getByTestId("user-status-edit-btn"));
		});
		expect(screen.getByTestId("status-editor")).toBeInTheDocument();
	});

	it("status editor has emoji input and text input", async () => {
		render(<ChatLayout />);
		await act(async () => {
			fireEvent.click(screen.getByTestId("user-status-edit-btn"));
		});
		expect(screen.getByTestId("status-emoji-input")).toBeInTheDocument();
		expect(screen.getByTestId("status-text-input")).toBeInTheDocument();
	});

	it("clicking a preset populates the emoji and text inputs", async () => {
		render(<ChatLayout />);
		await act(async () => {
			fireEvent.click(screen.getByTestId("user-status-edit-btn"));
		});
		await act(async () => {
			fireEvent.click(screen.getByTestId("status-preset-working-from-home"));
		});
		expect(screen.getByTestId("status-emoji-input")).toHaveValue("🏠");
		expect(screen.getByTestId("status-text-input")).toHaveValue("Working from home");
	});

	it("saving a typed status shows it in the sidebar", async () => {
		render(<ChatLayout />);
		await act(async () => {
			fireEvent.click(screen.getByTestId("user-status-edit-btn"));
		});
		await act(async () => {
			fireEvent.change(screen.getByTestId("status-emoji-input"), { target: { value: "🎉" } });
			fireEvent.change(screen.getByTestId("status-text-input"), {
				target: { value: "Having fun" },
			});
		});
		await act(async () => {
			fireEvent.click(screen.getByTestId("status-save-btn"));
		});
		expect(screen.getByTestId("user-status-text")).toHaveTextContent("Having fun");
	});

	it("saved status emoji appears in the status bar", async () => {
		render(<ChatLayout />);
		await act(async () => {
			fireEvent.click(screen.getByTestId("user-status-edit-btn"));
		});
		await act(async () => {
			fireEvent.change(screen.getByTestId("status-emoji-input"), { target: { value: "🎧" } });
			fireEvent.change(screen.getByTestId("status-text-input"), {
				target: { value: "In a meeting" },
			});
		});
		await act(async () => {
			fireEvent.click(screen.getByTestId("status-save-btn"));
		});
		const statusEl = screen.getByTestId("user-status-text");
		expect(statusEl.textContent).toContain("🎧");
		expect(statusEl.textContent).toContain("In a meeting");
	});

	it("cancel closes the editor without saving the status", async () => {
		render(<ChatLayout />);
		await act(async () => {
			fireEvent.click(screen.getByTestId("user-status-edit-btn"));
		});
		await act(async () => {
			fireEvent.change(screen.getByTestId("status-text-input"), {
				target: { value: "This should not save" },
			});
		});
		await act(async () => {
			fireEvent.click(screen.getByTestId("status-cancel-btn"));
		});
		expect(screen.queryByTestId("status-editor")).not.toBeInTheDocument();
		expect(screen.getByTestId("user-status-placeholder")).toBeInTheDocument();
	});

	it("clear status removes an existing status and returns to placeholder", async () => {
		render(<ChatLayout />);
		// Set a status first
		await act(async () => {
			fireEvent.click(screen.getByTestId("user-status-edit-btn"));
		});
		await act(async () => {
			fireEvent.change(screen.getByTestId("status-text-input"), {
				target: { value: "On vacation" },
			});
		});
		await act(async () => {
			fireEvent.click(screen.getByTestId("status-save-btn"));
		});
		expect(screen.getByTestId("user-status-text")).toBeInTheDocument();

		// Now clear it
		await act(async () => {
			fireEvent.click(screen.getByTestId("user-status-edit-btn"));
		});
		await act(async () => {
			fireEvent.click(screen.getByTestId("status-clear-btn"));
		});
		expect(screen.queryByTestId("user-status-text")).not.toBeInTheDocument();
		expect(screen.getByTestId("user-status-placeholder")).toBeInTheDocument();
	});

	it("saving empty inputs clears the status", async () => {
		render(<ChatLayout />);
		// Set a status first
		await act(async () => {
			fireEvent.click(screen.getByTestId("user-status-edit-btn"));
		});
		await act(async () => {
			fireEvent.change(screen.getByTestId("status-text-input"), { target: { value: "test" } });
		});
		await act(async () => {
			fireEvent.click(screen.getByTestId("status-save-btn"));
		});
		// Reopen and clear both inputs, then save
		await act(async () => {
			fireEvent.click(screen.getByTestId("user-status-edit-btn"));
		});
		await act(async () => {
			fireEvent.change(screen.getByTestId("status-emoji-input"), { target: { value: "" } });
			fireEvent.change(screen.getByTestId("status-text-input"), { target: { value: "" } });
		});
		await act(async () => {
			fireEvent.click(screen.getByTestId("status-save-btn"));
		});
		expect(screen.queryByTestId("user-status-text")).not.toBeInTheDocument();
		expect(screen.getByTestId("user-status-placeholder")).toBeInTheDocument();
	});

	it("clicking the overlay backdrop closes the editor without saving", async () => {
		render(<ChatLayout />);
		await act(async () => {
			fireEvent.click(screen.getByTestId("user-status-edit-btn"));
		});
		await act(async () => {
			fireEvent.change(screen.getByTestId("status-text-input"), { target: { value: "nope" } });
		});
		await act(async () => {
			fireEvent.click(screen.getByTestId("status-editor-overlay"));
		});
		expect(screen.queryByTestId("status-editor")).not.toBeInTheDocument();
		expect(screen.getByTestId("user-status-placeholder")).toBeInTheDocument();
	});

	it("clear-status button only visible when a status exists", async () => {
		render(<ChatLayout />);
		// No status yet — no clear button
		await act(async () => {
			fireEvent.click(screen.getByTestId("user-status-edit-btn"));
		});
		expect(screen.queryByTestId("status-clear-btn")).not.toBeInTheDocument();
		await act(async () => {
			fireEvent.click(screen.getByTestId("status-cancel-btn"));
		});

		// Set a status, reopen — clear button appears
		await act(async () => {
			fireEvent.click(screen.getByTestId("user-status-edit-btn"));
		});
		await act(async () => {
			fireEvent.change(screen.getByTestId("status-text-input"), { target: { value: "busy" } });
		});
		await act(async () => {
			fireEvent.click(screen.getByTestId("status-save-btn"));
		});
		await act(async () => {
			fireEvent.click(screen.getByTestId("user-status-edit-btn"));
		});
		expect(screen.getByTestId("status-clear-btn")).toBeInTheDocument();
	});
});
