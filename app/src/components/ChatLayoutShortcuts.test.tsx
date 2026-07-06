import { act, cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { db } from "../db/schema";
import * as CryptoWorkerHook from "../hooks/useCryptoWorker";
import * as UseMessagesModule from "../hooks/useMessages";
import { useAuthStore } from "../store/auth";
import { ChatLayout } from "./ChatLayout";

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
};

function renderLayout() {
	return render(<ChatLayout />);
}

describe("keyboard shortcuts modal", () => {
	beforeEach(async () => {
		await db.verifiedContacts.clear();
		vi.spyOn(CryptoWorkerHook, "useCryptoWorker").mockReturnValue(
			MOCK_WORKER as unknown as ReturnType<typeof CryptoWorkerHook.useCryptoWorker>,
		);
		useAuthStore.setState({
			sessionToken: "tok-shortcuts",
			identityId: "id-shortcuts",
			deviceId: "dev-shortcuts",
		});
		vi.spyOn(UseMessagesModule, "useMessages").mockImplementation(() => {});
	});

	afterEach(async () => {
		await act(async () => {});
		cleanup();
		vi.restoreAllMocks();
	});

	it("1. modal is hidden by default", () => {
		renderLayout();
		expect(screen.queryByTestId("keyboard-shortcuts-modal")).not.toBeInTheDocument();
	});

	it("2. pressing ? (not in input) opens the modal", async () => {
		renderLayout();
		await act(async () => {
			fireEvent.keyDown(window, { key: "?" });
		});
		expect(screen.getByTestId("keyboard-shortcuts-modal")).toBeInTheDocument();
	});

	it("3. pressing ? while focused on textarea does NOT open the modal", async () => {
		renderLayout();
		const textarea = screen.getByPlaceholderText(/encrypted/i);
		textarea.focus();
		await act(async () => {
			fireEvent.keyDown(window, { key: "?" });
		});
		expect(screen.queryByTestId("keyboard-shortcuts-modal")).not.toBeInTheDocument();
	});

	it("4. modal has correct data-testid", async () => {
		renderLayout();
		await act(async () => {
			fireEvent.keyDown(window, { key: "?" });
		});
		const modal = screen.getByTestId("keyboard-shortcuts-modal");
		expect(modal).toBeInTheDocument();
	});

	it("5. modal shows a title containing 'Shortcuts' or 'Keyboard'", async () => {
		renderLayout();
		await act(async () => {
			fireEvent.keyDown(window, { key: "?" });
		});
		const modal = screen.getByTestId("keyboard-shortcuts-modal");
		expect(modal.textContent).toMatch(/Shortcuts|Keyboard/i);
	});

	it("6. modal lists 'Ctrl+F' (search action visible)", async () => {
		renderLayout();
		await act(async () => {
			fireEvent.keyDown(window, { key: "?" });
		});
		const modal = screen.getByTestId("keyboard-shortcuts-modal");
		expect(modal.textContent).toContain("Ctrl+F");
	});

	it("7. close button closes the modal", async () => {
		renderLayout();
		await act(async () => {
			fireEvent.keyDown(window, { key: "?" });
		});
		expect(screen.getByTestId("keyboard-shortcuts-modal")).toBeInTheDocument();
		fireEvent.click(screen.getByTestId("keyboard-shortcuts-close"));
		expect(screen.queryByTestId("keyboard-shortcuts-modal")).not.toBeInTheDocument();
	});

	it("8. pressing Escape closes the modal", async () => {
		renderLayout();
		await act(async () => {
			fireEvent.keyDown(window, { key: "?" });
		});
		expect(screen.getByTestId("keyboard-shortcuts-modal")).toBeInTheDocument();
		await act(async () => {
			fireEvent.keyDown(screen.getByTestId("keyboard-shortcuts-modal"), { key: "Escape" });
		});
		expect(screen.queryByTestId("keyboard-shortcuts-modal")).not.toBeInTheDocument();
	});

	it("9. pressing ? while modal is open closes it (toggle)", async () => {
		renderLayout();
		// Open
		await act(async () => {
			fireEvent.keyDown(window, { key: "?" });
		});
		expect(screen.getByTestId("keyboard-shortcuts-modal")).toBeInTheDocument();
		// Toggle closed
		await act(async () => {
			fireEvent.keyDown(window, { key: "?" });
		});
		expect(screen.queryByTestId("keyboard-shortcuts-modal")).not.toBeInTheDocument();
	});

	it("10. clicking backdrop closes the modal", async () => {
		renderLayout();
		await act(async () => {
			fireEvent.keyDown(window, { key: "?" });
		});
		const modal = screen.getByTestId("keyboard-shortcuts-modal");
		expect(modal).toBeInTheDocument();
		fireEvent.click(modal);
		expect(screen.queryByTestId("keyboard-shortcuts-modal")).not.toBeInTheDocument();
	});

	it("11. pressing ? while focused on input does NOT open the modal", async () => {
		renderLayout();
		// Focus the sidebar search input
		const searchInput = screen.getByPlaceholderText("Search chats");
		searchInput.focus();
		await act(async () => {
			fireEvent.keyDown(window, { key: "?" });
		});
		expect(screen.queryByTestId("keyboard-shortcuts-modal")).not.toBeInTheDocument();
	});
});
