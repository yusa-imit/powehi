import { act, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { db } from "../db/schema";
import * as CryptoWorkerHook from "../hooks/useCryptoWorker";
import * as UseMessagesModule from "../hooks/useMessages";
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

describe("ChatLayout — quick switcher (Cmd+K / Ctrl+K)", () => {
	beforeEach(async () => {
		await db.verifiedContacts.clear();
		vi.spyOn(CryptoWorkerHook, "useCryptoWorker").mockReturnValue(
			MOCK_WORKER as unknown as ReturnType<typeof CryptoWorkerHook.useCryptoWorker>,
		);
		vi.spyOn(UseMessagesModule, "useMessages").mockImplementation(() => {});
	});

	afterEach(() => {
		vi.restoreAllMocks();
	});

	it("quick switcher is not visible on initial render", () => {
		render(<ChatLayout />);
		expect(screen.queryByTestId("quick-switcher")).not.toBeInTheDocument();
	});

	it("Ctrl+K opens the quick switcher", async () => {
		render(<ChatLayout />);
		await act(async () => {
			fireEvent.keyDown(window, { key: "k", ctrlKey: true });
		});
		expect(screen.getByTestId("quick-switcher")).toBeInTheDocument();
	});

	it("Meta+K (Cmd+K) opens the quick switcher", async () => {
		render(<ChatLayout />);
		await act(async () => {
			fireEvent.keyDown(window, { key: "k", metaKey: true });
		});
		expect(screen.getByTestId("quick-switcher")).toBeInTheDocument();
	});

	it("Escape closes the quick switcher when input is focused", async () => {
		render(<ChatLayout />);
		await act(async () => {
			fireEvent.keyDown(window, { key: "k", ctrlKey: true });
		});
		expect(screen.getByTestId("quick-switcher")).toBeInTheDocument();
		fireEvent.keyDown(screen.getByTestId("quick-switcher"), { key: "Escape" });
		expect(screen.queryByTestId("quick-switcher")).not.toBeInTheDocument();
	});

	it("clicking the backdrop closes the quick switcher", async () => {
		render(<ChatLayout />);
		await act(async () => {
			fireEvent.keyDown(window, { key: "k", ctrlKey: true });
		});
		expect(screen.getByTestId("quick-switcher")).toBeInTheDocument();
		fireEvent.click(screen.getByTestId("quick-switcher-backdrop"));
		expect(screen.queryByTestId("quick-switcher")).not.toBeInTheDocument();
	});

	it("quick switcher lists all seed chats", async () => {
		render(<ChatLayout />);
		await act(async () => {
			fireEvent.keyDown(window, { key: "k", ctrlKey: true });
		});
		// Seed chats include Maya Akana, Jordan, Ari Work, Sam, Design Team
		expect(screen.getByTestId("quick-switcher-item-maya")).toBeInTheDocument();
		expect(screen.getByTestId("quick-switcher-item-jordan")).toBeInTheDocument();
		expect(screen.getByTestId("quick-switcher-item-ari")).toBeInTheDocument();
	});

	it("typing in the search input filters the chat list", async () => {
		render(<ChatLayout />);
		await act(async () => {
			fireEvent.keyDown(window, { key: "k", ctrlKey: true });
		});
		fireEvent.change(screen.getByTestId("quick-switcher-input"), { target: { value: "maya" } });
		expect(screen.getByTestId("quick-switcher-item-maya")).toBeInTheDocument();
		expect(screen.queryByTestId("quick-switcher-item-jordan")).not.toBeInTheDocument();
	});

	it("shows 'No conversations found' when query matches nothing", async () => {
		render(<ChatLayout />);
		await act(async () => {
			fireEvent.keyDown(window, { key: "k", ctrlKey: true });
		});
		fireEvent.change(screen.getByTestId("quick-switcher-input"), {
			target: { value: "xyznonexistent" },
		});
		expect(screen.getByTestId("quick-switcher-empty")).toBeInTheDocument();
		expect(screen.getByText(/no conversations found/i)).toBeInTheDocument();
	});

	it("clicking a chat item switches to that chat and closes the switcher", async () => {
		render(<ChatLayout />);
		await act(async () => {
			fireEvent.keyDown(window, { key: "k", ctrlKey: true });
		});
		fireEvent.click(screen.getByTestId("quick-switcher-item-jordan"));
		// Switcher should close
		expect(screen.queryByTestId("quick-switcher")).not.toBeInTheDocument();
		// Jordan's name should appear in the conversation header
		const headers = screen.getAllByText("Jordan");
		expect(headers.length).toBeGreaterThan(0);
	});

	it("ArrowDown moves active highlight to the next item", async () => {
		render(<ChatLayout />);
		await act(async () => {
			fireEvent.keyDown(window, { key: "k", ctrlKey: true });
		});
		const switcher = screen.getByTestId("quick-switcher");
		// First item should be selected (index 0) by default
		const items = screen
			.getAllByRole("button", { name: /./ })
			.filter((btn) => btn.dataset.testid?.startsWith("quick-switcher-item-"));
		expect(items[0].getAttribute("aria-selected")).toBe("true");
		fireEvent.keyDown(switcher, { key: "ArrowDown" });
		expect(items[0].getAttribute("aria-selected")).toBe("false");
		expect(items[1].getAttribute("aria-selected")).toBe("true");
	});

	it("Enter selects the highlighted item", async () => {
		render(<ChatLayout />);
		await act(async () => {
			fireEvent.keyDown(window, { key: "k", ctrlKey: true });
		});
		// Filter to just 'maya' so it's first
		fireEvent.change(screen.getByTestId("quick-switcher-input"), { target: { value: "maya" } });
		fireEvent.keyDown(screen.getByTestId("quick-switcher"), { key: "Enter" });
		expect(screen.queryByTestId("quick-switcher")).not.toBeInTheDocument();
	});

	it("second Ctrl+K press closes the switcher", async () => {
		render(<ChatLayout />);
		await act(async () => {
			fireEvent.keyDown(window, { key: "k", ctrlKey: true });
		});
		expect(screen.getByTestId("quick-switcher")).toBeInTheDocument();
		await act(async () => {
			fireEvent.keyDown(window, { key: "k", ctrlKey: true });
		});
		expect(screen.queryByTestId("quick-switcher")).not.toBeInTheDocument();
	});
});
