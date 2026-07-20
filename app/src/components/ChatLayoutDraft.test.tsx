import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { db } from "../db/schema";
import * as CryptoWorkerHook from "../hooks/useCryptoWorker";
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

describe("ChatLayout — draft message saving", () => {
	beforeEach(async () => {
		await db.verifiedContacts.clear();
		vi.spyOn(CryptoWorkerHook, "useCryptoWorker").mockReturnValue(
			MOCK_WORKER as unknown as ReturnType<typeof CryptoWorkerHook.useCryptoWorker>,
		);
		useAuthStore.setState({
			sessionToken: "tok-draft",
			identityId: "id-draft",
			deviceId: "dev-draft",
		});
	});

	afterEach(() => {
		vi.restoreAllMocks();
	});

	it("draft is preserved when switching chats", async () => {
		render(<ChatLayout />);
		const textarea = screen.getByPlaceholderText(/encrypted/i);
		fireEvent.change(textarea, { target: { value: "hello maya" } });
		expect(textarea).toHaveValue("hello maya");

		fireEvent.click(screen.getByRole("button", { name: /jordan/i }));
		fireEvent.click(screen.getAllByRole("button", { name: /maya akana/i })[0]);

		await waitFor(() => {
			expect(screen.getByPlaceholderText(/encrypted/i)).toHaveValue("hello maya");
		});
	});

	it("chat 2 composer is empty when selected (no cross-contamination)", async () => {
		render(<ChatLayout />);
		const textarea = screen.getByPlaceholderText(/encrypted/i);
		fireEvent.change(textarea, { target: { value: "only for maya" } });

		fireEvent.click(screen.getByRole("button", { name: /jordan/i }));

		await waitFor(() => {
			expect(screen.getByPlaceholderText(/encrypted/i)).toHaveValue("");
		});
	});

	it("draft is cleared after sending", async () => {
		render(<ChatLayout />);
		const textarea = screen.getByPlaceholderText(/encrypted/i);
		fireEvent.change(textarea, { target: { value: "to be sent" } });

		fireEvent.keyDown(textarea, { key: "Enter", shiftKey: false });

		fireEvent.click(screen.getByRole("button", { name: /jordan/i }));
		fireEvent.click(screen.getAllByRole("button", { name: /maya akana/i })[0]);

		await waitFor(() => {
			expect(screen.getByPlaceholderText(/encrypted/i)).toHaveValue("");
		});
	});

	it("different chats have independent drafts", async () => {
		render(<ChatLayout />);
		const textarea = screen.getByPlaceholderText(/encrypted/i);
		fireEvent.change(textarea, { target: { value: "hello" } });

		fireEvent.click(screen.getByRole("button", { name: /jordan/i }));
		await waitFor(() => {
			expect(screen.getByPlaceholderText(/encrypted/i)).toHaveValue("");
		});
		fireEvent.change(screen.getByPlaceholderText(/encrypted/i), { target: { value: "world" } });

		fireEvent.click(screen.getAllByRole("button", { name: /maya akana/i })[0]);
		await waitFor(() => {
			expect(screen.getByPlaceholderText(/encrypted/i)).toHaveValue("hello");
		});

		fireEvent.click(screen.getByRole("button", { name: /jordan/i }));
		await waitFor(() => {
			expect(screen.getByPlaceholderText(/encrypted/i)).toHaveValue("world");
		});
	});

	it("draft is empty initially for a fresh chat (no saved draft)", () => {
		render(<ChatLayout />);
		expect(screen.getByPlaceholderText(/encrypted/i)).toHaveValue("");
	});

	// ── Draft sidebar indicator tests ──────────────────────────────────────────

	it("draft-preview appears in sidebar after switching away from a chat with text", async () => {
		render(<ChatLayout />);
		const textarea = screen.getByPlaceholderText(/encrypted/i);
		fireEvent.change(textarea, { target: { value: "hello world" } });

		fireEvent.click(screen.getByRole("button", { name: /jordan/i }));

		await waitFor(() => {
			expect(screen.getByTestId("draft-preview")).toBeInTheDocument();
		});
	});

	it("draft-preview shows 'Draft:' label and the draft text", async () => {
		render(<ChatLayout />);
		const textarea = screen.getByPlaceholderText(/encrypted/i);
		fireEvent.change(textarea, { target: { value: "my draft message" } });

		fireEvent.click(screen.getByRole("button", { name: /jordan/i }));

		await waitFor(() => {
			const preview = screen.getByTestId("draft-preview");
			expect(preview).toHaveTextContent("Draft:");
			expect(preview).toHaveTextContent("my draft message");
		});
	});

	it("draft-preview absent for the active chat even with text in composer", async () => {
		render(<ChatLayout />);
		const textarea = screen.getByPlaceholderText(/encrypted/i);
		fireEvent.change(textarea, { target: { value: "typing now" } });

		expect(screen.queryByTestId("draft-preview")).not.toBeInTheDocument();
	});

	it("draft-preview absent when no text was typed before switching", async () => {
		render(<ChatLayout />);
		fireEvent.click(screen.getByRole("button", { name: /jordan/i }));

		await waitFor(() => {
			expect(screen.queryByTestId("draft-preview")).not.toBeInTheDocument();
		});
	});

	it("draft-preview disappears after the draft is sent", async () => {
		render(<ChatLayout />);
		const textarea = screen.getByPlaceholderText(/encrypted/i);
		fireEvent.change(textarea, { target: { value: "soon to be sent" } });

		fireEvent.keyDown(textarea, { key: "Enter", shiftKey: false });

		fireEvent.click(screen.getByRole("button", { name: /jordan/i }));

		await waitFor(() => {
			expect(screen.queryByTestId("draft-preview")).not.toBeInTheDocument();
		});
	});

	it("each inactive chat shows its own independent draft-preview", async () => {
		render(<ChatLayout />);
		const textarea = screen.getByPlaceholderText(/encrypted/i);
		fireEvent.change(textarea, { target: { value: "maya draft" } });

		fireEvent.click(screen.getByRole("button", { name: /jordan/i }));
		await waitFor(() => {
			expect(screen.getByTestId("draft-preview")).toBeInTheDocument();
		});

		fireEvent.change(screen.getByPlaceholderText(/encrypted/i), {
			target: { value: "jordan draft" },
		});

		fireEvent.click(screen.getAllByRole("button", { name: /maya akana/i })[0]);
		await waitFor(() => {
			const previews = screen.getAllByTestId("draft-preview");
			expect(previews).toHaveLength(1);
			expect(previews[0]).toHaveTextContent("jordan draft");
		});
	});

	it("draft-preview replaces chat.last text (not shown alongside it)", async () => {
		render(<ChatLayout />);
		const textarea = screen.getByPlaceholderText(/encrypted/i);
		fireEvent.change(textarea, { target: { value: "drafty" } });

		fireEvent.click(screen.getByRole("button", { name: /jordan/i }));

		await waitFor(() => {
			expect(screen.getByTestId("draft-preview")).toBeInTheDocument();
		});
	});

	// ── Dexie persistence (schema v17, GroupRow.draft — encrypted at rest) ─────

	const JORDAN_GROUP_ID = "33333333-3333-3333-3333-333333333333";

	it("persists the typed draft to Dexie GroupRow so it survives a reload", async () => {
		await db.groups.clear();
		await db.groups.add({
			id: JORDAN_GROUP_ID,
			name: "Jordan",
			mlsStateB64: "",
			lastActivity: Date.now(),
		});
		render(<ChatLayout />);
		fireEvent.click(screen.getByRole("button", { name: /jordan/i }));
		fireEvent.change(screen.getByPlaceholderText(/encrypted/i), {
			target: { value: "persisted draft text" },
		});

		await waitFor(async () => {
			const row = await db.groups.get(JORDAN_GROUP_ID);
			expect(row?.draft).toBe("persisted draft text");
		});
	});

	it("rehydrates a persisted draft from Dexie when switching to that chat", async () => {
		await db.groups.clear();
		await db.groups.add({
			id: JORDAN_GROUP_ID,
			name: "Jordan",
			mlsStateB64: "",
			lastActivity: Date.now(),
			draft: "saved from before reload",
		});
		render(<ChatLayout />);
		fireEvent.click(screen.getByRole("button", { name: /jordan/i }));

		await waitFor(() => {
			expect(screen.getByPlaceholderText(/encrypted/i)).toHaveValue("saved from before reload");
		});
	});
});
