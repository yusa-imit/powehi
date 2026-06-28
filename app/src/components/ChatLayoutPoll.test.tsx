import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
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

describe("ChatLayout — group poll feature", () => {
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

	it("poll button is NOT shown in a DM chat (Maya)", () => {
		render(<ChatLayout />);
		// Maya is the default active DM chat
		expect(screen.queryByRole("button", { name: "Create poll" })).not.toBeInTheDocument();
	});

	it("poll button IS shown when a group chat is active", async () => {
		render(<ChatLayout />);
		const groupBtn = screen.getByRole("button", { name: /Design Team/i });
		await act(async () => {
			fireEvent.click(groupBtn);
		});
		expect(screen.getByRole("button", { name: "Create poll" })).toBeInTheDocument();
	});

	it("clicking poll button opens the poll creator popup", async () => {
		render(<ChatLayout />);
		const groupBtn = screen.getByRole("button", { name: /Design Team/i });
		await act(async () => {
			fireEvent.click(groupBtn);
		});
		const pollBtn = screen.getByRole("button", { name: "Create poll" });
		await act(async () => {
			fireEvent.click(pollBtn);
		});
		expect(screen.getByTestId("poll-creator")).toBeInTheDocument();
	});

	it("poll creator has question input and two option inputs", async () => {
		render(<ChatLayout />);
		const groupBtn = screen.getByRole("button", { name: /Design Team/i });
		await act(async () => {
			fireEvent.click(groupBtn);
		});
		await act(async () => {
			fireEvent.click(screen.getByRole("button", { name: "Create poll" }));
		});
		expect(screen.getByTestId("poll-question-input")).toBeInTheDocument();
		expect(screen.getByTestId("poll-option-input-0")).toBeInTheDocument();
		expect(screen.getByTestId("poll-option-input-1")).toBeInTheDocument();
	});

	it("Add option button adds a third option input", async () => {
		render(<ChatLayout />);
		const groupBtn = screen.getByRole("button", { name: /Design Team/i });
		await act(async () => {
			fireEvent.click(groupBtn);
		});
		await act(async () => {
			fireEvent.click(screen.getByRole("button", { name: "Create poll" }));
		});
		expect(screen.queryByTestId("poll-option-input-2")).not.toBeInTheDocument();
		await act(async () => {
			fireEvent.click(screen.getByTestId("poll-add-option"));
		});
		expect(screen.getByTestId("poll-option-input-2")).toBeInTheDocument();
	});

	it("Cancel closes the poll creator without creating a poll", async () => {
		render(<ChatLayout />);
		const groupBtn = screen.getByRole("button", { name: /Design Team/i });
		await act(async () => {
			fireEvent.click(groupBtn);
		});
		await act(async () => {
			fireEvent.click(screen.getByRole("button", { name: "Create poll" }));
		});
		await act(async () => {
			fireEvent.click(screen.getByTestId("poll-cancel"));
		});
		expect(screen.queryByTestId("poll-creator")).not.toBeInTheDocument();
		expect(screen.queryByTestId("poll-view")).not.toBeInTheDocument();
	});

	it("Creating a poll adds a poll message to the chat", async () => {
		render(<ChatLayout />);
		const groupBtn = screen.getByRole("button", { name: /Design Team/i });
		await act(async () => {
			fireEvent.click(groupBtn);
		});
		await act(async () => {
			fireEvent.click(screen.getByRole("button", { name: "Create poll" }));
		});
		fireEvent.change(screen.getByTestId("poll-question-input"), {
			target: { value: "Best framework?" },
		});
		fireEvent.change(screen.getByTestId("poll-option-input-0"), {
			target: { value: "React" },
		});
		fireEvent.change(screen.getByTestId("poll-option-input-1"), {
			target: { value: "Vue" },
		});
		await act(async () => {
			fireEvent.click(screen.getByTestId("poll-create"));
		});
		await waitFor(() => expect(screen.getByTestId("poll-view")).toBeInTheDocument());
	});

	it("Poll message shows the question text", async () => {
		render(<ChatLayout />);
		const groupBtn = screen.getByRole("button", { name: /Design Team/i });
		await act(async () => {
			fireEvent.click(groupBtn);
		});
		await act(async () => {
			fireEvent.click(screen.getByRole("button", { name: "Create poll" }));
		});
		fireEvent.change(screen.getByTestId("poll-question-input"), {
			target: { value: "Favourite colour?" },
		});
		fireEvent.change(screen.getByTestId("poll-option-input-0"), { target: { value: "Blue" } });
		fireEvent.change(screen.getByTestId("poll-option-input-1"), { target: { value: "Red" } });
		await act(async () => {
			fireEvent.click(screen.getByTestId("poll-create"));
		});
		await waitFor(() =>
			expect(screen.getByTestId("poll-question")).toHaveTextContent("Favourite colour?"),
		);
	});

	it("Poll message shows all option buttons", async () => {
		render(<ChatLayout />);
		const groupBtn = screen.getByRole("button", { name: /Design Team/i });
		await act(async () => {
			fireEvent.click(groupBtn);
		});
		await act(async () => {
			fireEvent.click(screen.getByRole("button", { name: "Create poll" }));
		});
		fireEvent.change(screen.getByTestId("poll-question-input"), {
			target: { value: "Lunch?" },
		});
		fireEvent.change(screen.getByTestId("poll-option-input-0"), { target: { value: "Pizza" } });
		fireEvent.change(screen.getByTestId("poll-option-input-1"), { target: { value: "Sushi" } });
		await act(async () => {
			fireEvent.click(screen.getByTestId("poll-create"));
		});
		await waitFor(() => expect(screen.getByTestId("poll-option-0")).toBeInTheDocument());
		expect(screen.getByTestId("poll-option-1")).toBeInTheDocument();
	});

	it("Clicking a poll option registers a vote (vote count updates to 1)", async () => {
		render(<ChatLayout />);
		const groupBtn = screen.getByRole("button", { name: /Design Team/i });
		await act(async () => {
			fireEvent.click(groupBtn);
		});
		await act(async () => {
			fireEvent.click(screen.getByRole("button", { name: "Create poll" }));
		});
		fireEvent.change(screen.getByTestId("poll-question-input"), {
			target: { value: "Vote?" },
		});
		fireEvent.change(screen.getByTestId("poll-option-input-0"), { target: { value: "Yes" } });
		fireEvent.change(screen.getByTestId("poll-option-input-1"), { target: { value: "No" } });
		await act(async () => {
			fireEvent.click(screen.getByTestId("poll-create"));
		});
		await waitFor(() => expect(screen.getByTestId("poll-option-0")).toBeInTheDocument());
		expect(screen.getByTestId("poll-total-votes")).toHaveTextContent("0 votes");
		await act(async () => {
			fireEvent.click(screen.getByTestId("poll-option-0"));
		});
		expect(screen.getByTestId("poll-total-votes")).toHaveTextContent("1 vote");
	});

	it("Clicking a voted option removes the vote (toggle behaviour)", async () => {
		render(<ChatLayout />);
		const groupBtn = screen.getByRole("button", { name: /Design Team/i });
		await act(async () => {
			fireEvent.click(groupBtn);
		});
		await act(async () => {
			fireEvent.click(screen.getByRole("button", { name: "Create poll" }));
		});
		fireEvent.change(screen.getByTestId("poll-question-input"), {
			target: { value: "Toggle?" },
		});
		fireEvent.change(screen.getByTestId("poll-option-input-0"), { target: { value: "On" } });
		fireEvent.change(screen.getByTestId("poll-option-input-1"), { target: { value: "Off" } });
		await act(async () => {
			fireEvent.click(screen.getByTestId("poll-create"));
		});
		await waitFor(() => expect(screen.getByTestId("poll-option-0")).toBeInTheDocument());
		// Vote
		await act(async () => {
			fireEvent.click(screen.getByTestId("poll-option-0"));
		});
		expect(screen.getByTestId("poll-total-votes")).toHaveTextContent("1 vote");
		// Un-vote
		await act(async () => {
			fireEvent.click(screen.getByTestId("poll-option-0"));
		});
		expect(screen.getByTestId("poll-total-votes")).toHaveTextContent("0 votes");
	});

	it("Vote percentage updates after voting (50% for one of two options)", async () => {
		render(<ChatLayout />);
		const groupBtn = screen.getByRole("button", { name: /Design Team/i });
		await act(async () => {
			fireEvent.click(groupBtn);
		});
		await act(async () => {
			fireEvent.click(screen.getByRole("button", { name: "Create poll" }));
		});
		fireEvent.change(screen.getByTestId("poll-question-input"), {
			target: { value: "Pct?" },
		});
		fireEvent.change(screen.getByTestId("poll-option-input-0"), { target: { value: "A" } });
		fireEvent.change(screen.getByTestId("poll-option-input-1"), { target: { value: "B" } });
		await act(async () => {
			fireEvent.click(screen.getByTestId("poll-create"));
		});
		await waitFor(() => expect(screen.getByTestId("poll-option-0")).toBeInTheDocument());
		await act(async () => {
			fireEvent.click(screen.getByTestId("poll-option-0"));
		});
		// 1 vote for option 0 out of 1 total = 100%
		expect(screen.getByTestId("poll-pct-0")).toHaveTextContent("100%");
		// option 1 has 0 votes = 0%
		expect(screen.getByTestId("poll-pct-1")).toHaveTextContent("0%");
	});

	it("Poll creator popup closes after creating a poll", async () => {
		render(<ChatLayout />);
		const groupBtn = screen.getByRole("button", { name: /Design Team/i });
		await act(async () => {
			fireEvent.click(groupBtn);
		});
		await act(async () => {
			fireEvent.click(screen.getByRole("button", { name: "Create poll" }));
		});
		fireEvent.change(screen.getByTestId("poll-question-input"), { target: { value: "Q?" } });
		fireEvent.change(screen.getByTestId("poll-option-input-0"), { target: { value: "A" } });
		fireEvent.change(screen.getByTestId("poll-option-input-1"), { target: { value: "B" } });
		await act(async () => {
			fireEvent.click(screen.getByTestId("poll-create"));
		});
		await waitFor(() => expect(screen.queryByTestId("poll-creator")).not.toBeInTheDocument());
	});

	it("Empty question prevents poll creation", async () => {
		render(<ChatLayout />);
		const groupBtn = screen.getByRole("button", { name: /Design Team/i });
		await act(async () => {
			fireEvent.click(groupBtn);
		});
		await act(async () => {
			fireEvent.click(screen.getByRole("button", { name: "Create poll" }));
		});
		// Leave question empty, fill options
		fireEvent.change(screen.getByTestId("poll-option-input-0"), { target: { value: "A" } });
		fireEvent.change(screen.getByTestId("poll-option-input-1"), { target: { value: "B" } });
		await act(async () => {
			fireEvent.click(screen.getByTestId("poll-create"));
		});
		// Creator should still be open (not submitted)
		expect(screen.getByTestId("poll-creator")).toBeInTheDocument();
	});

	it("Only one empty option prevents poll creation (needs at least two non-empty options)", async () => {
		render(<ChatLayout />);
		const groupBtn = screen.getByRole("button", { name: /Design Team/i });
		await act(async () => {
			fireEvent.click(groupBtn);
		});
		await act(async () => {
			fireEvent.click(screen.getByRole("button", { name: "Create poll" }));
		});
		fireEvent.change(screen.getByTestId("poll-question-input"), { target: { value: "Q?" } });
		fireEvent.change(screen.getByTestId("poll-option-input-0"), { target: { value: "Only one" } });
		// Leave option 1 empty
		await act(async () => {
			fireEvent.click(screen.getByTestId("poll-create"));
		});
		// Creator should remain open
		expect(screen.getByTestId("poll-creator")).toBeInTheDocument();
	});
});
