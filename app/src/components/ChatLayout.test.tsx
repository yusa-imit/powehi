import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { ChatLayout } from "./ChatLayout";

describe("ChatLayout", () => {
	it("renders the sidebar encryption banner", () => {
		render(<ChatLayout />);
		// The sidebar banner uses uppercase text
		expect(screen.getByText("END-TO-END ENCRYPTED")).toBeInTheDocument();
	});

	it("renders the sidebar with seed chat names", () => {
		render(<ChatLayout />);
		// Names appear in both sidebar and conversation header — at least one instance each
		expect(screen.getAllByText("Maya Akana").length).toBeGreaterThan(0);
		expect(screen.getAllByText("Jordan").length).toBeGreaterThan(0);
	});

	it("renders the E2EE notice in the message area", () => {
		render(<ChatLayout />);
		expect(screen.getByText(/not even powehi/i)).toBeInTheDocument();
	});

	it("composer placeholder mentions encryption", () => {
		render(<ChatLayout />);
		const textarea = screen.getByPlaceholderText(/encrypted/i);
		expect(textarea).toBeInTheDocument();
	});

	it("searching filters — Jordan disappears when searching 'maya'", () => {
		render(<ChatLayout />);
		const searchInput = screen.getByPlaceholderText(/search chats/i);
		fireEvent.change(searchInput, { target: { value: "maya" } });
		// Jordan should no longer appear in the sidebar; conversation panel might still show last-selected
		// Check the sidebar specifically — filtered chat list buttons
		const chatButtons = screen.queryAllByRole("button", { name: /jordan/i });
		// The sidebar ChatRow is a button; after filter, Jordan's button should be gone
		expect(chatButtons.length).toBe(0);
	});

	it("empty search query shows no-match message", () => {
		render(<ChatLayout />);
		const searchInput = screen.getByPlaceholderText(/search chats/i);
		fireEvent.change(searchInput, { target: { value: "zzz-nomatch" } });
		expect(screen.getByText(/no chats match/i)).toBeInTheDocument();
	});

	it("typing and sending a message appends it to the conversation", () => {
		render(<ChatLayout />);
		const textarea = screen.getByPlaceholderText(/encrypted/i);
		const msg = `Hello test message ${Date.now()}`;
		fireEvent.change(textarea, { target: { value: msg } });
		fireEvent.click(screen.getByRole("button", { name: /send message/i }));
		expect(screen.getAllByText(msg).length).toBeGreaterThan(0);
	});

	it("the info panel opens and shows safety numbers verify button", () => {
		render(<ChatLayout />);
		fireEvent.click(screen.getByRole("button", { name: /info/i }));
		// Maya is pre-verified so aria-label is "Re-verify safety numbers".
		// Jordan (unverified) would show "Verify safety numbers".
		expect(
			screen.getByRole("button", { name: /verify safety numbers/i }),
		).toBeInTheDocument();
	});

	it("selecting Jordan switches the active conversation header", () => {
		render(<ChatLayout />);
		const jordanButton = screen.getByRole("button", { name: /jordan/i });
		fireEvent.click(jordanButton);
		const header = screen.getByRole("banner");
		expect(header).toHaveTextContent(/jordan/i);
	});

	it("timer button cycles through disappearing TTL options", () => {
		render(<ChatLayout />);
		// Initially Off — button has label "Set disappearing timer"
		const timerBtn = screen.getByRole("button", { name: /disappearing timer/i });
		expect(timerBtn).toBeInTheDocument();
		// First click → 5m
		fireEvent.click(timerBtn);
		expect(screen.getByRole("button", { name: /disappearing: 5m/i })).toBeInTheDocument();
		// Second click → 1h
		fireEvent.click(screen.getByRole("button", { name: /disappearing: 5m/i }));
		expect(screen.getByRole("button", { name: /disappearing: 1h/i })).toBeInTheDocument();
	});

	it("message sent with active TTL shows disappearing badge", () => {
		render(<ChatLayout />);
		// Enable disappearing timer (click once → 5m)
		fireEvent.click(screen.getByRole("button", { name: /disappearing timer/i }));
		// Send a message
		const textarea = screen.getByPlaceholderText(/encrypted/i);
		fireEvent.change(textarea, { target: { value: "secret message" } });
		fireEvent.click(screen.getByRole("button", { name: /send message/i }));
		// The message was appended
		expect(screen.getAllByText("secret message").length).toBeGreaterThan(0);
		// The disappearing badge should appear ("Disappearing" text)
		expect(screen.getByText("Disappearing")).toBeInTheDocument();
	});
});
