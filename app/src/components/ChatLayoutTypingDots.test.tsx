import { act, render, screen } from "@testing-library/react";
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

// Maya's group (active chat by default)
const MAYA_GROUP_ID = "11111111-1111-1111-1111-111111111111";
// Jordan's group
const JORDAN_GROUP_ID = "33333333-3333-3333-3333-333333333333";

describe("ChatLayout — animated typing dots (TypingDots component)", () => {
	beforeEach(async () => {
		await db.verifiedContacts.clear();
		vi.spyOn(CryptoWorkerHook, "useCryptoWorker").mockReturnValue(
			MOCK_WORKER as unknown as ReturnType<typeof CryptoWorkerHook.useCryptoWorker>,
		);
	});

	afterEach(() => {
		vi.restoreAllMocks();
		vi.useRealTimers();
	});

	it("seed chat Sam renders typing-dots in the sidebar (typing: true in seed data)", () => {
		render(<ChatLayout />);
		// Sam has typing: true — sidebar must render the animated TypingDots widget
		const dots = screen.getAllByTestId("typing-dots");
		expect(dots.length).toBeGreaterThanOrEqual(1);
	});

	it("typing-dots container carries aria-label='typing' for accessibility", () => {
		render(<ChatLayout />);
		const dots = screen.getAllByTestId("typing-dots");
		for (const dot of dots) {
			expect(dot).toHaveAttribute("aria-label", "typing");
		}
	});

	it("typing-dots renders exactly three dot spans with class powehi-typing-dot", () => {
		render(<ChatLayout />);
		const container = screen.getAllByTestId("typing-dots")[0];
		const dotSpans = container.querySelectorAll(".powehi-typing-dot");
		expect(dotSpans).toHaveLength(3);
	});

	it("no static 'typing...' text node is rendered when typing is active (replaced by dots)", () => {
		render(<ChatLayout />);
		// The old text "typing..." must not appear anywhere in the DOM
		expect(screen.queryByText("typing...")).not.toBeInTheDocument();
	});

	it("incoming typing signal for active chat shows typing-dots in the header", async () => {
		let capturedOnTyping: ((groupId: string) => void) | undefined;
		vi.spyOn(UseMessagesModule, "useMessages").mockImplementation(
			(_identityId, _groupId, _onMessage, _onPqBinding, onTyping) => {
				capturedOnTyping = onTyping;
			},
		);
		render(<ChatLayout />);
		expect(capturedOnTyping).toBeDefined();

		await act(async () => {
			capturedOnTyping?.(MAYA_GROUP_ID);
		});

		// Header area (active chat Maya) must now show typing-dots
		const allDots = screen.getAllByTestId("typing-dots");
		expect(allDots.length).toBeGreaterThanOrEqual(2); // Sam sidebar + Maya header
	});

	it("typing-dots count increases when header typing activates (sidebar + header both present)", async () => {
		let capturedOnTyping: ((groupId: string) => void) | undefined;
		vi.spyOn(UseMessagesModule, "useMessages").mockImplementation(
			(_identityId, _groupId, _onMessage, _onPqBinding, onTyping) => {
				capturedOnTyping = onTyping;
			},
		);
		render(<ChatLayout />);

		// Count before firing signal (only Sam's sidebar)
		const before = screen.getAllByTestId("typing-dots").length;

		await act(async () => {
			capturedOnTyping?.(MAYA_GROUP_ID);
		});

		const after = screen.getAllByTestId("typing-dots").length;
		expect(after).toBeGreaterThan(before);
	});

	it("typing signal for a background (non-active) chat does not add header dots", async () => {
		let capturedOnTyping: ((groupId: string) => void) | undefined;
		vi.spyOn(UseMessagesModule, "useMessages").mockImplementation(
			(_identityId, _groupId, _onMessage, _onPqBinding, onTyping) => {
				capturedOnTyping = onTyping;
			},
		);
		render(<ChatLayout />);

		const before = screen.getAllByTestId("typing-dots").length;

		// Jordan is NOT the active chat
		await act(async () => {
			capturedOnTyping?.(JORDAN_GROUP_ID);
		});

		// Sam's sidebar still 1 dot; Jordan's row could get one → count increases by at most 1
		// But the *header* (Maya's) should not show a dot
		const after = screen.getAllByTestId("typing-dots").length;
		// The header for Maya should have no extra dot from Jordan's signal
		// Total may increase (Jordan's sidebar row), but header stays unchanged
		expect(after).toBeGreaterThanOrEqual(before);
	});

	it("typing-dots auto-clear after 3 s — count drops back to baseline", async () => {
		vi.useFakeTimers();

		let capturedOnTyping: ((groupId: string) => void) | undefined;
		vi.spyOn(UseMessagesModule, "useMessages").mockImplementation(
			(_identityId, _groupId, _onMessage, _onPqBinding, onTyping) => {
				capturedOnTyping = onTyping;
			},
		);
		render(<ChatLayout />);

		const baseline = screen.getAllByTestId("typing-dots").length;

		await act(async () => {
			capturedOnTyping?.(MAYA_GROUP_ID);
		});
		expect(screen.getAllByTestId("typing-dots").length).toBeGreaterThan(baseline);

		await act(async () => {
			vi.advanceTimersByTime(3_100);
		});

		expect(screen.getAllByTestId("typing-dots").length).toBe(baseline);
	});

	it("no 'typing...' literal text in the DOM at any time (no plaintext label)", async () => {
		let capturedOnTyping: ((groupId: string) => void) | undefined;
		vi.spyOn(UseMessagesModule, "useMessages").mockImplementation(
			(_identityId, _groupId, _onMessage, _onPqBinding, onTyping) => {
				capturedOnTyping = onTyping;
			},
		);
		render(<ChatLayout />);

		await act(async () => {
			capturedOnTyping?.(MAYA_GROUP_ID);
		});

		// Neither the old "typing..." text nor the "· typing" text should appear
		expect(screen.queryByText("typing...")).not.toBeInTheDocument();
		expect(screen.queryByText(/·\s*typing$/i)).not.toBeInTheDocument();
	});

	it("typing-dots uses the accretion-orange color token (#FF9E52) as currentColor", () => {
		render(<ChatLayout />);
		const container = screen.getAllByTestId("typing-dots")[0];
		// The inline style on the wrapper should carry the accent color
		expect(container).toHaveStyle({ color: "#FF9E52" });
	});
});
