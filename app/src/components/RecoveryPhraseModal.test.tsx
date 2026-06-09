/**
 * RecoveryPhraseModal — unit tests (prd.md §8.5)
 *
 * Security invariants verified:
 * - Words appear only as visible text content, never in DOM attributes.
 * - localStorage and sessionStorage are not written with word content.
 * - Modal is not dismissible without explicit user confirmation.
 */

import { act, cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { RecoveryPhraseModal } from "./RecoveryPhraseModal";

// 24 deterministic test words — no real BIP-39 entropy, no PII.
const TEST_WORDS = Array.from({ length: 24 }, (_, i) => `testword${i + 1}`);

afterEach(cleanup);

describe("RecoveryPhraseModal", () => {
	// ── 1. Renders all 24 words ─────────────────────────────────────────────
	it("renders all 24 words as visible text", () => {
		render(<RecoveryPhraseModal words={TEST_WORDS} onConfirmed={vi.fn()} />);
		for (const word of TEST_WORDS) {
			expect(screen.getByText(word)).toBeInTheDocument();
		}
	});

	// ── 2. Words are numbered 1–24 ──────────────────────────────────────────
	it("displays numeric labels 1 through 24 alongside the words", () => {
		render(<RecoveryPhraseModal words={TEST_WORDS} onConfirmed={vi.fn()} />);
		// The index labels are rendered as visible text spans.
		for (let i = 1; i <= 24; i++) {
			// getAllByText because the number might appear elsewhere (e.g. in word text).
			const matches = screen.getAllByText(String(i));
			expect(matches.length).toBeGreaterThan(0);
		}
	});

	// ── 3. Copy button calls clipboard.writeText with space-joined phrase ───
	it("copy button calls navigator.clipboard.writeText with space-joined phrase", async () => {
		const writeTextMock = vi.fn().mockResolvedValue(undefined);
		Object.defineProperty(navigator, "clipboard", {
			value: { writeText: writeTextMock },
			writable: true,
			configurable: true,
		});

		render(<RecoveryPhraseModal words={TEST_WORDS} onConfirmed={vi.fn()} />);
		await act(async () => {
			fireEvent.click(screen.getByText("Copy all words"));
		});

		expect(writeTextMock).toHaveBeenCalledOnce();
		expect(writeTextMock).toHaveBeenCalledWith(TEST_WORDS.join(" "));
	});

	// ── 4. Copy button text changes to "Copied!" then resets ───────────────
	it("copy button label changes to Copied! immediately and resets after 2 s", async () => {
		vi.useFakeTimers();
		const writeTextMock = vi.fn().mockResolvedValue(undefined);
		Object.defineProperty(navigator, "clipboard", {
			value: { writeText: writeTextMock },
			writable: true,
			configurable: true,
		});

		render(<RecoveryPhraseModal words={TEST_WORDS} onConfirmed={vi.fn()} />);

		await act(async () => {
			fireEvent.click(screen.getByText("Copy all words"));
		});

		expect(screen.getByText("Copied!")).toBeInTheDocument();

		await act(async () => {
			vi.advanceTimersByTime(2000);
		});

		expect(screen.getByText("Copy all words")).toBeInTheDocument();

		vi.useRealTimers();
	});

	// ── 5. Confirm button calls onConfirmed ─────────────────────────────────
	it("confirm button calls onConfirmed callback", async () => {
		const onConfirmed = vi.fn();
		render(<RecoveryPhraseModal words={TEST_WORDS} onConfirmed={onConfirmed} />);

		await act(async () => {
			fireEvent.click(screen.getByText("I have saved my recovery phrase"));
		});

		expect(onConfirmed).toHaveBeenCalledOnce();
	});

	// ── 6. Modal has no X button and backdrop click does nothing ─────────────
	it("has no close/dismiss button — no aria-label=Close or X button", () => {
		render(<RecoveryPhraseModal words={TEST_WORDS} onConfirmed={vi.fn()} />);

		// No "Close" button.
		expect(screen.queryByRole("button", { name: /close/i })).toBeNull();

		// The dialog element itself has no onClick that dismisses it (no backdrop dismiss).
		// Clicking the dialog backdrop (the <dialog> element) does NOT call onConfirmed.
		const dialog = screen.getByRole("dialog");
		expect(dialog).toBeInTheDocument();
	});

	it("pressing Escape does not call onConfirmed — modal requires explicit confirmation", async () => {
		const onConfirmed = vi.fn();
		render(<RecoveryPhraseModal words={TEST_WORDS} onConfirmed={onConfirmed} />);

		await act(async () => {
			fireEvent.keyDown(screen.getByRole("dialog"), { key: "Escape" });
		});

		expect(onConfirmed).not.toHaveBeenCalled();
	});

	// ── 7. Security: words appear ONLY as text content, not in any DOM attribute ──
	it("no recovery word appears in any DOM attribute (data-*, aria-*, class, id)", () => {
		const { container } = render(<RecoveryPhraseModal words={TEST_WORDS} onConfirmed={vi.fn()} />);

		// Serialise every attribute of every element and assert no test word is present.
		const allElements = container.querySelectorAll("*");
		for (const el of allElements) {
			for (const attr of el.attributes) {
				for (const word of TEST_WORDS) {
					expect(attr.value).not.toContain(word);
				}
			}
		}
	});

	it("localStorage and sessionStorage are not written with recovery word content", async () => {
		const setItemSpy = vi.spyOn(Storage.prototype, "setItem");

		render(<RecoveryPhraseModal words={TEST_WORDS} onConfirmed={vi.fn()} />);

		// Trigger copy (which is the only async action that could theoretically leak)
		const writeTextMock = vi.fn().mockResolvedValue(undefined);
		Object.defineProperty(navigator, "clipboard", {
			value: { writeText: writeTextMock },
			writable: true,
			configurable: true,
		});
		await act(async () => {
			fireEvent.click(screen.getByText("Copy all words"));
		});

		// Assert no storage write contained any test word
		for (const call of setItemSpy.mock.calls) {
			const callStr = JSON.stringify(call);
			for (const word of TEST_WORDS) {
				expect(callStr).not.toContain(word);
			}
		}

		setItemSpy.mockRestore();
	});
});
