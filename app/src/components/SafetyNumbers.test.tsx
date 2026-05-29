import { describe, expect, it, vi } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";
import { SafetyNumbers } from "./SafetyNumbers";

// 12 six-digit groups matching the WASM KAT output (prd.md §5.6).
const MOCK_SAFETY_NUMBER =
	"689053 337949 184798 288064 134849 362568 560227 765408 921198 315305 693006 807986";

describe("SafetyNumbers", () => {
	it("renders 12 digit groups from the safety number string", () => {
		render(
			<SafetyNumbers
				safetyNumber={MOCK_SAFETY_NUMBER}
				peerName="Alice"
				verified={false}
				onVerify={() => {}}
			/>,
		);
		const groups = MOCK_SAFETY_NUMBER.split(" ");
		for (const g of groups) {
			expect(screen.getByText(g)).toBeTruthy();
		}
	});

	it("shows unverified state and Compare button when not verified", () => {
		render(
			<SafetyNumbers
				safetyNumber={MOCK_SAFETY_NUMBER}
				peerName="Alice"
				verified={false}
				onVerify={() => {}}
			/>,
		);
		expect(screen.getByText("Not yet verified")).toBeTruthy();
		expect(screen.getByLabelText("Verify safety numbers")).toBeTruthy();
	});

	it("shows verified state with timestamp when verified", () => {
		const verifiedAt = Date.now() - 2 * 86_400_000;
		render(
			<SafetyNumbers
				safetyNumber={MOCK_SAFETY_NUMBER}
				peerName="Alice"
				verified={true}
				verifiedAt={verifiedAt}
				onVerify={() => {}}
			/>,
		);
		expect(screen.getByText("Identity verified")).toBeTruthy();
		// Timestamp shows relative date — multiple /verified/i matches are expected (title + date).
		expect(screen.getAllByText(/verified/i).length).toBeGreaterThanOrEqual(2);
	});

	it("shows confirm prompt on Compare click and calls onVerify on confirmation", () => {
		const onVerify = vi.fn();
		render(
			<SafetyNumbers
				safetyNumber={MOCK_SAFETY_NUMBER}
				peerName="Alice"
				verified={false}
				onVerify={onVerify}
			/>,
		);
		fireEvent.click(screen.getByLabelText("Verify safety numbers"));
		expect(screen.getByLabelText("Confirm match")).toBeTruthy();
		fireEvent.click(screen.getByLabelText("Confirm match"));
		expect(onVerify).toHaveBeenCalledTimes(1);
	});

	it("cancel hides the confirm prompt without calling onVerify", () => {
		const onVerify = vi.fn();
		render(
			<SafetyNumbers
				safetyNumber={MOCK_SAFETY_NUMBER}
				peerName="Alice"
				verified={false}
				onVerify={onVerify}
			/>,
		);
		fireEvent.click(screen.getByLabelText("Verify safety numbers"));
		fireEvent.click(screen.getByLabelText("Cancel verification"));
		expect(onVerify).not.toHaveBeenCalled();
		expect(screen.queryByLabelText("Confirm match")).toBeNull();
	});
});
