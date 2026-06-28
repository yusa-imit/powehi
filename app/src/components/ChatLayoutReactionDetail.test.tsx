/**
 * Reaction detail tooltip — shows who reacted when hovering a reaction chip.
 * Verifies: tooltip renders with correct handles, handles for unknown ID, chip independence.
 */
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import { ChatLayout } from "./ChatLayout";

afterEach(cleanup);

describe("reaction detail tooltip", () => {
	it("shows handles of reactors on reaction chip hover", async () => {
		render(<ChatLayout />);

		// Activate the Design Team group chat (has reactions in seed data)
		const groupRow = await screen.findByText("Design Team");
		fireEvent.click(groupRow);

		// The first message has reactions: { "👍": ["dev-a","dev-b","dev-c"], "❤️": ["dev-d"] }
		const wrapper = await screen.findByTestId("reaction-chip-wrapper-👍");
		fireEvent.mouseEnter(wrapper);

		const tooltip = await screen.findByTestId("reaction-tooltip-👍");
		expect(tooltip).toBeTruthy();

		const text = tooltip.textContent ?? "";
		expect(text).toContain("finn");
		expect(text).toContain("maya");
		expect(text).toContain("jordan");
	});

	it("hides tooltip after mouse leaves chip wrapper", async () => {
		render(<ChatLayout />);

		const groupRow = await screen.findByText("Design Team");
		fireEvent.click(groupRow);

		const wrapper = await screen.findByTestId("reaction-chip-wrapper-👍");
		fireEvent.mouseEnter(wrapper);
		expect(await screen.findByTestId("reaction-tooltip-👍")).toBeTruthy();

		fireEvent.mouseLeave(wrapper);
		expect(screen.queryByTestId("reaction-tooltip-👍")).toBeNull();
	});

	it("shows tooltip for ❤️ chip with correct handle", async () => {
		render(<ChatLayout />);

		const groupRow = await screen.findByText("Design Team");
		fireEvent.click(groupRow);

		// ❤️ chip — only dev-d (noa)
		const heartWrapper = await screen.findByTestId("reaction-chip-wrapper-❤️");
		fireEvent.mouseEnter(heartWrapper);

		const tooltip = await screen.findByTestId("reaction-tooltip-❤️");
		expect(tooltip.textContent).toContain("noa");
		expect(tooltip.textContent).not.toContain("finn");
	});

	it("hovering one chip does not show another emoji tooltip", async () => {
		render(<ChatLayout />);

		const groupRow = await screen.findByText("Design Team");
		fireEvent.click(groupRow);

		const thumbsWrapper = await screen.findByTestId("reaction-chip-wrapper-👍");
		fireEvent.mouseEnter(thumbsWrapper);

		expect(screen.queryByTestId("reaction-tooltip-👍")).not.toBeNull();
		expect(screen.queryByTestId("reaction-tooltip-❤️")).toBeNull();
	});
});
