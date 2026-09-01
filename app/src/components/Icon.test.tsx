import { render } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { Icon, type IconName } from "./Icon";

describe("Icon", () => {
	it("renders an svg with the shared 24x24 viewBox for a known name", () => {
		const { container } = render(<Icon name="lock" />);
		const svg = container.querySelector("svg");
		expect(svg).not.toBeNull();
		expect(svg).toHaveAttribute("viewBox", "0 0 24 24");
		expect(svg).toHaveAttribute("stroke", "currentColor");
	});

	it("returns null for an unrecognized icon name", () => {
		const { container } = render(<Icon name={"not-a-real-icon" as IconName} />);
		expect(container.firstChild).toBeNull();
	});

	it("defaults size to 20 and applies a custom size", () => {
		const { container: def } = render(<Icon name="check" />);
		expect(def.querySelector("svg")).toHaveAttribute("width", "20");
		expect(def.querySelector("svg")).toHaveAttribute("height", "20");

		const { container: custom } = render(<Icon name="check" size={32} />);
		expect(custom.querySelector("svg")).toHaveAttribute("width", "32");
		expect(custom.querySelector("svg")).toHaveAttribute("height", "32");
	});

	it("uses a custom color as the stroke instead of currentColor", () => {
		const { container } = render(<Icon name="star" color="var(--photon-300)" />);
		expect(container.querySelector("svg")).toHaveAttribute("stroke", "var(--photon-300)");
	});

	it("passes through className and style props", () => {
		const { container } = render(
			<Icon name="settings" className="my-icon" style={{ opacity: 0.5 }} />,
		);
		const svg = container.querySelector("svg");
		expect(svg).toHaveClass("my-icon");
		expect(svg).toHaveStyle({ opacity: "0.5" });
	});

	it("renders the known SVG path content for a given name", () => {
		const { container } = render(<Icon name="check" />);
		expect(container.querySelector("svg polyline")).not.toBeNull();
	});
});
