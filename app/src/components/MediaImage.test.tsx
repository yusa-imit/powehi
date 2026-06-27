import { render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import * as UseMediaReceiveModule from "../hooks/useMediaReceive";
import * as UseThumbnailModule from "../hooks/useThumbnail";
import type { MediaPayload } from "../hooks/useMessages";
import { MediaImage } from "./MediaImage";

const OBJECT_URL = "blob:mock-full-url";
const THUMB_URL = "blob:mock-thumb-url";

function makeMedia(overrides: Partial<MediaPayload> = {}): MediaPayload {
	return {
		blobId: "blob-uuid-0001",
		blobHash: [1, 2, 3, 4],
		mediaKey: Array.from(new Uint8Array(32).fill(5)),
		iv: Array.from(new Uint8Array(12).fill(6)),
		...overrides,
	};
}

beforeEach(() => {
	vi.spyOn(UseThumbnailModule, "useThumbnail").mockReturnValue({ objectUrl: null });
	vi.spyOn(UseMediaReceiveModule, "useMediaReceive").mockReturnValue({
		objectUrl: null,
		loading: true,
		error: false,
	});
});

afterEach(() => {
	vi.restoreAllMocks();
});

describe("MediaImage", () => {
	it("shows loading placeholder when loading with no thumbnail", () => {
		render(<MediaImage media={makeMedia()} />);
		expect(screen.getByLabelText("Loading image")).toBeInTheDocument();
		expect(screen.getByText("Loading…")).toBeInTheDocument();
	});

	it("shows blurred thumbnail placeholder when loading and thumbnail is available", () => {
		vi.spyOn(UseThumbnailModule, "useThumbnail").mockReturnValue({ objectUrl: THUMB_URL });

		render(<MediaImage media={makeMedia()} />);

		// aria-label="Loading image" takes precedence over alt for accessible name.
		const img = screen.getByRole("img", { name: "Loading image" });
		expect(img).toHaveAttribute("src", THUMB_URL);
		expect(img).toHaveStyle({ filter: "blur(4px)" });
	});

	it("shows full image when loaded", () => {
		vi.spyOn(UseMediaReceiveModule, "useMediaReceive").mockReturnValue({
			objectUrl: OBJECT_URL,
			loading: false,
			error: false,
		});

		render(<MediaImage media={makeMedia()} />);

		const img = screen.getByRole("img", { name: "Encrypted attachment" });
		expect(img).toHaveAttribute("src", OBJECT_URL);
	});

	it("shows 'Image unavailable' on error", () => {
		vi.spyOn(UseMediaReceiveModule, "useMediaReceive").mockReturnValue({
			objectUrl: null,
			loading: false,
			error: true,
		});

		render(<MediaImage media={makeMedia()} />);

		expect(screen.getByText("Image unavailable")).toBeInTheDocument();
		expect(screen.queryByRole("img")).not.toBeInTheDocument();
	});

	it("shows 'Image unavailable' when loaded but objectUrl is null", () => {
		vi.spyOn(UseMediaReceiveModule, "useMediaReceive").mockReturnValue({
			objectUrl: null,
			loading: false,
			error: false,
		});

		render(<MediaImage media={makeMedia()} />);

		expect(screen.getByText("Image unavailable")).toBeInTheDocument();
	});

	it("passes thumbnail prop to useThumbnail only while loading", () => {
		const thumbnail = { ct: [1], key: [2], iv: [3] };
		const thumbSpy = vi.spyOn(UseThumbnailModule, "useThumbnail").mockReturnValue({
			objectUrl: null,
		});
		// loading=true → thumbnail passed through
		vi.spyOn(UseMediaReceiveModule, "useMediaReceive").mockReturnValue({
			objectUrl: null,
			loading: true,
			error: false,
		});

		render(<MediaImage media={makeMedia({ thumbnail })} />);
		expect(thumbSpy).toHaveBeenCalledWith(thumbnail);
	});

	it("passes undefined to useThumbnail when not loading (thumbnail no longer needed)", () => {
		const thumbnail = { ct: [1], key: [2], iv: [3] };
		const thumbSpy = vi
			.spyOn(UseThumbnailModule, "useThumbnail")
			.mockReturnValue({ objectUrl: null });
		vi.spyOn(UseMediaReceiveModule, "useMediaReceive").mockReturnValue({
			objectUrl: OBJECT_URL,
			loading: false,
			error: false,
		});

		render(<MediaImage media={makeMedia({ thumbnail })} />);
		expect(thumbSpy).toHaveBeenCalledWith(undefined);
	});

	it("full image uses correct alt text for accessibility", () => {
		vi.spyOn(UseMediaReceiveModule, "useMediaReceive").mockReturnValue({
			objectUrl: OBJECT_URL,
			loading: false,
			error: false,
		});

		render(<MediaImage media={makeMedia()} />);
		expect(screen.getByAltText("Encrypted attachment")).toBeInTheDocument();
	});

	it("thumbnail img uses descriptive alt for screen-reader loading context", () => {
		vi.spyOn(UseThumbnailModule, "useThumbnail").mockReturnValue({ objectUrl: THUMB_URL });

		render(<MediaImage media={makeMedia()} />);
		expect(screen.getByAltText("Loading encrypted attachment")).toBeInTheDocument();
	});

	it("renders without crashing when media has no thumbnail", () => {
		render(<MediaImage media={makeMedia()} />);
		// Thumbnail hook still called (with undefined thumbnail).
		// No crash and loading placeholder visible.
		expect(screen.getByLabelText("Loading image")).toBeInTheDocument();
	});
});
