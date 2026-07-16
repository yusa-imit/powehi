import { fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import * as UseMediaReceiveModule from "../hooks/useMediaReceive";
import type { MediaPayload } from "../hooks/useMessages";
import * as UseThumbnailModule from "../hooks/useThumbnail";
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

	describe("video attachments (§9.4.2 chunked)", () => {
		it("renders a <video> with controls when media.chunked is true and loaded", () => {
			vi.spyOn(UseMediaReceiveModule, "useMediaReceive").mockReturnValue({
				objectUrl: OBJECT_URL,
				loading: false,
				error: false,
			});

			render(<MediaImage media={makeMedia({ chunked: true })} />);

			const video = screen.getByLabelText("Encrypted video attachment");
			expect(video.tagName).toBe("VIDEO");
			expect(video).toHaveAttribute("src", OBJECT_URL);
			expect(video).toHaveAttribute("controls");
			expect(screen.queryByRole("img")).not.toBeInTheDocument();
		});

		it("omits the controls attribute and shows a play badge when interactive=false", () => {
			vi.spyOn(UseMediaReceiveModule, "useMediaReceive").mockReturnValue({
				objectUrl: OBJECT_URL,
				loading: false,
				error: false,
			});

			render(<MediaImage media={makeMedia({ chunked: true })} interactive={false} />);

			const video = screen.getByLabelText("Encrypted video attachment");
			expect(video).not.toHaveAttribute("controls");
		});

		it("shows 'Video unavailable' (not 'Image unavailable') on error for chunked media", () => {
			vi.spyOn(UseMediaReceiveModule, "useMediaReceive").mockReturnValue({
				objectUrl: null,
				loading: false,
				error: true,
			});

			render(<MediaImage media={makeMedia({ chunked: true })} />);

			expect(screen.getByText("Video unavailable")).toBeInTheDocument();
			expect(screen.queryByText("Image unavailable")).not.toBeInTheDocument();
		});

		it("falls back to <video> when a non-chunked attachment fails to decode as an image", () => {
			vi.spyOn(UseMediaReceiveModule, "useMediaReceive").mockReturnValue({
				objectUrl: OBJECT_URL,
				loading: false,
				error: false,
			});

			render(<MediaImage media={makeMedia()} />);

			const img = screen.getByRole("img", { name: "Encrypted attachment" });
			fireEvent.error(img);

			const video = screen.getByLabelText("Encrypted video attachment");
			expect(video.tagName).toBe("VIDEO");
			expect(video).toHaveAttribute("src", OBJECT_URL);
			expect(screen.queryByRole("img")).not.toBeInTheDocument();
		});

		it("renders <video> immediately (no onError round-trip) for a small video with a real mimeType, not chunked (cycle-296 fix)", () => {
			vi.spyOn(UseMediaReceiveModule, "useMediaReceive").mockReturnValue({
				objectUrl: OBJECT_URL,
				loading: false,
				error: false,
			});

			render(<MediaImage media={makeMedia({ mimeType: "video/quicktime" })} />);

			const video = screen.getByLabelText("Encrypted video attachment");
			expect(video.tagName).toBe("VIDEO");
			expect(screen.queryByRole("img")).not.toBeInTheDocument();
		});

		it("shows 'Video unavailable' on error for a real-mimeType video that isn't chunked", () => {
			vi.spyOn(UseMediaReceiveModule, "useMediaReceive").mockReturnValue({
				objectUrl: null,
				loading: false,
				error: true,
			});

			render(<MediaImage media={makeMedia({ mimeType: "video/mp4" })} />);

			expect(screen.getByText("Video unavailable")).toBeInTheDocument();
			expect(screen.queryByText("Image unavailable")).not.toBeInTheDocument();
		});

		it("still renders <img> for a real image mimeType (mimeType doesn't force video)", () => {
			vi.spyOn(UseMediaReceiveModule, "useMediaReceive").mockReturnValue({
				objectUrl: OBJECT_URL,
				loading: false,
				error: false,
			});

			render(<MediaImage media={makeMedia({ mimeType: "image/heic" })} />);

			expect(screen.getByRole("img", { name: "Encrypted attachment" })).toBeInTheDocument();
			expect(screen.queryByLabelText("Encrypted video attachment")).not.toBeInTheDocument();
		});
	});
});
