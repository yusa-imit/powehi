import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { db } from "../db/schema";
import * as CryptoWorkerHook from "../hooks/useCryptoWorker";
import * as UseMediaReceiveModule from "../hooks/useMediaReceive";
import * as UseMessagesModule from "../hooks/useMessages";
import type { IncomingMessage } from "../hooks/useMessages";
import * as UseThumbnailModule from "../hooks/useThumbnail";
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

function makeMedia(suffix: string) {
	return {
		blobId: `blob-mg-${suffix}`,
		blobHash: [1, 2, 3, 4],
		mediaKey: Array.from(new Uint8Array(32).fill(7)),
		iv: Array.from(new Uint8Array(12).fill(8)),
	};
}

function openInfoPanel() {
	fireEvent.click(screen.getByRole("button", { name: /info/i }));
}

describe("ChatLayout — media gallery in InfoPanel", () => {
	beforeEach(async () => {
		await db.verifiedContacts.clear();
		await db.messages.clear();
		vi.spyOn(CryptoWorkerHook, "useCryptoWorker").mockReturnValue(
			MOCK_WORKER as unknown as ReturnType<typeof CryptoWorkerHook.useCryptoWorker>,
		);
		vi.spyOn(UseMediaReceiveModule, "useMediaReceive").mockReturnValue({
			objectUrl: "blob:mock-image",
			loading: false,
			error: false,
		});
		vi.spyOn(UseThumbnailModule, "useThumbnail").mockReturnValue({ objectUrl: null });
	});

	afterEach(() => {
		vi.restoreAllMocks();
	});

	it("empty state shown when no media in active chat", async () => {
		vi.spyOn(UseMessagesModule, "useMessages").mockImplementation(() => {});
		render(<ChatLayout />);
		openInfoPanel();
		// InfoPanel kicks off an async mlsGroupMembers/getVerifiedContact promise chain on
		// mount (safety-number computation) that resolves after this synchronous test body
		// would otherwise finish; flush it inside act() so the resulting setState doesn't
		// land outside an act() boundary.
		await act(async () => {});
		expect(screen.getByTestId("media-gallery-empty")).toBeInTheDocument();
		expect(screen.getByTestId("media-gallery-empty")).toHaveTextContent("No shared media");
	});

	it("media gallery grid appears after a media message arrives", async () => {
		let capturedOnMessage: ((msg: IncomingMessage) => void) | undefined;
		vi.spyOn(UseMessagesModule, "useMessages").mockImplementation((_id, _gid, onMsg) => {
			capturedOnMessage = onMsg;
		});
		render(<ChatLayout />);

		await act(async () => {
			capturedOnMessage?.({
				id: "mg-uuid-0001",
				senderId: "peer-device-mg",
				groupId: "11111111-1111-1111-1111-111111111111",
				text: "",
				ciphertextB64: "Zg==",
				epochSeq: 1,
				media: makeMedia("001"),
			});
		});

		openInfoPanel();
		await waitFor(() => expect(screen.getByTestId("media-gallery")).toBeInTheDocument());
	});

	it("gallery shows one thumbnail for one media message", async () => {
		let capturedOnMessage: ((msg: IncomingMessage) => void) | undefined;
		vi.spyOn(UseMessagesModule, "useMessages").mockImplementation((_id, _gid, onMsg) => {
			capturedOnMessage = onMsg;
		});
		render(<ChatLayout />);

		await act(async () => {
			capturedOnMessage?.({
				id: "mg-uuid-0002",
				senderId: "peer-device-mg",
				groupId: "11111111-1111-1111-1111-111111111111",
				text: "",
				ciphertextB64: "Zg==",
				epochSeq: 1,
				media: makeMedia("002"),
			});
		});

		openInfoPanel();
		await waitFor(() => {
			expect(screen.getAllByTestId("media-gallery-thumb")).toHaveLength(1);
		});
	});

	it("gallery shows 6 thumbnails for 6 media messages", async () => {
		let capturedOnMessage: ((msg: IncomingMessage) => void) | undefined;
		vi.spyOn(UseMessagesModule, "useMessages").mockImplementation((_id, _gid, onMsg) => {
			capturedOnMessage = onMsg;
		});
		render(<ChatLayout />);

		for (let i = 0; i < 6; i++) {
			await act(async () => {
				capturedOnMessage?.({
					id: `mg-uuid-6th-${String(i).padStart(4, "0")}`,
					senderId: "peer-device-mg",
					groupId: "11111111-1111-1111-1111-111111111111",
					text: "",
					ciphertextB64: "Zg==",
					epochSeq: i + 1,
					media: makeMedia(`6th-${i}`),
				});
			});
		}

		openInfoPanel();
		await waitFor(() => {
			expect(screen.getAllByTestId("media-gallery-thumb")).toHaveLength(6);
		});
		expect(screen.queryByTestId("media-gallery-overflow")).not.toBeInTheDocument();
	});

	it("overflow indicator appears when more than 6 media messages exist", async () => {
		let capturedOnMessage: ((msg: IncomingMessage) => void) | undefined;
		vi.spyOn(UseMessagesModule, "useMessages").mockImplementation((_id, _gid, onMsg) => {
			capturedOnMessage = onMsg;
		});
		render(<ChatLayout />);

		for (let i = 0; i < 8; i++) {
			await act(async () => {
				capturedOnMessage?.({
					id: `mg-uuid-over-${String(i).padStart(4, "0")}`,
					senderId: "peer-device-mg",
					groupId: "11111111-1111-1111-1111-111111111111",
					text: "",
					ciphertextB64: "Zg==",
					epochSeq: i + 1,
					media: makeMedia(`over-${i}`),
				});
			});
		}

		openInfoPanel();
		await waitFor(() => expect(screen.getByTestId("media-gallery-overflow")).toBeInTheDocument());
		expect(screen.getByTestId("media-gallery-overflow")).toHaveTextContent("+3");
	});

	it("overflow shows only 6 thumbnails even with 8 media messages", async () => {
		let capturedOnMessage: ((msg: IncomingMessage) => void) | undefined;
		vi.spyOn(UseMessagesModule, "useMessages").mockImplementation((_id, _gid, onMsg) => {
			capturedOnMessage = onMsg;
		});
		render(<ChatLayout />);

		for (let i = 0; i < 8; i++) {
			await act(async () => {
				capturedOnMessage?.({
					id: `mg-uuid-cap-${String(i).padStart(4, "0")}`,
					senderId: "peer-device-mg",
					groupId: "11111111-1111-1111-1111-111111111111",
					text: "",
					ciphertextB64: "Zg==",
					epochSeq: i + 1,
					media: makeMedia(`cap-${i}`),
				});
			});
		}

		openInfoPanel();
		await waitFor(() => {
			expect(screen.getAllByTestId("media-gallery-thumb")).toHaveLength(6);
		});
	});

	it("clicking a gallery thumbnail opens the lightbox", async () => {
		let capturedOnMessage: ((msg: IncomingMessage) => void) | undefined;
		vi.spyOn(UseMessagesModule, "useMessages").mockImplementation((_id, _gid, onMsg) => {
			capturedOnMessage = onMsg;
		});
		render(<ChatLayout />);

		await act(async () => {
			capturedOnMessage?.({
				id: "mg-uuid-click-0001",
				senderId: "peer-device-mg",
				groupId: "11111111-1111-1111-1111-111111111111",
				text: "",
				ciphertextB64: "Zg==",
				epochSeq: 1,
				media: makeMedia("click-001"),
			});
		});

		openInfoPanel();
		await waitFor(() => expect(screen.getByTestId("media-gallery-thumb")).toBeInTheDocument());
		fireEvent.click(screen.getByTestId("media-gallery-thumb"));
		expect(screen.getByTestId("lightbox")).toBeInTheDocument();
	});

	it("gallery thumbnail has aria-label 'View image'", async () => {
		let capturedOnMessage: ((msg: IncomingMessage) => void) | undefined;
		vi.spyOn(UseMessagesModule, "useMessages").mockImplementation((_id, _gid, onMsg) => {
			capturedOnMessage = onMsg;
		});
		render(<ChatLayout />);

		await act(async () => {
			capturedOnMessage?.({
				id: "mg-uuid-aria-0001",
				senderId: "peer-device-mg",
				groupId: "11111111-1111-1111-1111-111111111111",
				text: "",
				ciphertextB64: "Zg==",
				epochSeq: 1,
				media: makeMedia("aria-001"),
			});
		});

		openInfoPanel();
		await waitFor(() => expect(screen.getByTestId("media-gallery-thumb")).toBeInTheDocument());
		expect(screen.getByTestId("media-gallery-thumb")).toHaveAttribute("aria-label", "View image");
	});

	it("overflow thumbnail aria-label mentions total count", async () => {
		let capturedOnMessage: ((msg: IncomingMessage) => void) | undefined;
		vi.spyOn(UseMessagesModule, "useMessages").mockImplementation((_id, _gid, onMsg) => {
			capturedOnMessage = onMsg;
		});
		render(<ChatLayout />);

		for (let i = 0; i < 7; i++) {
			await act(async () => {
				capturedOnMessage?.({
					id: `mg-uuid-aria-over-${String(i).padStart(4, "0")}`,
					senderId: "peer-device-mg",
					groupId: "11111111-1111-1111-1111-111111111111",
					text: "",
					ciphertextB64: "Zg==",
					epochSeq: i + 1,
					media: makeMedia(`aria-over-${i}`),
				});
			});
		}

		openInfoPanel();
		await waitFor(() => expect(screen.getByTestId("media-gallery-overflow")).toBeInTheDocument());
		const thumbs = screen.getAllByTestId("media-gallery-thumb");
		const lastThumb = thumbs[thumbs.length - 1];
		expect(lastThumb).toHaveAttribute("aria-label", "View all 7 images");
	});

	it("empty state gone once media arrives", async () => {
		let capturedOnMessage: ((msg: IncomingMessage) => void) | undefined;
		vi.spyOn(UseMessagesModule, "useMessages").mockImplementation((_id, _gid, onMsg) => {
			capturedOnMessage = onMsg;
		});
		render(<ChatLayout />);
		openInfoPanel();
		expect(screen.getByTestId("media-gallery-empty")).toBeInTheDocument();

		await act(async () => {
			capturedOnMessage?.({
				id: "mg-uuid-toggle-0001",
				senderId: "peer-device-mg",
				groupId: "11111111-1111-1111-1111-111111111111",
				text: "",
				ciphertextB64: "Zg==",
				epochSeq: 1,
				media: makeMedia("toggle-001"),
			});
		});

		await waitFor(() =>
			expect(screen.queryByTestId("media-gallery-empty")).not.toBeInTheDocument(),
		);
		expect(screen.getByTestId("media-gallery")).toBeInTheDocument();
	});
});
