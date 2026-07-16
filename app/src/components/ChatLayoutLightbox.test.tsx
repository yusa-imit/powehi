import { act, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
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

const MOCK_MEDIA = {
	blobId: "blob-lb-001",
	blobHash: [1, 2, 3, 4],
	mediaKey: Array.from(new Uint8Array(32).fill(7)),
	iv: Array.from(new Uint8Array(12).fill(8)),
};

const MOCK_MEDIA_2 = {
	blobId: "blob-lb-002",
	blobHash: [5, 6, 7, 8],
	mediaKey: Array.from(new Uint8Array(32).fill(9)),
	iv: Array.from(new Uint8Array(12).fill(10)),
};

describe("ChatLayout — image lightbox", () => {
	beforeEach(async () => {
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

	it("clicking a media image opens the lightbox", async () => {
		let capturedOnMessage: ((msg: IncomingMessage) => void) | undefined;
		vi.spyOn(UseMessagesModule, "useMessages").mockImplementation((_id, _gid, onMsg) => {
			capturedOnMessage = onMsg;
		});
		render(<ChatLayout />);

		await act(async () => {
			capturedOnMessage?.({
				id: "lb-img-uuid-0001",
				senderId: "peer-device-lb",
				groupId: "11111111-1111-1111-1111-111111111111",
				text: "",
				ciphertextB64: "Zg==",
				epochSeq: 1,
				media: MOCK_MEDIA,
			});
		});

		fireEvent.click(screen.getByTestId("media-open-lightbox"));

		expect(screen.getByTestId("lightbox")).toBeInTheDocument();
	});

	it("close button dismisses the lightbox", async () => {
		let capturedOnMessage: ((msg: IncomingMessage) => void) | undefined;
		vi.spyOn(UseMessagesModule, "useMessages").mockImplementation((_id, _gid, onMsg) => {
			capturedOnMessage = onMsg;
		});
		render(<ChatLayout />);

		await act(async () => {
			capturedOnMessage?.({
				id: "lb-close-uuid-0002",
				senderId: "peer-device-lb",
				groupId: "11111111-1111-1111-1111-111111111111",
				text: "",
				ciphertextB64: "Zg==",
				epochSeq: 1,
				media: MOCK_MEDIA,
			});
		});

		fireEvent.click(screen.getByTestId("media-open-lightbox"));
		expect(screen.getByTestId("lightbox")).toBeInTheDocument();

		fireEvent.click(screen.getByTestId("lightbox-close"));
		expect(screen.queryByTestId("lightbox")).not.toBeInTheDocument();
	});

	it("Escape key closes the lightbox", async () => {
		let capturedOnMessage: ((msg: IncomingMessage) => void) | undefined;
		vi.spyOn(UseMessagesModule, "useMessages").mockImplementation((_id, _gid, onMsg) => {
			capturedOnMessage = onMsg;
		});
		render(<ChatLayout />);

		await act(async () => {
			capturedOnMessage?.({
				id: "lb-esc-uuid-0003",
				senderId: "peer-device-lb",
				groupId: "11111111-1111-1111-1111-111111111111",
				text: "",
				ciphertextB64: "Zg==",
				epochSeq: 1,
				media: MOCK_MEDIA,
			});
		});

		fireEvent.click(screen.getByTestId("media-open-lightbox"));
		expect(screen.getByTestId("lightbox")).toBeInTheDocument();

		fireEvent.keyDown(window, { key: "Escape" });
		expect(screen.queryByTestId("lightbox")).not.toBeInTheDocument();
	});

	it("clicking the backdrop closes the lightbox", async () => {
		let capturedOnMessage: ((msg: IncomingMessage) => void) | undefined;
		vi.spyOn(UseMessagesModule, "useMessages").mockImplementation((_id, _gid, onMsg) => {
			capturedOnMessage = onMsg;
		});
		render(<ChatLayout />);

		await act(async () => {
			capturedOnMessage?.({
				id: "lb-backdrop-uuid-0004",
				senderId: "peer-device-lb",
				groupId: "11111111-1111-1111-1111-111111111111",
				text: "",
				ciphertextB64: "Zg==",
				epochSeq: 1,
				media: MOCK_MEDIA,
			});
		});

		fireEvent.click(screen.getByTestId("media-open-lightbox"));
		expect(screen.getByTestId("lightbox")).toBeInTheDocument();

		fireEvent.click(screen.getByTestId("lightbox"));
		expect(screen.queryByTestId("lightbox")).not.toBeInTheDocument();
	});

	it("shows prev/next buttons and counter when there are multiple media messages", async () => {
		let capturedOnMessage: ((msg: IncomingMessage) => void) | undefined;
		vi.spyOn(UseMessagesModule, "useMessages").mockImplementation((_id, _gid, onMsg) => {
			capturedOnMessage = onMsg;
		});
		render(<ChatLayout />);

		await act(async () => {
			capturedOnMessage?.({
				id: "lb-multi-uuid-0005a",
				senderId: "peer-device-lb",
				groupId: "11111111-1111-1111-1111-111111111111",
				text: "",
				ciphertextB64: "Zg==",
				epochSeq: 1,
				media: MOCK_MEDIA,
			});
		});

		await act(async () => {
			capturedOnMessage?.({
				id: "lb-multi-uuid-0005b",
				senderId: "peer-device-lb",
				groupId: "11111111-1111-1111-1111-111111111111",
				text: "",
				ciphertextB64: "Zg==",
				epochSeq: 2,
				media: MOCK_MEDIA_2,
			});
		});

		const openBtns = screen.getAllByTestId("media-open-lightbox");
		fireEvent.click(openBtns[0]);

		expect(screen.getByTestId("lightbox")).toBeInTheDocument();
		expect(screen.getByTestId("lightbox-counter")).toHaveTextContent("1 / 2");
		expect(screen.queryByTestId("lightbox-prev")).not.toBeInTheDocument();
		expect(screen.getByTestId("lightbox-next")).toBeInTheDocument();
	});

	it("arrow-right key navigates to next image", async () => {
		let capturedOnMessage: ((msg: IncomingMessage) => void) | undefined;
		vi.spyOn(UseMessagesModule, "useMessages").mockImplementation((_id, _gid, onMsg) => {
			capturedOnMessage = onMsg;
		});
		render(<ChatLayout />);

		await act(async () => {
			capturedOnMessage?.({
				id: "lb-nav-uuid-0006a",
				senderId: "peer-device-lb",
				groupId: "11111111-1111-1111-1111-111111111111",
				text: "",
				ciphertextB64: "Zg==",
				epochSeq: 1,
				media: MOCK_MEDIA,
			});
		});

		await act(async () => {
			capturedOnMessage?.({
				id: "lb-nav-uuid-0006b",
				senderId: "peer-device-lb",
				groupId: "11111111-1111-1111-1111-111111111111",
				text: "",
				ciphertextB64: "Zg==",
				epochSeq: 2,
				media: MOCK_MEDIA_2,
			});
		});

		const openBtns = screen.getAllByTestId("media-open-lightbox");
		fireEvent.click(openBtns[0]);
		expect(screen.getByTestId("lightbox-counter")).toHaveTextContent("1 / 2");

		fireEvent.keyDown(window, { key: "ArrowRight" });
		expect(screen.getByTestId("lightbox-counter")).toHaveTextContent("2 / 2");
		expect(screen.queryByTestId("lightbox-next")).not.toBeInTheDocument();
		expect(screen.getByTestId("lightbox-prev")).toBeInTheDocument();
	});

	it("arrow-left key navigates to previous image", async () => {
		let capturedOnMessage: ((msg: IncomingMessage) => void) | undefined;
		vi.spyOn(UseMessagesModule, "useMessages").mockImplementation((_id, _gid, onMsg) => {
			capturedOnMessage = onMsg;
		});
		render(<ChatLayout />);

		await act(async () => {
			capturedOnMessage?.({
				id: "lb-back-uuid-0007a",
				senderId: "peer-device-lb",
				groupId: "11111111-1111-1111-1111-111111111111",
				text: "",
				ciphertextB64: "Zg==",
				epochSeq: 1,
				media: MOCK_MEDIA,
			});
		});

		await act(async () => {
			capturedOnMessage?.({
				id: "lb-back-uuid-0007b",
				senderId: "peer-device-lb",
				groupId: "11111111-1111-1111-1111-111111111111",
				text: "",
				ciphertextB64: "Zg==",
				epochSeq: 2,
				media: MOCK_MEDIA_2,
			});
		});

		const openBtns = screen.getAllByTestId("media-open-lightbox");
		fireEvent.click(openBtns[1]);
		expect(screen.getByTestId("lightbox-counter")).toHaveTextContent("2 / 2");

		fireEvent.keyDown(window, { key: "ArrowLeft" });
		expect(screen.getByTestId("lightbox-counter")).toHaveTextContent("1 / 2");
	});

	it("chunked video attachments render inline (no lightbox trigger wrapper) — §9.4.2", async () => {
		let capturedOnMessage: ((msg: IncomingMessage) => void) | undefined;
		vi.spyOn(UseMessagesModule, "useMessages").mockImplementation((_id, _gid, onMsg) => {
			capturedOnMessage = onMsg;
		});
		render(<ChatLayout />);

		await act(async () => {
			capturedOnMessage?.({
				id: "lb-video-uuid-0008",
				senderId: "peer-device-lb",
				groupId: "11111111-1111-1111-1111-111111111111",
				text: "[video]",
				ciphertextB64: "Zg==",
				epochSeq: 1,
				media: { ...MOCK_MEDIA, chunked: true, totalSize: 33_554_432, chunkSize: 16 * 1024 * 1024 },
			});
		});

		// No lightbox-open button for video — the <video controls> element handles its
		// own playback/full-screen, and nesting it in a button would break the controls.
		expect(screen.queryByTestId("media-open-lightbox")).not.toBeInTheDocument();
		expect(screen.getByLabelText("Encrypted video attachment").tagName).toBe("VIDEO");
	});
});
