/**
 * ChatLayout — media message Dexie persistence + rehydration (this cycle's fix).
 *
 * Prior to this fix, media send/receive never called any persist* hook at all —
 * every photo/video/voice note vanished from chat history on reload, a strictly
 * worse gap than pollJson/replyToJson/scheduledFor had before their own schema
 * versions (those at least reached React state consistently; media never even
 * reached Dexie). See db/schema.ts's MessageRow.mediaJson doc comment for the
 * incoming/outgoing key-availability asymmetry this suite also covers.
 */
import { render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { db } from "../db/schema";
import * as CryptoWorkerHook from "../hooks/useCryptoWorker";
import * as UseMediaReceiveModule from "../hooks/useMediaReceive";
import * as UseMessagesModule from "../hooks/useMessages";
import * as UseThumbnailModule from "../hooks/useThumbnail";
import { useAuthStore } from "../store/auth";
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

// Maya's DM — the default active chat in every ChatLayout test (no click needed),
// same group id ChatLayoutMediaGallery.test.tsx uses.
const MAYA_GROUP_ID = "11111111-1111-1111-1111-111111111111";

const makeMedia = (suffix: string) => ({
	blobId: `blob-persist-${suffix}`,
	blobHash: [1, 2, 3, 4],
	mediaKey: Array.from(new Uint8Array(32).fill(7)),
	iv: Array.from(new Uint8Array(12).fill(8)),
});

describe("ChatLayout — media message Dexie persistence + rehydration", () => {
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
		vi.spyOn(UseMessagesModule, "useMessages").mockImplementation(() => {});
	});

	afterEach(() => {
		vi.restoreAllMocks();
	});

	it("rehydrates a persisted incoming media message from Dexie and redisplays it via MediaImage", async () => {
		// Simulate a media message already persisted from a prior session (e.g. by
		// persistIncoming) by seeding db.messages directly — same technique
		// ChatLayoutPoll.test.tsx's rehydration test uses.
		const media = makeMedia("rehydrate-1");
		await db.messages.put({
			id: "media-seeded-1",
			groupId: MAYA_GROUP_ID,
			ciphertextB64: "c2Vlbg==",
			senderDeviceId: "peer-device-x",
			epochSeq: 1,
			receivedAt: 1000,
			plaintextB64: btoa("[image]"),
			mediaJson: JSON.stringify(media),
		});

		render(<ChatLayout />);

		// The message survives the "reload" and MediaImage actually renders the
		// attachment (not just a text placeholder) — proving `media` was reconstructed
		// from mediaJson and threaded through to the live ChatMessage.
		await waitFor(() => {
			const img = screen.getByAltText("Encrypted attachment") as HTMLImageElement;
			expect(img.src).toContain("blob:mock-image");
		});
		// Mutation-tested: without this assertion, substituting an entirely wrong
		// media object (e.g. wrong blobId/mediaKey/iv) into the rehydration path
		// still passes the two checks above, since useMediaReceive is stubbed and
		// its call args were never inspected. This is the one assertion that proves
		// the actual seeded blobId/blobHash/mediaKey/iv survived the round trip —
		// the entire point of this cycle's fix.
		expect(UseMediaReceiveModule.useMediaReceive).toHaveBeenCalledWith(
			expect.objectContaining(media),
		);
	});

	it("does not crash and drops just the attachment when mediaJson fails to parse (corrupt/malformed)", async () => {
		await db.messages.put({
			id: "media-bad-json-1",
			groupId: MAYA_GROUP_ID,
			ciphertextB64: "c2Vlbg==",
			senderDeviceId: "peer-device-x",
			epochSeq: 1,
			receivedAt: 1000,
			plaintextB64: btoa("[image]"),
			mediaJson: "{not valid json",
		});

		render(<ChatLayout />);

		// The message row itself still rehydrates (falls back to its plaintext
		// placeholder) — the whole app must not blank on a corrupt mediaJson value,
		// same defensive contract pollJson/replyToJson already have.
		await waitFor(() => {
			expect(screen.getByText("[image]")).toBeInTheDocument();
		});
		expect(screen.queryByAltText("Encrypted attachment")).not.toBeInTheDocument();
	});

	it("drops the attachment when mediaJson is missing required fields (shape-invalid, not just syntax-invalid)", async () => {
		await db.messages.put({
			id: "media-bad-shape-1",
			groupId: MAYA_GROUP_ID,
			ciphertextB64: "c2Vlbg==",
			senderDeviceId: "peer-device-x",
			epochSeq: 1,
			receivedAt: 1000,
			plaintextB64: btoa("[image]"),
			// Valid JSON, but missing mediaKey/iv — MediaImage's downstream hooks index
			// into these arrays directly and must never receive a malformed payload.
			mediaJson: JSON.stringify({ blobId: "blob-x" }),
		});

		render(<ChatLayout />);

		await waitFor(() => {
			expect(screen.getByText("[image]")).toBeInTheDocument();
		});
		expect(screen.queryByAltText("Encrypted attachment")).not.toBeInTheDocument();
	});

	it("rehydrates a pre-ADR-0004 outgoing row (no mediaJson) as its placeholder text — back-compat, no MediaImage", async () => {
		// No mediaJson on this row — this is what persistOutgoing wrote for a media send
		// before ADR-0004 added the one-shot key export, and what it still writes when
		// the export is skipped or fails. There is no backfill for these rows: the key
		// was never exported and is gone from every local store, so the placeholder is
		// the correct (and only possible) rendering. See MessageRow.mediaJson, schema.ts.
		await db.messages.put({
			id: "media-outgoing-1",
			groupId: MAYA_GROUP_ID,
			ciphertextB64: "c2Vlbg==",
			senderDeviceId: "my-own-device",
			epochSeq: 2,
			receivedAt: 2000,
			plaintextB64: btoa("Image attachment"),
		});

		render(<ChatLayout />);

		await waitFor(() => {
			expect(screen.getByText("Image attachment")).toBeInTheDocument();
		});
		expect(screen.queryByAltText("Encrypted attachment")).not.toBeInTheDocument();
	});

	// ADR-0004: the asymmetry this file previously documented is now closed — an
	// outgoing row carries a real mediaKey and must rehydrate into a real attachment,
	// exactly like the incoming case at the top of this file. This is the end-to-end
	// proof of the whole cycle: without the WASM export, without the mediaTransfer
	// wiring, or without persistOutgoing threading `media` through, this test fails.
	it("rehydrates an outgoing (sender's own) media message WITH mediaJson into a real MediaImage (ADR-0004)", async () => {
		// Set on the store rather than reset in afterEach: mutating a zustand store
		// after teardown re-renders an unmounted tree (useSyncExternalStore throws).
		// Safe without a reset — this is the last test in the file and vitest isolates
		// per-file module state.
		// ChatLayout rehydrates from === "me" by comparing row.senderDeviceId against
		// the auth store's deviceId, so set it — otherwise this row would rehydrate as
		// an INCOMING message and the test would not actually cover the sender case.
		useAuthStore.setState({ deviceId: "my-own-device" });
		const media = makeMedia("outgoing-adr4");
		await db.messages.put({
			id: "media-outgoing-2",
			groupId: MAYA_GROUP_ID,
			ciphertextB64: "c2Vlbg==",
			// Same device the auth store reports, so this rehydrates as from === "me".
			senderDeviceId: "my-own-device",
			epochSeq: 3,
			receivedAt: 3000,
			plaintextB64: btoa("Image attachment"),
			mediaJson: JSON.stringify(media),
		});

		render(<ChatLayout />);

		await waitFor(() => {
			const img = screen.getByAltText("Encrypted attachment") as HTMLImageElement;
			expect(img.src).toContain("blob:mock-image");
		});
		// The sender's own blobId/blobHash/mediaKey/iv survived the Dexie round trip —
		// the attachment is genuinely re-decryptable, not just a rendered placeholder.
		expect(UseMediaReceiveModule.useMediaReceive).toHaveBeenCalledWith(
			expect.objectContaining(media),
		);
		// Guards the premise: this really did rehydrate as the sender's own message.
		const row = await db.messages.get("media-outgoing-2");
		expect(row?.senderDeviceId).toBe(useAuthStore.getState().deviceId);
	});
});
