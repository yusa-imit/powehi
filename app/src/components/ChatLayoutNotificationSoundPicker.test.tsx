import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { db } from "../db/schema";
import * as CryptoWorkerHook from "../hooks/useCryptoWorker";
import * as NotificationSound from "../lib/notificationSound";
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

describe("ChatLayout — per-chat notification sound picker", () => {
	beforeEach(async () => {
		await db.verifiedContacts.clear();
		vi.spyOn(CryptoWorkerHook, "useCryptoWorker").mockReturnValue(
			MOCK_WORKER as unknown as ReturnType<typeof CryptoWorkerHook.useCryptoWorker>,
		);
		vi.spyOn(NotificationSound, "playNotificationSound").mockImplementation(() => {});
	});

	afterEach(() => {
		vi.restoreAllMocks();
	});

	function openJordanNotifications() {
		render(<ChatLayout />);
		fireEvent.click(screen.getByRole("button", { name: /jordan/i }));
		fireEvent.click(screen.getByRole("button", { name: /info/i }));
	}

	it("shows the sound picker with all catalog options when sound is on", () => {
		openJordanNotifications();
		expect(screen.getByTestId("notification-sound-picker")).toBeInTheDocument();
		for (const id of NotificationSound.NOTIFICATION_SOUNDS) {
			expect(screen.getByTestId(`notification-sound-option-${id}`)).toBeInTheDocument();
		}
	});

	it("defaults to 'default' selected", () => {
		openJordanNotifications();
		expect(screen.getByTestId("notification-sound-option-default")).toHaveAttribute(
			"aria-pressed",
			"true",
		);
		expect(screen.getByTestId("notification-sound-option-chime")).toHaveAttribute(
			"aria-pressed",
			"false",
		);
	});

	it("hides the picker when the Sound toggle is off", async () => {
		openJordanNotifications();
		fireEvent.click(screen.getByRole("button", { name: /^sound/i }));
		await waitFor(() =>
			expect(screen.queryByTestId("notification-sound-picker")).not.toBeInTheDocument(),
		);
	});

	it("selecting an option marks it pressed and previews it via playNotificationSound", async () => {
		openJordanNotifications();
		fireEvent.click(screen.getByTestId("notification-sound-option-chime"));
		await waitFor(() =>
			expect(screen.getByTestId("notification-sound-option-chime")).toHaveAttribute(
				"aria-pressed",
				"true",
			),
		);
		expect(screen.getByTestId("notification-sound-option-default")).toHaveAttribute(
			"aria-pressed",
			"false",
		);
		expect(NotificationSound.playNotificationSound).toHaveBeenCalledWith("chime");
	});

	it("sound selection is chat-specific — picking 'pop' for Jordan leaves Maya on 'default'", async () => {
		openJordanNotifications();
		fireEvent.click(screen.getByTestId("notification-sound-option-pop"));
		await waitFor(() =>
			expect(screen.getByTestId("notification-sound-option-pop")).toHaveAttribute(
				"aria-pressed",
				"true",
			),
		);
		fireEvent.click(screen.getAllByRole("button", { name: /maya akana/i })[0]);
		await waitFor(() =>
			expect(screen.getByTestId("notification-sound-option-default")).toHaveAttribute(
				"aria-pressed",
				"true",
			),
		);
	});

	it("never passes message content or sender identity to playNotificationSound — only an opaque sound id", async () => {
		openJordanNotifications();
		fireEvent.click(screen.getByTestId("notification-sound-option-chime"));
		await waitFor(() => expect(NotificationSound.playNotificationSound).toHaveBeenCalled());
		for (const call of (NotificationSound.playNotificationSound as ReturnType<typeof vi.fn>).mock
			.calls) {
			expect(call).toHaveLength(1);
			expect(NotificationSound.NOTIFICATION_SOUNDS).toContain(call[0]);
		}
	});
});
