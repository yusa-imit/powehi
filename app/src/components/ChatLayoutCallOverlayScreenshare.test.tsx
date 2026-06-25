import { act, cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import * as CryptoWorkerHook from "../hooks/useCryptoWorker";
import * as UseMessagesModule from "../hooks/useMessages";
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

async function renderWithActiveCall(type: "voice" | "video" = "voice") {
	vi.useFakeTimers();
	render(<ChatLayout />);
	const label = type === "video" ? "Video call" : "Voice call";
	fireEvent.click(screen.getByLabelText(label));
	// Advance 2500ms so outgoing → active
	await act(async () => {
		vi.advanceTimersByTime(2500);
	});
}

describe("ChatLayout — call overlay screenshare button", () => {
	beforeEach(() => {
		vi.spyOn(CryptoWorkerHook, "useCryptoWorker").mockReturnValue(
			MOCK_WORKER as unknown as ReturnType<typeof CryptoWorkerHook.useCryptoWorker>,
		);
		useAuthStore.setState({
			sessionToken: "tok-ss-test",
			identityId: "33333333-3333-3333-3333-333333333333",
			phase: "app",
			deviceId: "dev-ss-test",
		});
		vi.spyOn(UseMessagesModule, "useMessages").mockImplementation(() => {});
	});

	afterEach(() => {
		cleanup();
		vi.restoreAllMocks();
		vi.useRealTimers();
		useAuthStore.setState({ sessionToken: null, identityId: null, phase: "login", deviceId: null });
	});

	it("screenshare button present in active voice call", async () => {
		await renderWithActiveCall("voice");
		expect(screen.getByTestId("call-btn-screenshare")).toBeTruthy();
	});

	it("screenshare button present in active video call", async () => {
		await renderWithActiveCall("video");
		expect(screen.getByTestId("call-btn-screenshare")).toBeTruthy();
	});

	it("screenshare button initially shows 'Share screen' aria-label", async () => {
		await renderWithActiveCall("voice");
		expect(screen.getByLabelText("Share screen")).toBeTruthy();
	});

	it("screenshare button toggle changes aria-label to 'Stop sharing screen'", async () => {
		await renderWithActiveCall("voice");
		const btn = screen.getByTestId("call-btn-screenshare");
		await act(async () => {
			fireEvent.click(btn);
		});
		expect(screen.getByLabelText("Stop sharing screen")).toBeTruthy();
	});

	it("clicking screenshare twice returns to 'Share screen' label", async () => {
		await renderWithActiveCall("voice");
		const btn = screen.getByTestId("call-btn-screenshare");
		await act(async () => {
			fireEvent.click(btn);
		});
		await act(async () => {
			fireEvent.click(btn);
		});
		expect(screen.getByLabelText("Share screen")).toBeTruthy();
	});

	it("screenshare button not visible when call is outgoing (pre-active)", () => {
		vi.useFakeTimers();
		render(<ChatLayout />);
		fireEvent.click(screen.getByLabelText("Voice call"));
		// Still in outgoing state — no active controls row
		expect(screen.queryByTestId("call-btn-screenshare")).toBeNull();
	});

	it("screenshare button not visible on incoming call (pre-accept)", () => {
		render(<ChatLayout />);
		fireEvent.click(screen.getByTestId("dev-simulate-incoming-call"));
		expect(screen.queryByTestId("call-btn-screenshare")).toBeNull();
	});

	it("screenshare state clears on hang up", async () => {
		await renderWithActiveCall("voice");
		const btn = screen.getByTestId("call-btn-screenshare");
		await act(async () => {
			fireEvent.click(btn);
		});
		expect(screen.getByLabelText("Stop sharing screen")).toBeTruthy();
		// End the call
		await act(async () => {
			fireEvent.click(screen.getByLabelText("End call"));
		});
		// Overlay gone
		expect(screen.queryByTestId("call-overlay")).toBeNull();
		// Start a new call — screensharing must be reset to false
		fireEvent.click(screen.getByLabelText("Voice call"));
		await act(async () => {
			vi.advanceTimersByTime(2500);
		});
		expect(screen.getByLabelText("Share screen")).toBeTruthy();
	});

	it("screenshare and mute are independent toggles", async () => {
		await renderWithActiveCall("voice");
		await act(async () => {
			fireEvent.click(screen.getByTestId("call-btn-screenshare"));
		});
		await act(async () => {
			fireEvent.click(screen.getByTestId("call-btn-mute"));
		});
		expect(screen.getByLabelText("Stop sharing screen")).toBeTruthy();
		expect(screen.getByLabelText("Unmute")).toBeTruthy();
	});

	it("no getDisplayMedia or getUserMedia calls are made — stub only", async () => {
		const getDisplayMedia = vi.fn();
		const getUserMedia = vi.fn();
		Object.defineProperty(global.navigator, "mediaDevices", {
			value: { getDisplayMedia, getUserMedia },
			writable: true,
			configurable: true,
		});
		await renderWithActiveCall("voice");
		await act(async () => {
			fireEvent.click(screen.getByTestId("call-btn-screenshare"));
		});
		expect(getDisplayMedia).not.toHaveBeenCalled();
		expect(getUserMedia).not.toHaveBeenCalled();
	});
});
