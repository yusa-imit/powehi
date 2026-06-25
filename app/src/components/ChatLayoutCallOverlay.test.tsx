import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
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

describe("ChatLayout — voice/video call overlay", () => {
	beforeEach(() => {
		vi.spyOn(CryptoWorkerHook, "useCryptoWorker").mockReturnValue(
			MOCK_WORKER as unknown as ReturnType<typeof CryptoWorkerHook.useCryptoWorker>,
		);
		useAuthStore.setState({
			sessionToken: "tok-call-test",
			identityId: "22222222-2222-2222-2222-222222222222",
			phase: "app",
			deviceId: "dev-call-test",
		});
		vi.spyOn(UseMessagesModule, "useMessages").mockImplementation(() => {});
	});

	afterEach(() => {
		cleanup();
		vi.restoreAllMocks();
		vi.useRealTimers();
		useAuthStore.setState({ sessionToken: null, identityId: null, phase: "login", deviceId: null });
	});

	it("no call overlay shown initially", () => {
		render(<ChatLayout />);
		expect(screen.queryByTestId("call-overlay")).toBeNull();
	});

	it("voice call button opens overlay in outgoing state", async () => {
		render(<ChatLayout />);
		fireEvent.click(screen.getByLabelText("Voice call"));
		const overlay = await screen.findByTestId("call-overlay");
		expect(overlay).toBeTruthy();
		expect(screen.getByTestId("call-status-outgoing").textContent).toContain("Calling...");
	});

	it("video call button opens overlay in outgoing state with video label", async () => {
		render(<ChatLayout />);
		fireEvent.click(screen.getByLabelText("Video call"));
		const overlay = await screen.findByTestId("call-overlay");
		expect(overlay).toBeTruthy();
		expect(screen.getByTestId("call-status-outgoing").textContent).toContain("Video call");
	});

	it("outgoing overlay shows the active chat name", async () => {
		render(<ChatLayout />);
		fireEvent.click(screen.getByLabelText("Voice call"));
		await screen.findByTestId("call-overlay");
		// Default active chat is Maya
		expect(screen.getByTestId("call-peer-name").textContent).toBe("Maya Akana");
	});

	it("outgoing overlay transitions to active after 2500 ms (fake timers)", async () => {
		vi.useFakeTimers();
		render(<ChatLayout />);
		fireEvent.click(screen.getByLabelText("Voice call"));
		// Synchronous check — state update is batched by React, so wrap in act
		await act(async () => {});
		expect(screen.getByTestId("call-status-outgoing")).toBeTruthy();
		await act(async () => {
			vi.advanceTimersByTime(2500);
		});
		expect(screen.queryByTestId("call-status-outgoing")).toBeNull();
		expect(screen.getByTestId("call-duration")).toBeTruthy();
	});

	it("active call shows 00:00 duration initially", async () => {
		vi.useFakeTimers();
		render(<ChatLayout />);
		fireEvent.click(screen.getByLabelText("Voice call"));
		await act(async () => {
			vi.advanceTimersByTime(2500);
		});
		expect(screen.getByTestId("call-duration").textContent).toBe("00:00");
	});

	it("duration timer increments every second", async () => {
		vi.useFakeTimers();
		render(<ChatLayout />);
		fireEvent.click(screen.getByLabelText("Voice call"));
		await act(async () => {
			vi.advanceTimersByTime(2500);
		});
		await act(async () => {
			vi.advanceTimersByTime(3000);
		});
		expect(screen.getByTestId("call-duration").textContent).toBe("00:03");
	});

	it("end call button dismisses the overlay", async () => {
		render(<ChatLayout />);
		fireEvent.click(screen.getByLabelText("Voice call"));
		await screen.findByTestId("call-overlay");
		fireEvent.click(screen.getByTestId("call-btn-end"));
		await waitFor(() => expect(screen.queryByTestId("call-overlay")).toBeNull());
	});

	it("mute button toggles aria-label between Mute and Unmute", async () => {
		vi.useFakeTimers();
		render(<ChatLayout />);
		fireEvent.click(screen.getByLabelText("Voice call"));
		await act(async () => {
			vi.advanceTimersByTime(2500);
		});
		const muteBtn = screen.getByTestId("call-btn-mute");
		expect(muteBtn.getAttribute("aria-label")).toBe("Mute");
		fireEvent.click(muteBtn);
		expect(screen.getByTestId("call-btn-mute").getAttribute("aria-label")).toBe("Unmute");
	});

	it("camera button is absent for voice call", async () => {
		vi.useFakeTimers();
		render(<ChatLayout />);
		fireEvent.click(screen.getByLabelText("Voice call"));
		await act(async () => {
			vi.advanceTimersByTime(2500);
		});
		expect(screen.queryByTestId("call-btn-camera")).toBeNull();
	});

	it("camera button present for video call and toggles", async () => {
		vi.useFakeTimers();
		render(<ChatLayout />);
		fireEvent.click(screen.getByLabelText("Video call"));
		await act(async () => {
			vi.advanceTimersByTime(2500);
		});
		const camBtn = screen.getByTestId("call-btn-camera");
		expect(camBtn.getAttribute("aria-label")).toBe("Camera off");
		fireEvent.click(camBtn);
		expect(screen.getByTestId("call-btn-camera").getAttribute("aria-label")).toBe("Camera on");
	});

	it("incoming call overlay shows accept and decline buttons", async () => {
		render(<ChatLayout />);
		const simBtn = screen.getByTestId("dev-simulate-incoming-call");
		fireEvent.click(simBtn);
		await screen.findByTestId("call-overlay");
		expect(screen.getByTestId("call-status-incoming")).toBeTruthy();
		expect(screen.getByTestId("call-btn-accept")).toBeTruthy();
		expect(screen.getByTestId("call-btn-decline")).toBeTruthy();
	});

	it("accepting incoming call transitions to active state", async () => {
		render(<ChatLayout />);
		fireEvent.click(screen.getByTestId("dev-simulate-incoming-call"));
		await screen.findByTestId("call-status-incoming");
		fireEvent.click(screen.getByTestId("call-btn-accept"));
		await waitFor(() => expect(screen.getByTestId("call-duration")).toBeTruthy());
	});

	it("declining incoming call dismisses overlay", async () => {
		render(<ChatLayout />);
		fireEvent.click(screen.getByTestId("dev-simulate-incoming-call"));
		await screen.findByTestId("call-status-incoming");
		fireEvent.click(screen.getByTestId("call-btn-decline"));
		await waitFor(() => expect(screen.queryByTestId("call-overlay")).toBeNull());
	});
});
