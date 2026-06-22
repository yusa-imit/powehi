import { act, renderHook } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { useTauriNotification } from "./useTauriNotification";

// ── Plugin mock ────────────────────────────────────────────────────────────────
const mockSendNotification = vi.fn();
const mockIsPermissionGranted = vi.fn();
const mockRequestPermission = vi.fn();

vi.mock("@tauri-apps/plugin-notification", () => ({
	isPermissionGranted: mockIsPermissionGranted,
	requestPermission: mockRequestPermission,
	sendNotification: mockSendNotification,
}));

// ── Helpers ───────────────────────────────────────────────────────────────────

function setTauri(active: boolean) {
	if (active) {
		Object.defineProperty(window, "__TAURI_INTERNALS__", {
			value: {},
			configurable: true,
			writable: true,
		});
	} else {
		Object.defineProperty(window, "__TAURI_INTERNALS__", {
			value: undefined,
			configurable: true,
			writable: true,
		});
	}
}

function setFocus(focused: boolean) {
	vi.spyOn(document, "hasFocus").mockReturnValue(focused);
}

// ── Tests ─────────────────────────────────────────────────────────────────────

describe("useTauriNotification — outside Tauri", () => {
	beforeEach(() => {
		setTauri(false);
		vi.clearAllMocks();
	});

	afterEach(() => {
		vi.restoreAllMocks();
	});

	it("returns a no-op outside Tauri (does not call sendNotification)", async () => {
		setFocus(false);
		const { result } = renderHook(() => useTauriNotification());
		await act(async () => {});
		result.current();
		expect(mockSendNotification).not.toHaveBeenCalled();
	});
});

describe("useTauriNotification — inside Tauri, permission granted", () => {
	beforeEach(() => {
		setTauri(true);
		mockIsPermissionGranted.mockResolvedValue(true);
		mockRequestPermission.mockResolvedValue("granted");
		vi.clearAllMocks();
	});

	afterEach(() => {
		vi.restoreAllMocks();
	});

	it("shows notification when window is not focused", async () => {
		mockIsPermissionGranted.mockResolvedValue(true);
		setFocus(false);
		const { result } = renderHook(() => useTauriNotification());
		await act(async () => {});
		result.current();
		expect(mockSendNotification).toHaveBeenCalledWith({
			title: "Powehi",
			body: "New message",
		});
	});

	it("suppresses notification when window is focused", async () => {
		mockIsPermissionGranted.mockResolvedValue(true);
		setFocus(true);
		const { result } = renderHook(() => useTauriNotification());
		await act(async () => {});
		result.current();
		expect(mockSendNotification).not.toHaveBeenCalled();
	});

	it("notification title is always 'Powehi' — never contains sender info", async () => {
		mockIsPermissionGranted.mockResolvedValue(true);
		setFocus(false);
		const { result } = renderHook(() => useTauriNotification());
		await act(async () => {});
		result.current();
		const call = mockSendNotification.mock.calls[0][0] as { title: string; body: string };
		expect(call.title).toBe("Powehi");
		expect(call.body).not.toMatch(/[A-Za-z0-9+/=]{10,}/); // no base64 blobs (ciphertext guard)
	});

	it("notification body never contains plaintext message content", async () => {
		mockIsPermissionGranted.mockResolvedValue(true);
		setFocus(false);
		const { result } = renderHook(() => useTauriNotification());
		await act(async () => {});
		// Call with a hypothetical message text to verify it does NOT appear in the notification
		result.current();
		const call = mockSendNotification.mock.calls[0][0] as { title: string; body: string };
		expect(call.body).toBe("New message");
	});
});

describe("useTauriNotification — inside Tauri, permission denied", () => {
	beforeEach(() => {
		setTauri(true);
		mockIsPermissionGranted.mockResolvedValue(false);
		mockRequestPermission.mockResolvedValue("denied");
		vi.clearAllMocks();
	});

	afterEach(() => {
		vi.restoreAllMocks();
	});

	it("does not show notification when permission is denied", async () => {
		setFocus(false);
		const { result } = renderHook(() => useTauriNotification());
		await act(async () => {});
		result.current();
		expect(mockSendNotification).not.toHaveBeenCalled();
	});
});

describe("useTauriNotification — permission flows", () => {
	afterEach(() => {
		setTauri(false);
		vi.restoreAllMocks();
	});

	it("requests permission when isPermissionGranted is false", async () => {
		setTauri(true);
		mockIsPermissionGranted.mockResolvedValue(false);
		mockRequestPermission.mockResolvedValue("granted");
		setFocus(false);
		const { result } = renderHook(() => useTauriNotification());
		await act(async () => {});
		expect(mockRequestPermission).toHaveBeenCalled();
		result.current();
		expect(mockSendNotification).toHaveBeenCalledTimes(1);
	});

	it("skips requestPermission when already granted", async () => {
		setTauri(true);
		mockIsPermissionGranted.mockResolvedValue(true);
		setFocus(false);
		renderHook(() => useTauriNotification());
		await act(async () => {});
		expect(mockRequestPermission).not.toHaveBeenCalled();
	});

	it("callback is stable across re-renders", () => {
		setTauri(false);
		const { result, rerender } = renderHook(() => useTauriNotification());
		const first = result.current;
		rerender();
		expect(result.current).toBe(first);
	});
});
