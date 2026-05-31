import { create } from "zustand";
import { getCryptoWorkerProxy } from "../hooks/useCryptoWorker";

interface AuthState {
	phase: "login" | "app";
	deviceId: string | null;
	login: (deviceId: string) => void;
	logout: () => void;
}

export const useAuthStore = create<AuthState>()((set) => ({
	phase: "login",
	deviceId: null,
	login: (deviceId: string) => set({ phase: "app", deviceId }),
	logout: () => {
		// Clear the AES-GCM-256 IndexedDB key and all MLS/OPAQUE session state
		// from the crypto worker. Comlink's message queue is FIFO per worker, so
		// both posts are guaranteed to be processed before any subsequent
		// initDbKey()/mls_init_identity() that would follow a new OPAQUE login
		// (which requires server round-trips, leaving ample time after these posts).
		// State transitions synchronously; the wipes complete asynchronously in the worker.
		const proxy = getCryptoWorkerProxy();
		// Swallow rejections: WASM panic during clear does not block the logout
		// transition.  Error category is not logged (no-plaintext-logging rule).
		proxy?.clearSessionState().catch(() => {});
		proxy?.dropDbKey();
		set({ phase: "login", deviceId: null });
	},
}));
