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
		// Clear the AES-GCM-256 IndexedDB key from the crypto worker.
		// Comlink's message queue is FIFO per worker, so this post is guaranteed
		// to be processed before any subsequent initDbKey() call that would
		// follow a new OPAQUE login (which requires server round-trips, leaving
		// ample time after this post).  State transitions synchronously; the key
		// wipe completes asynchronously in the worker.
		//
		// Scope: this wipes only the Dexie AES-GCM key.  MLS identity material
		// held in the WASM heap is NOT cleared here — wiring a full WASM memory
		// reset on logout is deferred until the OPAQUE→MLS session binding work.
		getCryptoWorkerProxy()?.dropDbKey();
		set({ phase: "login", deviceId: null });
	},
}));
