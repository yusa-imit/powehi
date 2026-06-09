import { create } from "zustand";
import { getCryptoWorkerProxy } from "../hooks/useCryptoWorker";

interface AuthState {
	phase: "login" | "app";
	deviceId: string | null;
	/** Bearer token for authenticated API calls. In-memory only — cleared on logout/refresh. */
	sessionToken: string | null;
	/** MLS identity handle in the WASM worker for this session. Re-generated each login. */
	identityId: string | null;
	login: (deviceId: string, sessionToken?: string, identityId?: string) => void;
	logout: () => Promise<void>;
}

export const useAuthStore = create<AuthState>()((set) => ({
	phase: "login",
	deviceId: null,
	sessionToken: null,
	identityId: null,
	login: (deviceId: string, sessionToken?: string, identityId?: string) =>
		set({
			phase: "app",
			deviceId,
			sessionToken: sessionToken ?? null,
			identityId: identityId ?? null,
		}),
	logout: async () => {
		// Await both wipes before clearing auth state (F3): key material must be
		// gone from the worker heap before a new OPAQUE session can begin.
		// Rejections from clearSessionState are swallowed (WASM panic does not
		// block logout); dropDbKey is synchronous in the worker but async via Comlink.
		const proxy = getCryptoWorkerProxy();
		await proxy?.clearSessionState().catch(() => {});
		await proxy?.dropDbKey();
		set({ phase: "login", deviceId: null, sessionToken: null, identityId: null });
	},
}));
