import { create } from "zustand";
import { getCryptoWorkerProxy } from "../hooks/useCryptoWorker";

interface AuthState {
	phase: "login" | "app";
	deviceId: string | null;
	/** Bearer token for authenticated API calls. In-memory only — cleared on logout/refresh. */
	sessionToken: string | null;
	/** MLS identity handle in the WASM worker for this session. Re-generated each login. */
	identityId: string | null;
	/** ML-KEM-768 decap key handle for the Welcome-side PQ binding (§5.3 Phase B). Cleared after use. */
	pqDecapKeyHandle: string | null;
	/** The user's own plaintext handle — used for @mention detection in group messages. Never sent to server. */
	myHandle: string | null;
	login: (
		deviceId: string,
		sessionToken?: string,
		identityId?: string,
		pqDecapKeyHandle?: string,
		myHandle?: string,
	) => void;
	clearPqDecapKeyHandle: () => void;
	logout: () => Promise<void>;
}

export const useAuthStore = create<AuthState>()((set) => ({
	phase: "login",
	deviceId: null,
	sessionToken: null,
	identityId: null,
	pqDecapKeyHandle: null,
	myHandle: null,
	login: (
		deviceId: string,
		sessionToken?: string,
		identityId?: string,
		pqDecapKeyHandle?: string,
		myHandle?: string,
	) =>
		set({
			phase: "app",
			deviceId,
			sessionToken: sessionToken ?? null,
			identityId: identityId ?? null,
			pqDecapKeyHandle: pqDecapKeyHandle ?? null,
			myHandle: myHandle ?? null,
		}),
	clearPqDecapKeyHandle: () => set({ pqDecapKeyHandle: null }),
	logout: async () => {
		// Await both wipes before clearing auth state (F3): key material must be
		// gone from the worker heap before a new OPAQUE session can begin.
		// Rejections from clearSessionState are swallowed (WASM panic does not
		// block logout); dropDbKey is synchronous in the worker but async via Comlink.
		const proxy = getCryptoWorkerProxy();
		await proxy?.clearSessionState().catch(() => {});
		await proxy?.dropDbKey();
		set({
			phase: "login",
			deviceId: null,
			sessionToken: null,
			identityId: null,
			pqDecapKeyHandle: null,
			myHandle: null,
		});
	},
}));
