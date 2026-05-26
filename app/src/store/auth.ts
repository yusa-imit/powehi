import { create } from "zustand";

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
	logout: () => set({ phase: "login", deviceId: null }),
}));
