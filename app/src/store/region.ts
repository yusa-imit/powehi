import { create } from "zustand";

interface RegionState {
	regionId: string | null;
	detectedAt: number | null;
	fetch: () => Promise<void>;
}

export const useRegionStore = create<RegionState>()((set) => ({
	regionId: null,
	detectedAt: null,
	fetch: async () => {
		try {
			const res = await window.fetch("/v1/region/detect");
			if (!res.ok) return;
			const data = (await res.json()) as { region_id: string };
			if (typeof data.region_id === "string" && data.region_id.length > 0) {
				set({ regionId: data.region_id, detectedAt: Date.now() });
			}
		} catch {
			// Network error or JSON parse failure — fail silently (non-critical bootstrap)
		}
	},
}));
