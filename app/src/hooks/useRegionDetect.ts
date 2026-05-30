import { useEffect } from "react";
import { useRegionStore } from "../store/region";

/**
 * Calls GET /v1/region/detect once on mount to discover the connected region.
 * The CF Worker already routes to the nearest healthy region; this endpoint
 * just confirms which region the request landed on (prd.md §7.6).
 */
export function useRegionDetect(): string | null {
	const fetch = useRegionStore((s) => s.fetch);
	const regionId = useRegionStore((s) => s.regionId);

	useEffect(() => {
		fetch();
	}, [fetch]);

	return regionId;
}
