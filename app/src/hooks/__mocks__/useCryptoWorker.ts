// Manual mock for useCryptoWorker — used by Vitest when vi.mock("../hooks/useCryptoWorker")
// is called without a factory.  Returns a stable singleton so that React's useEffect
// dependency array sees the same reference across re-renders.
const mockWorker = {
	mlsGroupMembers: async () => [
		{
			leafIndex: 0,
			sigKeyHex: "aa".repeat(64),
		},
		{
			leafIndex: 1,
			sigKeyHex: "bb".repeat(64),
		},
	],
	mlsComputeSafetyNumber: async () => ({
		safetyNumber:
			"689053 337949 184798 288064 134849 362568 560227 765408 921198 315305 693006 807986",
	}),
	dropDbKey: async () => {},
	clearSessionState: async () => {},
};

export const useCryptoWorker = () => mockWorker;
export const getCryptoWorkerProxy = () => mockWorker;
