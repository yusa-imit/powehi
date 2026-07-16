import { vi } from "vitest";
// Manual mock for useCryptoWorker — used by Vitest when vi.mock("../hooks/useCryptoWorker")
// is called without a factory.  Returns a stable singleton so that React's useEffect
// dependency array sees the same reference across re-renders.
const mockWorker = {
	// OPAQUE registration (§3.2)
	opaqueRegistrationStart: vi.fn().mockResolvedValue({
		sessionId: "mock-reg-session-id",
		message: new Uint8Array(32),
	}),
	opaqueRegistrationFinish: vi.fn().mockResolvedValue({
		upload: new Uint8Array(64),
	}),
	// OPAQUE login (§3.3)
	opaqueLoginStart: vi.fn().mockResolvedValue({
		sessionId: "mock-login-session-id",
		message: new Uint8Array(32),
	}),
	opaqueLoginFinish: vi.fn().mockResolvedValue({
		finalization: new Uint8Array(64),
	}),
	mlsInitIdentity: async (_identityBytes: Uint8Array) => ({
		identityId: "mock-identity-id",
		keyPackage: new Uint8Array(100),
		pqDecapKeyHandle: "mock-pq-decap-handle-0",
	}),
	mlsCreateGroup: async (_identityId: string) => ({
		groupId: "mock-group-id-00000000-0000-0000-0000-000000000000",
	}),
	mlsAddMember: async (_identityId: string, _groupId: string, _keyPackage: Uint8Array) => ({
		welcome: new Uint8Array(200),
	}),
	mlsJoinGroup: async (_identityId: string, _welcome: Uint8Array) => ({
		groupId: "mock-group-id-00000000-0000-0000-0000-000000000000",
	}),
	mlsEncrypt: async (_identityId: string, _groupId: string, _plaintext: Uint8Array) => ({
		ciphertext: new Uint8Array(64),
	}),
	mlsDecrypt: async (_identityId: string, _groupId: string, _ciphertext: Uint8Array) => ({
		plaintext: new TextEncoder().encode("mock plaintext"),
	}),
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
	mlKem768Keygen: async () => ({ encapKey: new Uint8Array(1184), decapKey: new Uint8Array(2400) }),
	mlKem768Encap: async (_encapKey: Uint8Array) => ({
		ciphertext: new Uint8Array(1088),
		sharedSecret: new Uint8Array(32),
	}),
	mlKem768Decap: async (_decapKey: Uint8Array, _ciphertext: Uint8Array) => ({
		sharedSecret: new Uint8Array(32),
	}),
	// ADR-0003 Phase B: opaque-handle mocks — handles are static strings (no real state).
	mlKem768KeygenV2: async () => ({
		encapKey: new Uint8Array(1184),
		decapKeyHandle: "mock-decap-handle-0",
	}),
	mlKem768EncapV2: async (_encapKey: Uint8Array) => ({
		ciphertext: new Uint8Array(1088),
		sharedSecretHandle: "mock-ss-enc-handle-0",
	}),
	mlKem768DecapV2: async (_decapKeyHandle: string, _ciphertext: Uint8Array) => ({
		sharedSecretHandle: "mock-ss-dec-handle-0",
	}),
	mlKem768DropDecapKey: async (_handle: string) => {},
	mlKem768DropSharedSecret: async (_handle: string) => {},
	// ADR-0003 Phase B, Y-3: signed encap key credential mocks.
	mlKem768SignEncapKey: async (_identityId: string, _encapKey: Uint8Array) => ({
		signature: new Uint8Array(64),
	}),
	mlKem768VerifyEncapKey: async (
		_encapKey: Uint8Array,
		_signature: Uint8Array,
		_sigPubKey: Uint8Array,
	) => ({ valid: true }),
	// §8.5 Recovery: BIP-39 phrase generation and phrase-derived identity.
	generateRecoveryPhrase: vi.fn().mockResolvedValue({
		words: Array.from({ length: 24 }, (_, i) => `word${i + 1}`),
	}),
	mlsInitIdentityFromPhrase: vi.fn().mockResolvedValue({
		identityId: "mock-identity-id",
		keyPackage: new Uint8Array([1, 2, 3]),
		pqDecapKeyHandle: "mock-pq-decap-handle-phrase-0",
	}),
	// prd.md §5.3 Phase B — extract ML-KEM encap key from a peer's KeyPackage.
	mlsPqExtractEncapKey: async (_keyPackageBytes: Uint8Array) => ({
		encapKey: new Uint8Array(1184),
		signature: new Uint8Array(64),
	}),
	// prd.md §5.3 Phase B — extract AND verify (recommended; prevents skipped verification).
	mlsPqExtractAndVerifyEncapKey: async (_keyPackageBytes: Uint8Array, _sigPubKey: Uint8Array) => ({
		encapKey: new Uint8Array(1184),
		signature: new Uint8Array(64),
	}),
	// prd.md §5.3 Phase B — derive PQ group binding from a shared-secret handle.
	mlsPqDeriveBinding: async (_ssHandle: string, _groupId: string) => ({
		bindingHex: "mockbindingval1",
	}),
	// §9.2 Media encryption: AES-256-GCM opaque-handle mocks.
	// mediaKeyHandle is a static string — no real key state in tests.
	mediaEncrypt: async (_plaintext: Uint8Array) => ({
		ciphertext: new Uint8Array(32 + 16), // 32 bytes plaintext + 16-byte GCM tag
		mediaKeyHandle: "mock-media-key-handle-0",
		iv: new Uint8Array(12),
		blobHash: new Uint8Array(32),
	}),
	mediaDecrypt: async (_mediaKeyHandle: string, _iv: Uint8Array, _ciphertext: Uint8Array) =>
		new Uint8Array(32),
	mediaDecryptWithRawKey: async (
		_mediaKey: Uint8Array,
		_iv: Uint8Array,
		_ciphertext: Uint8Array,
		_blobHash: Uint8Array,
	) => new Uint8Array(32),
	mediaDropKey: async (_handle: string) => true,
	// §9.2 media_message_create: returns mock MLS ciphertext (32 bytes).
	// Raw media key stays in WASM; this mock returns a fixed-length buffer.
	mediaMessageCreate: async (
		_identityId: string,
		_groupId: string,
		_mediaKeyHandle: string,
		_blobId: string,
		_blobHash: Uint8Array,
		_iv: Uint8Array,
		_mimeType?: string,
	) => ({ ciphertext: new Uint8Array(64) }),
	// §9.4.2 Chunked media encryption/message-create mocks.
	mediaEncryptChunked: async (bytes: Uint8Array) => ({
		ciphertext: new Uint8Array(bytes.length + 16),
		mediaKeyHandle: "mock-chunked-key-handle-0",
		iv: new Uint8Array(12),
		blobHash: new Uint8Array(32),
		totalSize: bytes.length,
		chunkSize: 16 * 1024 * 1024,
	}),
	mediaMessageCreateChunked: async (
		_identityId: string,
		_groupId: string,
		_mediaKeyHandle: string,
		_blobId: string,
		_blobHash: Uint8Array,
		_iv: Uint8Array,
		_totalSize: number,
		_mimeType?: string,
	) => ({ ciphertext: new Uint8Array(96) }),
	mediaDecryptChunkedWithRawKey: async (
		_mediaKey: Uint8Array,
		_iv: Uint8Array,
		_ciphertext: Uint8Array,
		_blobHash: Uint8Array,
		_totalSize: number,
	) => new Uint8Array(20),
	// §9.4.1 Thumbnail encryption mocks.
	mediaThumbnailEncrypt: async (_thumbBytes: Uint8Array) => ({
		thumbHandle: "mock-thumb-handle-0",
	}),
	mediaThumbnailDrop: async (_handle: string) => true,
	mediaThumbnailDecrypt: async (_ct: Uint8Array, _key: Uint8Array, _iv: Uint8Array) => ({
		pixels: new Uint8Array(new ArrayBuffer(64 * 64 * 3)), // mock 64x64 RGB pixels
	}),
	mediaMessageCreateWithThumbnail: async (
		_identityId: string,
		_groupId: string,
		_mediaKeyHandle: string,
		_blobId: string,
		_blobHash: Uint8Array,
		_iv: Uint8Array,
		_thumbHandle: string,
		_mimeType?: string,
	) => ({ ciphertext: new Uint8Array(64) }),
};

export const useCryptoWorker = () => mockWorker;
export const getCryptoWorkerProxy = () => mockWorker;
