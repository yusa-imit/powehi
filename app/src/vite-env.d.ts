/// <reference types="vite/client" />

interface ImportMetaEnv {
	readonly VITE_VAPID_PUBLIC_KEY?: string;
}

interface ImportMeta {
	readonly env: ImportMetaEnv;
}

// Ambient declaration so tsc is satisfied before wasm-pack generates the real file.
// The actual types are cast at the import site (as unknown as WasmModule).
declare module "*powehi_crypto_wasm.js" {
	const init: () => Promise<void>;
	export default init;
	export {};
}
