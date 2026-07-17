import { type ChangeEvent, type FormEvent, useRef, useState } from "react";
import {
	hashHandle,
	loginFinish,
	loginInit,
	regFinish,
	regInit,
	uploadKeyPackage,
} from "../api/auth";
import { EncryptedPowehiDb } from "../db/encrypted-db";
import { db } from "../db/schema";
import { useCryptoWorker } from "../hooks/useCryptoWorker";
import { useAuthStore } from "../store/auth";
import { base64ToUint8Array, uint8ToBase64 } from "../utils/base64";
import type { MlsIdentityFromPhraseResult } from "../workers/crypto.worker";
import { Icon } from "./Icon";
import { RecoveryPhraseModal } from "./RecoveryPhraseModal";

// Logo — Gargantua silhouette (from Atoms.jsx).
function Logo({ size = 32 }: { size?: number }) {
	const uid = `pw-logo-${size}`;
	return (
		<svg
			width={size}
			height={size}
			viewBox="0 0 256 256"
			fill="none"
			role="img"
			aria-label="Powehi logo"
		>
			<defs>
				<radialGradient id={uid} cx="50%" cy="50%" r="50%">
					<stop offset="0%" stopColor="#FFB155" />
					<stop offset="30%" stopColor="#FF8A3D" />
					<stop offset="60%" stopColor="#C75612" stopOpacity="0.7" />
					<stop offset="100%" stopColor="#3A1A06" stopOpacity="0" />
				</radialGradient>
			</defs>
			<ellipse cx="128" cy="128" rx="124" ry="84" fill={`url(#${uid})`} />
			<circle cx="128" cy="128" r="46" fill="#000000" />
			<circle cx="128" cy="128" r="46" fill="none" stroke="#E8F0FF" strokeWidth="1.4" />
		</svg>
	);
}

type LoginPhase = "idle" | "loading" | "recovery" | "error";
type Mode = "sign-in" | "create-account" | "restore-account";

export function Login() {
	const login = useAuthStore((s) => s.login);
	const cryptoWorker = useCryptoWorker();

	const [handle, setHandle] = useState("");
	const [password, setPassword] = useState("");
	const [phase, setPhase] = useState<LoginPhase>("idle");
	const [recoveryWords, setRecoveryWords] = useState<string[] | null>(null);
	// Holds registration credentials until the user confirms the recovery phrase (§8.5).
	const pendingLoginRef = useRef<{
		device_id: string;
		token: string;
		identityId: string | undefined;
		pqDecapKeyHandle: string | undefined;
		myHandle: string;
	} | null>(null);
	const [errorMsg, setErrorMsg] = useState("");
	const [mode, setMode] = useState<Mode>("sign-in");
	// §8.5 account restore: the 24-word BIP-39 recovery phrase, typed by a user
	// with no local device row. Cleared immediately after every submit attempt
	// (success or failure) — same F2-style hygiene as the password field below.
	const [recoveryPhrase, setRecoveryPhrase] = useState("");

	const handleHandleChange = (e: ChangeEvent<HTMLInputElement>) => {
		setHandle(e.target.value);
	};

	const handlePasswordChange = (e: ChangeEvent<HTMLInputElement>) => {
		setPassword(e.target.value);
	};

	/** OPAQUE registration → returns (device_id, session_token, identityId). DB key derived inside worker. */
	const doRegister = async (
		pw: Uint8Array,
		handle_hash: Uint8Array,
	): Promise<{
		device_id: string;
		token: string;
		identityId: string;
		recoveryWords: string[];
		pqDecapKeyHandle: string;
	}> => {
		if (!cryptoWorker) throw new Error("crypto_unavailable");

		// Step 1: OPAQUE reg start
		const { sessionId, message: ke1 } = await cryptoWorker.opaqueRegistrationStart(pw);

		// Step 2: server registration init
		const initResp = await regInit(handle_hash, ke1);

		// Step 3: OPAQUE reg finish — worker derives DB key internally; returns upload only.
		const { upload: opaque_record } = await cryptoWorker.opaqueRegistrationFinish(
			sessionId,
			pw,
			new Uint8Array(initResp.opaque_response),
		);

		// Step 4: Generate BIP-39 recovery phrase (§8.5) — NEVER log or store the joined phrase.
		const { words: recoveryWords } = await cryptoWorker.generateRecoveryPhrase();
		const phrase = recoveryWords.join(" ");

		// Derive a 16-byte public identity label from SHA-256(phrase)[0..16].
		// The actual MLS signing key is derived inside WASM from the full BIP-39 seed.
		const phraseEncoder = new TextEncoder();
		const phraseHash = await crypto.subtle.digest("SHA-256", phraseEncoder.encode(phrase));
		const mlsIdentityBytes = new Uint8Array(phraseHash).slice(0, 16);

		const { identityId, keyPackage, pqDecapKeyHandle, recoveryPubkey } =
			(await cryptoWorker.mlsInitIdentityFromPhrase(
				phrase,
				mlsIdentityBytes,
			)) as MlsIdentityFromPhraseResult;
		// phrase goes out of scope here; the words array is held temporarily for display only.

		// Step 5: server registration finish — creates user + device.
		// §8.5: recoveryPubkey is submitted ONCE here so a future restore-account
		// login (doRestoreAccount below) can prove phrase possession against it.
		// Without this, users.recovery_pubkey is never populated and restore can
		// never succeed for this account.
		const finishResp = await regFinish(
			initResp.user_id,
			opaque_record,
			mlsIdentityBytes,
			recoveryPubkey,
		);

		// Step 6: auto-login to get a session token
		const { token } = await doLogin(pw, handle_hash, finishResp.device_id);

		// Step 7: upload initial key package (non-fatal)
		uploadKeyPackage(token, finishResp.device_id, keyPackage).catch(() => {});

		// Step 8: persist MLS identity bytes so they can be re-used on future logins.
		await db.identity.put({
			id: 1,
			deviceId: finishResp.device_id,
			mlsIdentityId: identityId,
			mlsIdentityB64: uint8ToBase64(mlsIdentityBytes),
		});

		return { device_id: finishResp.device_id, token, identityId, recoveryWords, pqDecapKeyHandle };
	};

	/** OPAQUE login → returns session_token. DB key derived inside worker. */
	const doLogin = async (
		pw: Uint8Array,
		handle_hash: Uint8Array,
		device_id: string,
	): Promise<{ token: string }> => {
		if (!cryptoWorker) throw new Error("crypto_unavailable");

		// Step 1: OPAQUE login start
		const { sessionId, message: ke1 } = await cryptoWorker.opaqueLoginStart(pw);

		// Step 2: server login init
		const initResp = await loginInit(handle_hash, ke1);

		// Step 3: OPAQUE login finish — verifies server, worker derives DB key internally.
		const { finalization: ke3 } = await cryptoWorker.opaqueLoginFinish(
			sessionId,
			pw,
			new Uint8Array(initResp.opaque_ke2),
		);

		// Step 4: server login finish — validates ke3, returns session token
		const token = await loginFinish(ke3, initResp.login_nonce, device_id);

		return { token };
	};

	/**
	 * §8.5 account restore — signs in from a brand-new device (no local
	 * IndexedDB identity row) using password + the 24-word BIP-39 recovery
	 * phrase. Re-derives the phrase-locked MLS identity in-browser, proves
	 * possession of the phrase by signing the server's login nonce, and the
	 * server mints a brand-new device for this account.
	 */
	const doRestoreAccount = async (
		pw: Uint8Array,
		handle_hash: Uint8Array,
		phrase: string,
	): Promise<{
		device_id: string;
		token: string;
		identityId: string;
		pqDecapKeyHandle: string;
	}> => {
		if (!cryptoWorker) throw new Error("crypto_unavailable");

		// Steps 1–3: OPAQUE login dance, identical to doLogin's.
		const { sessionId, message: ke1 } = await cryptoWorker.opaqueLoginStart(pw);
		const initResp = await loginInit(handle_hash, ke1);
		const { finalization: ke3 } = await cryptoWorker.opaqueLoginFinish(
			sessionId,
			pw,
			new Uint8Array(initResp.opaque_ke2),
		);

		// Derive the same 16-byte public identity label used at original
		// registration for this phrase — SHA-256(phrase)[0..16] (doRegister's
		// derivation, mirrored exactly so the same device credential label
		// results for the same phrase; the actual MLS signing key is re-derived
		// inside WASM from the full BIP-39 seed).
		const phraseEncoder = new TextEncoder();
		const phraseHash = await crypto.subtle.digest("SHA-256", phraseEncoder.encode(phrase));
		const mlsIdentityBytes = new Uint8Array(phraseHash).slice(0, 16);

		const { identityId, keyPackage, pqDecapKeyHandle } =
			await cryptoWorker.mlsInitIdentityFromPhrase(phrase, mlsIdentityBytes);

		// Prove possession of the recovery phrase by signing the server's login
		// nonce (UTF-8 bytes of the nonce string) with the phrase-derived key.
		const { signature } = await cryptoWorker.mlsSignRecoveryChallenge(
			phrase,
			new TextEncoder().encode(initResp.login_nonce),
		);

		// A brand-new device is minted for this restored account.
		const device_id = crypto.randomUUID();

		const token = await loginFinish(ke3, initResp.login_nonce, device_id, {
			mls_credential: mlsIdentityBytes,
			signature,
		});

		// Persist the new device's identity so future logins on THIS browser can
		// reuse it (mirrors doRegister's identity-persistence step exactly).
		await db.identity.put({
			id: 1,
			deviceId: device_id,
			mlsIdentityId: identityId,
			mlsIdentityB64: uint8ToBase64(mlsIdentityBytes),
		});

		// Non-fatal: this device's initial KeyPackage upload.
		uploadKeyPackage(token, device_id, keyPackage).catch(() => {});

		return { device_id, token, identityId, pqDecapKeyHandle };
	};

	const handleSubmit = async (e: FormEvent) => {
		e.preventDefault();
		if (!handle.trim() || !password.trim()) {
			setErrorMsg("Handle and password are required.");
			setPhase("error");
			return;
		}

		setPhase("loading");
		setErrorMsg("");

		const encoder = new TextEncoder();
		const pw = encoder.encode(password);
		// F2: clear password from React state immediately after encoding to Uint8Array.
		setPassword("");
		// §8.5: capture then clear the recovery-phrase textarea's controlled state
		// immediately after reading it — same F2 hygiene as the password field
		// above, and unconditional (every mode/outcome), never held past this point.
		const phrase = recoveryPhrase;
		setRecoveryPhrase("");

		try {
			const handle_hash = await hashHandle(handle.trim());

			let device_id: string;
			let token: string;
			let identityId: string | null = null;

			if (mode === "restore-account") {
				const result = await doRestoreAccount(pw, handle_hash, phrase);
				// No recovery-phrase-confirmation step here (unlike create-account) —
				// the user already claims to possess the phrase; nothing new to show.
				login(
					result.device_id,
					result.token,
					result.identityId,
					result.pqDecapKeyHandle,
					handle.trim(),
				);
				return;
			}

			if (mode === "create-account") {
				const result = await doRegister(pw, handle_hash);
				device_id = result.device_id;
				token = result.token;
				identityId = result.identityId;
				// doRegister persists the identity record (including mlsIdentityB64).

				// §8.5: Show recovery phrase modal before advancing to app.
				// Store words for display; defer login() until user confirms.
				setRecoveryWords(result.recoveryWords);
				setPhase("recovery");
				// Stash credentials so onConfirmed can call login().
				pendingLoginRef.current = {
					device_id,
					token,
					identityId: identityId ?? undefined,
					pqDecapKeyHandle: result.pqDecapKeyHandle,
					myHandle: handle.trim(),
				};
				return; // login() called from onConfirmed, not here.
			}
			// Load stored device_id and MLS identity bytes from IndexedDB.
			const identity = await db.identity.get(1);
			if (!identity?.deviceId) {
				setPhase("error");
				setErrorMsg("No device registered on this browser. Create an account first.");
				return;
			}
			device_id = identity.deviceId;
			({ token } = await doLogin(pw, handle_hash, device_id));

			// Rehydrate MLS state in the WASM worker. Preferred path: restore the full
			// exported MLS context (identity + provider key store + every group) via
			// mlsImportState so existing groups survive a reload — otherwise the
			// WASM MLS_CTX thread_local starts empty on this fresh worker instance
			// and every group would appear to need rejoining. Falls back to
			// re-deriving just the signer from the stored seed bytes (mlsInitIdentity,
			// today's behavior) when there is no stored provider-state blob yet, or
			// the stored blob fails to import (stale/corrupt/wrong-version — must
			// never crash sign-in on this).
			let pqDecapKeyHandle: string | undefined;
			if (cryptoWorker) {
				let restored: {
					identityId: string;
					keyPackage?: Uint8Array;
					pqDecapKeyHandle?: string;
				} | null = null;

				// mlsProviderStateB64 is an encrypted JSON envelope { stateB64, generation }
				// (db/encrypted-db.ts SENSITIVE.identity, schema v11) — it must be read through
				// EncryptedPowehiDb.getMlsProviderState()'s decrypt+parse path, never off the
				// raw `identity` row fetched above via db.identity.get(1). (encDb.getIdentity()
				// also decrypts the field via the SENSITIVE.identity path, but returns it as the
				// raw envelope STRING without JSON-parsing { stateB64, generation };
				// getMlsProviderState() is the method that additionally parses it.) The
				// envelope's own `generation` field is discarded below (never passed to
				// mlsImportState) — it is an inert mirror of the copy already embedded
				// inside stateB64, not itself the security check. The real import floor
				// is owned by the worker wrapper (the in-session high-water-mark), NOT
				// sourced from this envelope (that would compare a value to itself); see
				// useCryptoWorker.ts and schema.ts's mlsProviderStateB64 doc comment.
				const encDb = new EncryptedPowehiDb(db, cryptoWorker);
				let providerState: { stateB64: string; generation: number } | undefined;
				try {
					providerState = await encDb.getMlsProviderState();
				} catch {
					// Corrupt/tampered envelope failed AES-GCM auth, or decrypted plaintext
					// was not valid JSON — fall through to the mlsIdentityB64 path below.
					// Never log the caught error (content could embed blob fragments in
					// some engines' error messages).
					providerState = undefined;
				}

				let importAttemptedAndFailed = false;
				if (providerState) {
					let importedId: string | null = null;
					try {
						const stateBytes = base64ToUint8Array(providerState.stateB64);
						// Do NOT pass a floor from the envelope's own generation — the worker
						// wrapper owns the anti-replay floor (the in-session high-water-mark)
						// and injects it (useCryptoWorker.ts). Passing the blob's own
						// generation here would make the WASM freshness gate compare a value
						// against itself and never reject.
						const { identityId: id } = await cryptoWorker.mlsImportState(stateBytes);
						importedId = id;
					} catch (importErr) {
						// A present-but-rejected envelope is a genuine anomaly (corrupt or
						// tampered-at-rest, unsupported version, or — for an in-session
						// re-import — a stale-generation replay), distinct from the routine
						// "no envelope yet" case, which never reaches here (providerState
						// would be undefined). Surface only the content-free error CATEGORY
						// (never the blob, key material, or generation — no-plaintext-logging)
						// so this is observably different from a clean first login, then fall
						// back to re-deriving the signer from the seed below.
						const category =
							importErr instanceof Error && importErr.name === "MlsImportRejectedError"
								? "mls_import_rejected"
								: "mls_import_unknown";
						console.warn("mls_state_rehydration_failed", category);
						importedId = null;
						importAttemptedAndFailed = true;
					}

					if (importedId) {
						// Import SUCCEEDED — the full multi-group context is live in the worker
						// and the encrypted on-disk blob is intact. Mint a fresh KeyPackage for
						// this session. If minting/persisting the KeyPackage fails, do NOT
						// discard the successfully-imported group state by falling through to
						// mlsInitIdentity (that would reset the identity and overwrite the good
						// multi-group blob on disk with a groupless one). Keep the imported
						// identity and simply skip this session's KeyPackage upload.
						try {
							const { keyPackage, pqDecapKeyHandle: pqHandle } =
								await cryptoWorker.mlsGetKeyPackage(importedId);
							restored = { identityId: importedId, keyPackage, pqDecapKeyHandle: pqHandle };
						} catch {
							restored = { identityId: importedId };
						}
					}
				}

				if (!restored && identity.mlsIdentityB64) {
					// Each login produces a fresh identityId handle (the WASM map is
					// cleared on logout), but the signing keys are derived from the
					// same seed bytes so KeyPackages from this session are associated
					// with this device.
					const bytes = base64ToUint8Array(identity.mlsIdentityB64);
					const {
						identityId: id,
						keyPackage,
						pqDecapKeyHandle: pqHandle,
					} = await cryptoWorker.mlsInitIdentity(bytes);
					restored = { identityId: id, keyPackage, pqDecapKeyHandle: pqHandle };

					if (importAttemptedAndFailed && providerState) {
						// crypto-reviewer finding Y2: mlsInitIdentity's own persistence
						// wrapper (useCryptoWorker.ts IDENTITY_INIT_METHODS) already
						// durably overwrote the on-disk envelope with this fresh,
						// groupless identity's state as a side effect of the call
						// above. An import FAILURE (even a genuine stale/corrupt one)
						// must not forfeit the still-possibly-recoverable prior
						// envelope — only a SUCCESSFUL import may replace it. Restore
						// the pre-existing snapshot immediately after so a same-app-
						// version retry (e.g. next reload, before this fallback
						// session performs any MLS mutation) can still attempt to
						// recover the groups instead of them being unconditionally
						// lost. NOTE: this recovery window is only until the FIRST
						// ratchet-advancing op in this fallback session — the next
						// doFlush (useCryptoWorker.ts) persists the groupless state's
						// own advancing generation and overwrites this restored
						// envelope again; it is not open-ended recoverability.
						try {
							await encDb.setMlsProviderState(providerState.stateB64, providerState.generation);
						} catch {
							// Best-effort restore only — never block sign-in on this.
						}
					}
				}

				if (restored) {
					identityId = restored.identityId;
					pqDecapKeyHandle = restored.pqDecapKeyHandle;
					// Update the current session handle in the DB; don't overwrite mlsIdentityB64.
					await db.identity.update(1, { mlsIdentityId: restored.identityId });
					// Upload a fresh KeyPackage for this session (non-fatal). Absent only when
					// an import succeeded but minting this session's KeyPackage failed — the
					// imported group state is still kept (see above).
					if (restored.keyPackage) {
						uploadKeyPackage(token, device_id, restored.keyPackage).catch(() => {});
					}
				}
			}

			// Advance to app phase (sign-in path) — DB key was derived inside the crypto worker.
			login(device_id, token, identityId ?? undefined, pqDecapKeyHandle, handle.trim());
		} catch (err) {
			setPhase("error");
			if (mode === "restore-account") {
				// Anti-oracle (§8.5): collapse EVERY restore failure — bad OPAQUE
				// creds, server-rejected recovery proof, network error, whatever —
				// into one generic message. Never reveal which of handle/password/
				// phrase was wrong (same principle as invalid_credentials below).
				setErrorMsg("Restore failed. Please check your handle, password, and recovery phrase.");
			} else {
				const msg = err instanceof Error ? err.message : "unknown_error";
				if (msg === "invalid_credentials" || msg === "unauthorized") {
					setErrorMsg("Incorrect handle or password.");
				} else if (msg === "crypto_unavailable") {
					setErrorMsg("Encryption module unavailable. Please reload.");
				} else {
					setErrorMsg("Sign in failed. Please try again.");
				}
			}
		} finally {
			// F2: zero password bytes regardless of success or failure.
			pw.fill(0);
		}
	};

	const inputStyle: React.CSSProperties = {
		background: "var(--bg-input)",
		border: "1px solid var(--border-soft)",
		color: "var(--fg-1)",
		borderRadius: 12,
		padding: "13px 16px",
		fontSize: 16,
		fontFamily: "var(--font-mono)",
		letterSpacing: "0.02em",
		outline: "none",
		boxShadow: "inset 0 1px 2px rgba(0,0,0,0.55)",
		width: "100%",
		boxSizing: "border-box",
		transition: "border-color 160ms",
	};

	const labelStyle: React.CSSProperties = {
		fontSize: 11,
		fontWeight: 500,
		letterSpacing: "0.14em",
		textTransform: "uppercase",
		color: "var(--fg-3)",
		marginBottom: 6,
		display: "block",
	};

	return (
		<div
			style={{
				position: "fixed",
				inset: 0,
				background:
					"radial-gradient(ellipse 80% 60% at 50% 30%, rgba(255,138,61,0.18), transparent 60%), radial-gradient(ellipse 40% 30% at 50% 30%, rgba(168,200,255,0.08), transparent 70%), var(--bg-void)",
				display: "flex",
				alignItems: "center",
				justifyContent: "center",
				zIndex: 100,
			}}
		>
			<div
				style={{
					width: 420,
					padding: "40px 36px",
					background: "rgba(12,12,20,0.6)",
					backdropFilter: "blur(20px)",
					WebkitBackdropFilter: "blur(20px)",
					border: "1px solid var(--border-soft)",
					borderRadius: 24,
					boxShadow: "0 24px 64px rgba(0,0,0,0.75), 0 8px 16px rgba(0,0,0,0.55)",
				}}
			>
				{/* Logo */}
				<div
					style={{
						display: "flex",
						justifyContent: "center",
						marginBottom: 28,
					}}
				>
					<Logo size={72} />
				</div>

				{/* Title */}
				<h1
					style={{
						fontFamily: "var(--font-serif)",
						fontStyle: "italic",
						fontSize: 36,
						color: "var(--fg-1)",
						textAlign: "center",
						lineHeight: 1.1,
						letterSpacing: "-0.02em",
						margin: 0,
					}}
				>
					<span
						style={{
							position: "absolute",
							width: 1,
							height: 1,
							overflow: "hidden",
							clip: "rect(0,0,0,0)",
							whiteSpace: "nowrap",
						}}
					>
						Powehi
					</span>
					Past the horizon,
					<br />
					<span style={{ color: "#FFD78A" }}>only you.</span>
				</h1>

				{/* Subtitle */}
				<div
					style={{
						fontSize: 13,
						color: "var(--fg-3)",
						textAlign: "center",
						margin: "14px 0 28px",
						lineHeight: 1.5,
					}}
				>
					{mode === "create-account"
						? "Create your encrypted account. Zero knowledge."
						: mode === "restore-account"
							? "Restore your account with your password and recovery phrase."
							: "Sign in securely. We never see your messages."}
				</div>

				{/* Form */}
				<form onSubmit={handleSubmit} noValidate>
					{/* Handle field */}
					<div
						style={{
							display: "flex",
							flexDirection: "column",
							marginBottom: 16,
						}}
					>
						<label htmlFor="handle" style={labelStyle}>
							Handle
						</label>
						<input
							id="handle"
							type="text"
							autoComplete="username"
							value={handle}
							onChange={handleHandleChange}
							style={inputStyle}
							onFocus={(e) => {
								e.currentTarget.style.borderColor = "rgba(255,138,61,0.5)";
							}}
							onBlur={(e) => {
								e.currentTarget.style.borderColor = "var(--border-soft)";
							}}
						/>
					</div>

					{/* Password field */}
					<div
						style={{
							display: "flex",
							flexDirection: "column",
							marginBottom: 20,
						}}
					>
						<label htmlFor="password" style={labelStyle}>
							Password
						</label>
						<input
							id="password"
							type="password"
							autoComplete="current-password"
							value={password}
							onChange={handlePasswordChange}
							style={inputStyle}
							onFocus={(e) => {
								e.currentTarget.style.borderColor = "rgba(255,138,61,0.5)";
							}}
							onBlur={(e) => {
								e.currentTarget.style.borderColor = "var(--border-soft)";
							}}
						/>
					</div>

					{/* Recovery phrase field — restore-account mode only (§8.5) */}
					{mode === "restore-account" && (
						<div
							style={{
								display: "flex",
								flexDirection: "column",
								marginBottom: 20,
							}}
						>
							<label htmlFor="recovery-phrase" style={labelStyle}>
								Recovery phrase
							</label>
							<textarea
								id="recovery-phrase"
								autoComplete="off"
								spellCheck={false}
								value={recoveryPhrase}
								onChange={(e: ChangeEvent<HTMLTextAreaElement>) =>
									setRecoveryPhrase(e.target.value)
								}
								placeholder="Enter your 24-word recovery phrase, separated by spaces"
								style={{
									...inputStyle,
									resize: "vertical",
									minHeight: 92,
									lineHeight: 1.5,
									fontSize: 14,
								}}
								onFocus={(e) => {
									e.currentTarget.style.borderColor = "rgba(255,138,61,0.5)";
								}}
								onBlur={(e) => {
									e.currentTarget.style.borderColor = "var(--border-soft)";
								}}
							/>
						</div>
					)}

					{/* Error message */}
					{phase === "error" && errorMsg && (
						<div
							style={{
								marginBottom: 16,
								padding: "10px 14px",
								background: "var(--flare-soft)",
								border: "1px solid rgba(255,122,122,0.3)",
								borderRadius: 10,
								fontSize: 13,
								color: "var(--flare)",
								lineHeight: 1.4,
							}}
						>
							{errorMsg}
						</div>
					)}

					{/* Submit button */}
					<button
						type="submit"
						disabled={phase === "loading"}
						style={{
							width: "100%",
							padding: "13px 20px",
							fontSize: 15,
							fontFamily: "var(--font-sans)",
							fontWeight: 500,
							background:
								phase === "loading"
									? "rgba(255,138,61,0.4)"
									: "linear-gradient(180deg, #FF9E52, #FF7A2B)",
							color: "#2A0A00",
							border: "1px solid transparent",
							borderRadius: 12,
							boxShadow:
								"0 0 0 1px rgba(255,138,61,0.35), 0 0 18px rgba(255,138,61,0.25), inset 0 1px 0 rgba(255,255,255,0.25)",
							cursor: phase === "loading" ? "not-allowed" : "pointer",
							display: "flex",
							alignItems: "center",
							justifyContent: "center",
							gap: 8,
							transition: "all 200ms",
							opacity: phase === "loading" ? 0.7 : 1,
						}}
					>
						{phase === "loading" ? (
							<>
								<Spinner />
								{mode === "create-account"
									? "Creating account…"
									: mode === "restore-account"
										? "Restoring account…"
										: "Signing in…"}
							</>
						) : mode === "create-account" ? (
							"Create account"
						) : mode === "restore-account" ? (
							"Restore account"
						) : (
							"Sign in"
						)}
					</button>
				</form>

				{/* Mode toggle */}
				<div style={{ textAlign: "center", marginTop: 16 }}>
					<button
						type="button"
						onClick={() => {
							setMode(mode === "sign-in" ? "create-account" : "sign-in");
							setErrorMsg("");
							setPhase("idle");
						}}
						style={{
							background: "transparent",
							border: "none",
							color: "var(--fg-3)",
							fontSize: 13,
							fontFamily: "var(--font-sans)",
							cursor: "pointer",
							padding: 0,
						}}
					>
						{mode === "sign-in"
							? "New to Powehi? Create account"
							: "Already have an account? Sign in"}
					</button>
					{mode === "sign-in" && (
						<button
							type="button"
							onClick={() => {
								setMode("restore-account");
								setErrorMsg("");
								setPhase("idle");
							}}
							style={{
								display: "block",
								background: "transparent",
								border: "none",
								color: "var(--fg-3)",
								fontSize: 13,
								fontFamily: "var(--font-sans)",
								cursor: "pointer",
								padding: 0,
								marginTop: 10,
							}}
						>
							Lost your device? Restore with recovery phrase
						</button>
					)}
				</div>

				{/* Footer — lock icon always photon blue */}
				<div
					style={{
						marginTop: 28,
						paddingTop: 18,
						borderTop: "1px solid var(--border-faint)",
						fontSize: 11,
						color: "var(--fg-4)",
						textAlign: "center",
						display: "flex",
						alignItems: "center",
						justifyContent: "center",
						gap: 6,
					}}
				>
					<Icon name="lock" size={11} color="#A8C8FF" />
					<span style={{ letterSpacing: "0.04em" }}>End-to-end encrypted from the first byte</span>
				</div>
			</div>

			{/* §8.5 Recovery phrase confirmation — shown after registration, blocks app entry */}
			{phase === "recovery" && recoveryWords && (
				<RecoveryPhraseModal
					words={recoveryWords}
					onConfirmed={() => {
						setRecoveryWords(null);
						if (pendingLoginRef.current) {
							const { device_id, token, identityId, pqDecapKeyHandle, myHandle } =
								pendingLoginRef.current;
							pendingLoginRef.current = null;
							login(device_id, token, identityId, pqDecapKeyHandle, myHandle);
						}
					}}
				/>
			)}
		</div>
	);
}

function Spinner() {
	return (
		<svg
			width="14"
			height="14"
			viewBox="0 0 24 24"
			fill="none"
			stroke="currentColor"
			strokeWidth="2.5"
			strokeLinecap="round"
			role="img"
			aria-label="Loading"
			style={{
				animation: "spin 0.8s linear infinite",
			}}
		>
			<style>{"@keyframes spin { to { transform: rotate(360deg); } }"}</style>
			<path d="M12 2a10 10 0 0 1 10 10" />
		</svg>
	);
}
