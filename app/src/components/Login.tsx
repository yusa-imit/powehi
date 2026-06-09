import { type ChangeEvent, type FormEvent, useState } from "react";
import {
	hashHandle,
	loginFinish,
	loginInit,
	regFinish,
	regInit,
	uploadKeyPackage,
} from "../api/auth";
import { db } from "../db/schema";
import { useCryptoWorker } from "../hooks/useCryptoWorker";
import { useAuthStore } from "../store/auth";
import { base64ToUint8Array, uint8ToBase64 } from "../utils/base64";
import { Icon } from "./Icon";

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

type LoginPhase = "idle" | "loading" | "error";
type Mode = "sign-in" | "create-account";

export function Login() {
	const login = useAuthStore((s) => s.login);
	const cryptoWorker = useCryptoWorker();

	const [handle, setHandle] = useState("");
	const [password, setPassword] = useState("");
	const [phase, setPhase] = useState<LoginPhase>("idle");
	const [errorMsg, setErrorMsg] = useState("");
	const [mode, setMode] = useState<Mode>("sign-in");

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
	): Promise<{ device_id: string; token: string; identityId: string }> => {
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

		// Step 4: MLS identity init — random 16-byte BasicCredential identity (RFC 9420 §5.3).
		// The identity bytes are a PUBLIC label (included in KeyPackages), not a secret.
		const mlsIdentityBytes = crypto.getRandomValues(new Uint8Array(16));
		const { identityId, keyPackage } = await cryptoWorker.mlsInitIdentity(mlsIdentityBytes);

		// Step 5: server registration finish — creates user + device
		const finishResp = await regFinish(initResp.user_id, opaque_record, mlsIdentityBytes);

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

		return { device_id: finishResp.device_id, token, identityId };
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

		try {
			const handle_hash = await hashHandle(handle.trim());

			let device_id: string;
			let token: string;
			let identityId: string | null = null;

			if (mode === "create-account") {
				const result = await doRegister(pw, handle_hash);
				device_id = result.device_id;
				token = result.token;
				identityId = result.identityId;
				// doRegister persists the identity record (including mlsIdentityB64).
			} else {
				// Load stored device_id and MLS identity bytes from IndexedDB.
				const identity = await db.identity.get(1);
				if (!identity?.deviceId) {
					setPhase("error");
					setErrorMsg("No device registered on this browser. Create an account first.");
					return;
				}
				device_id = identity.deviceId;
				({ token } = await doLogin(pw, handle_hash, device_id));

				// Re-initialise MLS identity in the WASM worker using stored bytes.
				// Each login produces a fresh identityId handle (the WASM map is cleared
				// on logout), but the signing keys are derived from the same seed bytes
				// so KeyPackages from this session are associated with this device.
				if (identity.mlsIdentityB64 && cryptoWorker) {
					const bytes = base64ToUint8Array(identity.mlsIdentityB64);
					const { identityId: id, keyPackage } = await cryptoWorker.mlsInitIdentity(bytes);
					identityId = id;
					// Update the current session handle in the DB; don't overwrite mlsIdentityB64.
					await db.identity.update(1, { mlsIdentityId: id });
					// Upload a fresh KeyPackage for this session (non-fatal).
					uploadKeyPackage(token, device_id, keyPackage).catch(() => {});
				}
			}

			// Advance to app phase — DB key was derived inside the crypto worker.
			login(device_id, token, identityId ?? undefined);
		} catch (err) {
			setPhase("error");
			const msg = err instanceof Error ? err.message : "unknown_error";
			if (msg === "invalid_credentials" || msg === "unauthorized") {
				setErrorMsg("Incorrect handle or password.");
			} else if (msg === "crypto_unavailable") {
				setErrorMsg("Encryption module unavailable. Please reload.");
			} else {
				setErrorMsg("Sign in failed. Please try again.");
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
								{mode === "create-account" ? "Creating account…" : "Signing in…"}
							</>
						) : mode === "create-account" ? (
							"Create account"
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
