import { type ChangeEvent, type FormEvent, useState } from "react";
import { useCryptoWorker } from "../hooks/useCryptoWorker";
import { useAuthStore } from "../store/auth";
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

export function Login() {
	const login = useAuthStore((s) => s.login);
	const cryptoWorker = useCryptoWorker();

	const [handle, setHandle] = useState("");
	const [password, setPassword] = useState("");
	const [phase, setPhase] = useState<LoginPhase>("idle");
	const [errorMsg, setErrorMsg] = useState("");

	const handleHandleChange = (e: ChangeEvent<HTMLInputElement>) => {
		setHandle(e.target.value);
	};

	const handlePasswordChange = (e: ChangeEvent<HTMLInputElement>) => {
		setPassword(e.target.value);
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

		try {
			if (cryptoWorker) {
				// Real OPAQUE login flow — worker does the WASM heavy lifting.
				// Phase 4 mock: the server endpoint is not yet live so we simulate.
				// In production this exchanges opaqueLoginStart/Finish with the server.
				const encoder = new TextEncoder();
				await cryptoWorker.opaqueLoginStart(encoder.encode(password));
				// Server round-trip would happen here; for now we accept the mock.
			}
			// Success — advance to app phase.
			login("mock-device-id");
		} catch {
			setPhase("error");
			setErrorMsg("Sign in failed. Check your handle and password.");
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
					Sign in securely. We never see your messages.
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
								Signing in…
							</>
						) : (
							"Sign in"
						)}
					</button>
				</form>

				{/* Ghost link */}
				<div style={{ textAlign: "center", marginTop: 16 }}>
					<button
						type="button"
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
						New to Powehi? Create account
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
