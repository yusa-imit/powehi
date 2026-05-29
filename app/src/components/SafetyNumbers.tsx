// SafetyNumbers — displays MLS identity verification fingerprint.
//
// The safety number is an 83-character string of 12 six-digit decimal groups
// (e.g. "689053 337949 ...") derived client-side from the two parties'
// Ed25519 signature public keys via SHA-512 (prd.md §5.6).  Comparing this number out-of-band
// (in person, over a call) gives cryptographic proof that no MITM is present.
//
// This component is purely presentational: it receives the already-computed
// safety number and a verified state, and calls back on user actions.

import { useState } from "react";
import { Icon } from "./Icon";

interface SafetyNumbersProps {
	safetyNumber: string; // "12345 67890 12345 67890 12345 67890 12345 67890 12345 67890 12345 67890"
	peerName: string;
	verified: boolean;
	verifiedAt?: number; // ms timestamp — shown as relative date when verified
	onVerify: () => void;
	onReset?: () => void; // allow re-verification after key change
}

function relativeDate(ms: number): string {
	const diff = Date.now() - ms;
	const days = Math.floor(diff / 86_400_000);
	if (days === 0) return "today";
	if (days === 1) return "yesterday";
	if (days < 7) return `${days} days ago`;
	if (days < 30) return `${Math.floor(days / 7)} weeks ago`;
	return `${Math.floor(days / 30)} months ago`;
}

export function SafetyNumbers({
	safetyNumber,
	peerName,
	verified,
	verifiedAt,
	onVerify,
	onReset,
}: SafetyNumbersProps) {
	const [confirmVisible, setConfirmVisible] = useState(false);
	const groups = safetyNumber.split(" ");

	const handleVerifyClick = () => {
		if (verified && onReset) {
			onReset();
		} else {
			setConfirmVisible(true);
		}
	};

	const handleConfirm = () => {
		setConfirmVisible(false);
		onVerify();
	};

	return (
		<div data-testid="safety-numbers">
			{/* Verified badge / status */}
			<div
				style={{
					display: "flex",
					alignItems: "center",
					gap: 8,
					marginBottom: 12,
				}}
			>
				<div
					style={{
						width: 28,
						height: 28,
						borderRadius: 8,
						background: verified
							? "rgba(168,200,255,0.18)"
							: "rgba(168,200,255,0.06)",
						display: "flex",
						alignItems: "center",
						justifyContent: "center",
					}}
				>
					<Icon name={verified ? "lock" : "shield"} size={14} color="#A8C8FF" />
				</div>
				<div>
					<div style={{ fontSize: 12, fontWeight: 500, color: "var(--fg-1)" }}>
						{verified ? "Identity verified" : "Not yet verified"}
					</div>
					{verified && verifiedAt != null && (
						<div style={{ fontSize: 10, color: "var(--fg-3)", marginTop: 1 }}>
							Verified {relativeDate(verifiedAt)}
						</div>
					)}
				</div>
			</div>

			{/* Safety number grid — 4 columns × 3 rows */}
			<div
				role="group"
				aria-label={`Safety number with ${peerName}`}
				style={{
					display: "grid",
					gridTemplateColumns: "repeat(4, 1fr)",
					gap: 4,
					marginBottom: 10,
				}}
			>
				{groups.map((block, i) => (
					<div
						key={i}
						style={{
							fontFamily: "var(--font-mono)",
							fontSize: 12,
							fontWeight: 500,
							letterSpacing: "0.04em",
							color: verified ? "#A8C8FF" : "var(--fg-2)",
							background: "var(--bg-input)",
							border: `1px solid ${verified ? "rgba(168,200,255,0.22)" : "var(--border-faint)"}`,
							borderRadius: 6,
							padding: "5px 0",
							textAlign: "center",
						}}
					>
						{block}
					</div>
				))}
			</div>

			{/* Confirm prompt (inline) */}
			{confirmVisible ? (
				<div
					style={{
						background: "rgba(168,200,255,0.06)",
						border: "1px solid rgba(168,200,255,0.22)",
						borderRadius: 9,
						padding: "10px 12px",
						marginBottom: 6,
					}}
				>
					<div style={{ fontSize: 12, color: "var(--fg-1)", marginBottom: 8 }}>
						Compare the numbers with {peerName} in person or over a call. Match?
					</div>
					<div style={{ display: "flex", gap: 6 }}>
						<button
							type="button"
							aria-label="Confirm match"
							onClick={handleConfirm}
							style={{
								flex: 1,
								background: "rgba(168,200,255,0.14)",
								border: "1px solid rgba(168,200,255,0.3)",
								color: "#C8DCFF",
								borderRadius: 7,
								padding: "6px",
								fontFamily: "var(--font-sans)",
								fontSize: 12,
								fontWeight: 500,
								cursor: "pointer",
							}}
						>
							They match
						</button>
						<button
							type="button"
							aria-label="Cancel verification"
							onClick={() => setConfirmVisible(false)}
							style={{
								flex: 1,
								background: "transparent",
								border: "1px solid var(--border-soft)",
								color: "var(--fg-2)",
								borderRadius: 7,
								padding: "6px",
								fontFamily: "var(--font-sans)",
								fontSize: 12,
								fontWeight: 500,
								cursor: "pointer",
							}}
						>
							Cancel
						</button>
					</div>
				</div>
			) : (
				<button
					type="button"
					aria-label={verified ? "Re-verify safety numbers" : "Verify safety numbers"}
					onClick={handleVerifyClick}
					style={{
						width: "100%",
						background: "transparent",
						border: `1px solid ${verified ? "rgba(168,200,255,0.2)" : "rgba(168,200,255,0.3)"}`,
						color: verified ? "var(--fg-3)" : "#C8DCFF",
						borderRadius: 9,
						padding: "7px",
						fontFamily: "var(--font-sans)",
						fontSize: 12,
						fontWeight: 500,
						cursor: "pointer",
					}}
				>
					{verified ? "Compare again" : "Compare in person"}
				</button>
			)}
		</div>
	);
}
