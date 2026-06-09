/**
 * RecoveryPhraseModal — BIP-39 recovery phrase display after registration (prd.md §8.5).
 *
 * Security invariants:
 * - Modal is NOT dismissible without user confirming they have saved the words.
 * - Words appear ONLY as visible text content — no data-* attributes, no aria labels
 *   containing word content, no console.log calls.
 * - The parent MUST NOT store the joined phrase string in React state. Only the
 *   words array is passed here for display; the phrase itself goes out of scope in Login.
 * - Lock icon is always photon blue (#A8C8FF) per DESIGN.md brand rules.
 * - Confirm button uses accretion orange (action role, DESIGN.md dual-light system).
 * - Copy button uses photon blue (encryption-related element, DESIGN.md).
 */

import { useState } from "react";
import { Icon } from "./Icon";

export interface RecoveryPhraseModalProps {
	/** Exactly 24 BIP-39 words. */
	words: string[];
	/** Called after the user clicks "I have saved my recovery phrase". */
	onConfirmed: () => void;
}

export function RecoveryPhraseModal({ words, onConfirmed }: RecoveryPhraseModalProps) {
	const [copied, setCopied] = useState(false);

	const handleCopy = async () => {
		await navigator.clipboard.writeText(words.join(" "));
		setCopied(true);
		setTimeout(() => setCopied(false), 2000);
	};

	return (
		<dialog
			open
			aria-label="Recovery phrase"
			aria-modal="true"
			style={{
				position: "fixed",
				inset: 0,
				width: "100vw",
				height: "100vh",
				maxWidth: "100vw",
				maxHeight: "100vh",
				display: "flex",
				alignItems: "center",
				justifyContent: "center",
				background: "rgba(4,4,8,0.88)",
				zIndex: 200,
				border: "none",
				padding: 0,
				margin: 0,
				// No onClick on the backdrop — modal must not be dismissible without confirmation.
			}}
		>
			<div
				style={{
					background: "var(--bg-surface)",
					border: "1px solid var(--border-photon)",
					borderRadius: 20,
					padding: "32px 28px 28px",
					width: 560,
					maxWidth: "calc(100vw - 32px)",
					maxHeight: "calc(100vh - 32px)",
					overflowY: "auto",
					boxShadow:
						"0 24px 80px rgba(0,0,0,0.72), 0 0 0 1px rgba(168,200,255,0.12), var(--glow-photon-soft)",
				}}
			>
				{/* Header */}
				<div
					style={{
						display: "flex",
						alignItems: "center",
						gap: 10,
						marginBottom: 20,
					}}
				>
					<Icon name="lock" size={18} color="#A8C8FF" />
					<span
						style={{
							fontSize: 17,
							fontWeight: 600,
							color: "var(--fg-1)",
							fontFamily: "var(--font-sans)",
							letterSpacing: "-0.01em",
						}}
					>
						Your recovery phrase
					</span>
				</div>

				{/* Warning banner */}
				<div
					role="alert"
					style={{
						display: "flex",
						alignItems: "flex-start",
						gap: 10,
						padding: "12px 14px",
						background: "rgba(168,200,255,0.06)",
						border: "1px solid rgba(168,200,255,0.22)",
						borderRadius: 12,
						marginBottom: 24,
					}}
				>
					<Icon name="lock" size={13} color="#A8C8FF" />
					<p
						style={{
							margin: 0,
							fontSize: 13,
							color: "#C8DCFF",
							lineHeight: 1.55,
							fontFamily: "var(--font-sans)",
						}}
					>
						These 24 words are the ONLY way to recover your account on a new device. Save them
						somewhere safe — they will not be shown again.
					</p>
				</div>

				{/* 24-word grid — 4 columns */}
				<div
					aria-label="Recovery words"
					style={{
						display: "grid",
						gridTemplateColumns: "repeat(4, 1fr)",
						gap: "8px 12px",
						marginBottom: 20,
					}}
				>
					{words.map((word, index) => (
						<div
							// biome-ignore lint/suspicious/noArrayIndexKey: word list is ordered and static
							key={index}
							style={{
								display: "flex",
								alignItems: "baseline",
								gap: 6,
								padding: "7px 10px",
								background: "var(--bg-elevated)",
								border: "1px solid var(--border-soft)",
								borderRadius: 8,
							}}
						>
							<span
								style={{
									fontSize: 10,
									fontFamily: "var(--font-mono)",
									color: "var(--fg-4)",
									minWidth: 16,
									userSelect: "none",
								}}
							>
								{index + 1}
							</span>
							<span
								style={{
									fontSize: 13,
									fontFamily: "var(--font-mono)",
									color: "var(--fg-1)",
									letterSpacing: "0.01em",
								}}
							>
								{word}
							</span>
						</div>
					))}
				</div>

				{/* Copy button — photon blue (encryption-related element) */}
				<button
					type="button"
					onClick={handleCopy}
					style={{
						width: "100%",
						padding: "10px 16px",
						marginBottom: 12,
						background: copied ? "rgba(168,200,255,0.14)" : "rgba(168,200,255,0.08)",
						border: "1px solid rgba(168,200,255,0.28)",
						borderRadius: 10,
						color: "#A8C8FF",
						fontSize: 13,
						fontWeight: 500,
						fontFamily: "var(--font-sans)",
						cursor: "pointer",
						display: "flex",
						alignItems: "center",
						justifyContent: "center",
						gap: 8,
						transition: "background 160ms, color 160ms",
					}}
				>
					<Icon name={copied ? "check" : "copy"} size={13} color={copied ? "#5EE6A8" : "#A8C8FF"} />
					{copied ? "Copied!" : "Copy all words"}
				</button>

				{/* Confirm button — accretion orange (action role) */}
				<button
					type="button"
					onClick={onConfirmed}
					style={{
						width: "100%",
						padding: "13px 20px",
						background: "linear-gradient(180deg, #FF9E52, #FF7A2B)",
						border: "none",
						borderRadius: 12,
						color: "#2A0A00",
						fontSize: 15,
						fontWeight: 600,
						fontFamily: "var(--font-sans)",
						cursor: "pointer",
						boxShadow:
							"0 0 0 1px rgba(255,138,61,0.35), 0 0 18px rgba(255,138,61,0.22), inset 0 1px 0 rgba(255,255,255,0.2)",
						transition: "opacity 160ms",
					}}
				>
					I have saved my recovery phrase
				</button>
			</div>
		</dialog>
	);
}
