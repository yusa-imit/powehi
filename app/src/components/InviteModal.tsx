import QRCode from "qrcode";
import { useEffect, useState } from "react";
import { buildInviteUrl, createInvite } from "../api/invites";
import { useAuthStore } from "../store/auth";
import { Icon } from "./Icon";

interface InviteModalProps {
	open: boolean;
	onClose: () => void;
}

type Step = "idle" | "loading" | "ready" | "error";

export function InviteModal({ open, onClose }: InviteModalProps) {
	const { sessionToken } = useAuthStore();
	const [step, setStep] = useState<Step>("idle");
	const [inviteUrl, setInviteUrl] = useState("");
	const [copied, setCopied] = useState(false);
	const [qrDataUrl, setQrDataUrl] = useState("");

	const handleCreate = async () => {
		if (!sessionToken) return;
		setStep("loading");
		try {
			const { code } = await createInvite(sessionToken);
			const url = buildInviteUrl(window.location.origin, code);
			setInviteUrl(url);
			setStep("ready");
		} catch {
			setStep("error");
		}
	};

	const handleCopy = async () => {
		try {
			await navigator.clipboard.writeText(inviteUrl);
			setCopied(true);
			setTimeout(() => setCopied(false), 2000);
		} catch {
			// clipboard unavailable — do nothing
		}
	};

	const handleClose = () => {
		setStep("idle");
		setInviteUrl("");
		setCopied(false);
		setQrDataUrl("");
		onClose();
	};

	useEffect(() => {
		if (!inviteUrl) return;
		let cancelled = false;
		QRCode.toDataURL(inviteUrl, {
			width: 200,
			margin: 2,
			color: { dark: "#F2EDE3", light: "#040408" },
		})
			.then((url) => {
				if (!cancelled) setQrDataUrl(url);
			})
			.catch(() => {
				// QR generation failed — modal remains usable via the text link
			});
		return () => {
			cancelled = true;
		};
	}, [inviteUrl]);

	if (!open) return null;

	return (
		<dialog
			open
			aria-label="New contact invite"
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
				background: "rgba(4,4,8,0.72)",
				zIndex: 100,
				border: "none",
				padding: 0,
				margin: 0,
			}}
			onClick={(e) => {
				if (e.target === e.currentTarget) handleClose();
			}}
			onKeyDown={(e) => {
				if (e.key === "Escape") handleClose();
			}}
		>
			<div
				style={{
					background: "var(--bg-surface)",
					border: "1px solid var(--border-soft)",
					borderRadius: 18,
					padding: "28px 28px 24px",
					width: 420,
					maxWidth: "calc(100vw - 48px)",
					boxShadow: "0 24px 80px rgba(0,0,0,0.56)",
				}}
			>
				{/* Header */}
				<div
					style={{
						display: "flex",
						alignItems: "center",
						justifyContent: "space-between",
						marginBottom: 20,
					}}
				>
					<div style={{ display: "flex", alignItems: "center", gap: 10 }}>
						<Icon name="plus" size={18} color="var(--fg-2)" />
						<span style={{ fontSize: 15, fontWeight: 500, color: "var(--fg-1)" }}>New contact</span>
					</div>
					<button
						type="button"
						aria-label="Close"
						onClick={handleClose}
						style={{
							width: 28,
							height: 28,
							borderRadius: 8,
							background: "transparent",
							border: "none",
							color: "var(--fg-3)",
							display: "flex",
							alignItems: "center",
							justifyContent: "center",
							cursor: "pointer",
						}}
					>
						<Icon name="x" size={14} />
					</button>
				</div>

				{/* E2EE notice */}
				<div
					style={{
						display: "flex",
						alignItems: "center",
						gap: 8,
						padding: "10px 14px",
						background: "rgba(168,200,255,0.05)",
						border: "1px solid rgba(168,200,255,0.16)",
						borderRadius: 10,
						marginBottom: 20,
					}}
				>
					<Icon name="lock" size={12} color="#A8C8FF" />
					<span style={{ fontSize: 12, color: "#C8DCFF", lineHeight: 1.45 }}>
						Share this one-time link. The contact code is in the{" "}
						<span style={{ fontFamily: "var(--font-mono)", opacity: 0.85 }}>#fragment</span> —
						Powehi servers never see it.
					</span>
				</div>

				{/* Content */}
				{step === "idle" && (
					<button
						type="button"
						onClick={handleCreate}
						style={{
							width: "100%",
							padding: "12px 0",
							background: "linear-gradient(180deg, #FF9E52, #FF7A2B)",
							border: "none",
							borderRadius: 12,
							color: "#2A0A00",
							fontSize: 14,
							fontWeight: 600,
							fontFamily: "var(--font-sans)",
							cursor: "pointer",
							boxShadow: "0 0 0 1px rgba(255,138,61,0.35), 0 0 14px rgba(255,138,61,0.18)",
						}}
					>
						Create invite link
					</button>
				)}

				{step === "loading" && (
					<div
						style={{
							padding: "20px 0",
							textAlign: "center",
							color: "var(--fg-3)",
							fontSize: 13,
						}}
					>
						Generating secure link…
					</div>
				)}

				{step === "error" && (
					<div
						style={{
							padding: "12px 14px",
							background: "rgba(255,100,100,0.08)",
							border: "1px solid rgba(255,100,100,0.3)",
							borderRadius: 10,
							color: "#FF9999",
							fontSize: 13,
						}}
					>
						Could not create invite link. Please try again.
					</div>
				)}

				{step === "ready" && (
					<div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
						{qrDataUrl && (
							<div
								style={{
									display: "flex",
									flexDirection: "column",
									alignItems: "center",
									gap: 8,
								}}
							>
								<img
									src={qrDataUrl}
									alt="QR code for invite link"
									data-testid="invite-qr"
									width={200}
									height={200}
									style={{ borderRadius: 10, imageRendering: "pixelated" }}
								/>
								<span
									style={{
										fontSize: 11,
										color: "var(--fg-4)",
										letterSpacing: "0.04em",
									}}
								>
									Scan to add contact
								</span>
							</div>
						)}
						<div
							style={{
								background: "var(--bg-elevated)",
								border: "1px solid var(--border-faint)",
								borderRadius: 10,
								padding: "10px 14px",
							}}
						>
							<div
								style={{
									fontSize: 11,
									color: "var(--fg-3)",
									letterSpacing: "0.06em",
									marginBottom: 6,
								}}
							>
								INVITE LINK — VALID 24 HOURS · ONE USE
							</div>
							<div
								data-testid="invite-url"
								style={{
									fontSize: 12,
									fontFamily: "var(--font-mono)",
									color: "var(--fg-2)",
									wordBreak: "break-all",
									lineHeight: 1.5,
								}}
							>
								{inviteUrl}
							</div>
						</div>

						<button
							type="button"
							onClick={handleCopy}
							aria-label="Copy invite link"
							style={{
								width: "100%",
								padding: "11px 0",
								background: copied ? "rgba(94,230,168,0.12)" : "var(--bg-elevated)",
								border: `1px solid ${copied ? "rgba(94,230,168,0.4)" : "var(--border-soft)"}`,
								borderRadius: 10,
								color: copied ? "#5EE6A8" : "var(--fg-1)",
								fontSize: 13,
								fontWeight: 500,
								fontFamily: "var(--font-sans)",
								cursor: "pointer",
								display: "flex",
								alignItems: "center",
								justifyContent: "center",
								gap: 8,
								transition: "all 200ms",
							}}
						>
							<Icon name={copied ? "check" : "copy"} size={14} />
							{copied ? "Copied!" : "Copy link"}
						</button>

						<div
							style={{
								fontSize: 11,
								color: "var(--fg-4)",
								textAlign: "center",
								lineHeight: 1.5,
							}}
						>
							When your contact opens this link, they can add you. Each link expires after one use
							or 24 hours.
						</div>
					</div>
				)}
			</div>
		</dialog>
	);
}
