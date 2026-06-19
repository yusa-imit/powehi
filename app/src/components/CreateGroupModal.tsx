import { useCallback, useEffect, useState } from "react";
import { createGroup } from "../api/groups";
import { useCryptoWorker } from "../hooks/useCryptoWorker";
import { useAuthStore } from "../store/auth";
import { Icon } from "./Icon";

interface CreateGroupModalProps {
	open: boolean;
	onClose: () => void;
	onGroupCreated: (groupId: string, groupName: string) => void;
}

type Step = "idle" | "loading" | "error";

export function CreateGroupModal({ open, onClose, onGroupCreated }: CreateGroupModalProps) {
	const { sessionToken, identityId } = useAuthStore();
	const cryptoWorker = useCryptoWorker();
	const [groupName, setGroupName] = useState("");
	const [step, setStep] = useState<Step>("idle");
	const [nameError, setNameError] = useState("");
	const [apiError, setApiError] = useState("");

	// Reset state when modal opens/closes
	useEffect(() => {
		if (!open) {
			setGroupName("");
			setStep("idle");
			setNameError("");
			setApiError("");
		}
	}, [open]);

	const handleClose = useCallback(() => {
		setGroupName("");
		setStep("idle");
		setNameError("");
		setApiError("");
		onClose();
	}, [onClose]);

	useEffect(() => {
		const handleKeyDown = (e: KeyboardEvent) => {
			if (e.key === "Escape") handleClose();
		};
		if (open) {
			document.addEventListener("keydown", handleKeyDown);
		}
		return () => {
			document.removeEventListener("keydown", handleKeyDown);
		};
	}, [open, handleClose]);

	const handleSubmit = async () => {
		const trimmed = groupName.trim();
		if (!trimmed || trimmed.length > 50) {
			setNameError("Group name must be 1–50 characters.");
			return;
		}
		setNameError("");

		if (!sessionToken || !identityId || !cryptoWorker) {
			setApiError("Identity not available. Please try again.");
			return;
		}

		setStep("loading");
		setApiError("");

		try {
			const { groupId } = await cryptoWorker.mlsCreateGroup(identityId);
			await createGroup(sessionToken, groupId);
			setStep("idle");
			onGroupCreated(groupId, trimmed);
		} catch {
			// Error category only — no plaintext payload logged (no-plaintext-logging invariant)
			setStep("error");
			setApiError("Failed to create group. Please try again.");
		}
	};

	if (!open) return null;

	return (
		<dialog
			open
			aria-label="New group"
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
						<Icon name="users" size={18} color="var(--fg-2)" />
						<span style={{ fontSize: 15, fontWeight: 500, color: "var(--fg-1)" }}>New group</span>
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
						Group name stays on your device. Only encrypted messages reach the server.
					</span>
				</div>

				{/* Group name input */}
				<div style={{ marginBottom: 16 }}>
					<input
						data-testid="group-name-input"
						type="text"
						value={groupName}
						onChange={(e) => {
							setGroupName(e.target.value);
							if (nameError) setNameError("");
						}}
						placeholder="Group name"
						maxLength={50}
						disabled={step === "loading"}
						style={{
							width: "100%",
							padding: "11px 14px",
							background: "var(--bg-elevated)",
							border: `1px solid ${nameError ? "rgba(255,100,100,0.5)" : "var(--border-soft)"}`,
							borderRadius: 10,
							color: "var(--fg-1)",
							fontFamily: "var(--font-sans)",
							fontSize: 14,
							outline: "none",
							boxSizing: "border-box",
						}}
					/>
					{nameError && (
						<div
							data-testid="group-name-error"
							style={{
								marginTop: 6,
								fontSize: 12,
								color: "#FF9999",
							}}
						>
							{nameError}
						</div>
					)}
				</div>

				{/* API error */}
				{apiError && (
					<div
						data-testid="create-group-error"
						style={{
							padding: "10px 14px",
							background: "rgba(255,100,100,0.08)",
							border: "1px solid rgba(255,100,100,0.3)",
							borderRadius: 10,
							color: "#FF9999",
							fontSize: 13,
							marginBottom: 16,
						}}
					>
						{apiError}
					</div>
				)}

				{/* Submit */}
				<button
					type="button"
					data-testid="create-group-submit"
					onClick={handleSubmit}
					disabled={step === "loading"}
					style={{
						width: "100%",
						padding: "12px 0",
						background:
							!groupName.trim() || step === "loading"
								? "rgba(255,138,61,0.3)"
								: "linear-gradient(180deg, #FF9E52, #FF7A2B)",
						border: "none",
						borderRadius: 12,
						color: !groupName.trim() || step === "loading" ? "rgba(42,17,0,0.5)" : "#2A0A00",
						fontSize: 14,
						fontWeight: 600,
						fontFamily: "var(--font-sans)",
						cursor: !groupName.trim() || step === "loading" ? "not-allowed" : "pointer",
						boxShadow:
							!groupName.trim() || step === "loading"
								? "none"
								: "0 0 0 1px rgba(255,138,61,0.35), 0 0 14px rgba(255,138,61,0.18)",
					}}
				>
					{step === "loading" ? "Creating…" : "Create group"}
				</button>
			</div>
		</dialog>
	);
}
