import { useCallback, useEffect, useState } from "react";
import { addMember } from "../api/groups";
import { useAuthStore } from "../store/auth";
import { Icon } from "./Icon";

export interface ContactEntry {
	id: string;
	name: string;
}

interface AddMemberModalProps {
	open: boolean;
	onClose: () => void;
	groupId: string;
	groupName: string;
	contacts: ContactEntry[];
	onMemberAdded: (contactId: string, contactName: string) => void;
}

type Step = "idle" | "loading" | "error";

export function AddMemberModal({
	open,
	onClose,
	groupId,
	groupName,
	contacts,
	onMemberAdded,
}: AddMemberModalProps) {
	const { sessionToken } = useAuthStore();
	const [step, setStep] = useState<Step>("idle");
	const [apiError, setApiError] = useState("");

	useEffect(() => {
		if (!open) {
			setStep("idle");
			setApiError("");
		}
	}, [open]);

	const handleClose = useCallback(() => {
		setStep("idle");
		setApiError("");
		onClose();
	}, [onClose]);

	useEffect(() => {
		const handleKeyDown = (e: KeyboardEvent) => {
			if (e.key === "Escape") handleClose();
		};
		if (open) document.addEventListener("keydown", handleKeyDown);
		return () => document.removeEventListener("keydown", handleKeyDown);
	}, [open, handleClose]);

	const handleAdd = async (contact: ContactEntry) => {
		if (!sessionToken) {
			setApiError("Session expired. Please reload.");
			return;
		}
		setStep("loading");
		setApiError("");
		try {
			await addMember(sessionToken, groupId, contact.id, 0);
			setStep("idle");
			onMemberAdded(contact.id, contact.name);
			handleClose();
		} catch {
			// Error category only — no plaintext content logged (no-plaintext-logging invariant)
			setStep("error");
			setApiError("Failed to add member. Please try again.");
		}
	};

	if (!open) return null;

	return (
		<dialog
			open
			aria-label="Add member"
			data-testid="add-member-modal"
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
					width: 360,
					maxWidth: "calc(100vw - 48px)",
					boxShadow: "0 24px 80px rgba(0,0,0,0.56)",
				}}
				onClick={(e) => e.stopPropagation()}
				onKeyDown={(e) => {
					if (e.key !== "Escape") e.stopPropagation();
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
						<Icon name="user-plus" size={18} color="var(--fg-2)" />
						<span style={{ fontSize: 15, fontWeight: 500, color: "var(--fg-1)" }}>Add member</span>
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

				{/* Group name — server never sees this; displayed for user orientation only */}
				<div
					style={{
						fontSize: 12,
						color: "var(--fg-3)",
						marginBottom: 16,
						fontStyle: "italic",
					}}
				>
					Adding to{" "}
					<span style={{ color: "var(--fg-2)", fontStyle: "normal", fontWeight: 500 }}>
						{groupName}
					</span>
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
						marginBottom: 16,
					}}
				>
					<Icon name="lock" size={12} color="#A8C8FF" />
					<span style={{ fontSize: 12, color: "#C8DCFF", lineHeight: 1.45 }}>
						The member receives an encrypted Welcome message. Their identity is never sent in
						plaintext.
					</span>
				</div>

				{/* Contact list */}
				{contacts.length === 0 ? (
					<div
						data-testid="no-contacts-message"
						style={{
							padding: "20px 0",
							textAlign: "center",
							color: "var(--fg-3)",
							fontSize: 13,
						}}
					>
						No contacts to add. Invite someone first.
					</div>
				) : (
					<div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
						{contacts.map((c) => (
							<button
								key={c.id}
								type="button"
								data-testid="contact-option"
								disabled={step === "loading"}
								onClick={() => handleAdd(c)}
								style={{
									display: "flex",
									alignItems: "center",
									gap: 12,
									padding: "10px 14px",
									background: "var(--bg-elevated)",
									border: "1px solid var(--border-faint)",
									borderRadius: 10,
									color: "var(--fg-1)",
									fontSize: 14,
									fontFamily: "var(--font-sans)",
									cursor: step === "loading" ? "not-allowed" : "pointer",
									textAlign: "left",
									opacity: step === "loading" ? 0.6 : 1,
								}}
							>
								<Icon name="user" size={16} color="var(--fg-3)" />
								{c.name}
							</button>
						))}
					</div>
				)}

				{/* Error state */}
				{step === "error" && (
					<div
						data-testid="add-member-error"
						style={{
							marginTop: 12,
							padding: "10px 14px",
							background: "rgba(255,100,100,0.08)",
							border: "1px solid rgba(255,100,100,0.3)",
							borderRadius: 10,
							color: "#FF9999",
							fontSize: 13,
						}}
					>
						{apiError}
					</div>
				)}

				{/* Loading indicator */}
				{step === "loading" && (
					<div
						style={{
							marginTop: 12,
							textAlign: "center",
							color: "var(--fg-3)",
							fontSize: 13,
						}}
					>
						Adding member…
					</div>
				)}
			</div>
		</dialog>
	);
}
