/**
 * AcceptInviteModal — invite acceptance flow (prd.md §8.3, receiving side).
 *
 * When a user opens powehi.app/i/connect#<code>, App detects the code and
 * renders this modal. The user clicks "Connect" to:
 *   1. Redeem the one-time code → inviter's DeviceId
 *   2. Fetch the inviter's KeyPackage (single-use)
 *   3. Create a new MLS group (recipient is creator/sole member)
 *   4. Add the inviter via MLS mlsAddMember → Welcome message
 *   5. Register the group + inviter membership with the server
 *   6. Send the Welcome to the inviter
 *
 * Security invariants:
 * - The invite code travels in the request body (never URL path).
 * - The server sees only opaque UUIDs (groupId, deviceId) — never plaintext.
 * - The Welcome message is MLS ciphertext — server cannot decrypt it.
 */

import { useState } from "react";
import { addMember, createGroup } from "../api/groups";
import { redeemInvite } from "../api/invites";
import { fetchKeyPackage } from "../api/key_packages";
import { sendMessage, sendWelcome } from "../api/messages";
import { useCryptoWorker } from "../hooks/useCryptoWorker";
import { useAuthStore } from "../store/auth";
import { Icon } from "./Icon";

interface AcceptInviteModalProps {
	inviteCode: string;
	onClose: () => void;
	/** Called with the new groupId after the full accept flow succeeds. */
	onAccepted: (groupId: string) => void;
}

type Step = "idle" | "loading" | "accepted" | "error";

type ErrorKind = "expired" | "no_key_package" | "no_identity" | "generic";

function errorMessage(kind: ErrorKind): string {
	switch (kind) {
		case "expired":
			return "This invite has already been used or has expired.";
		case "no_key_package":
			return "Contact’s encryption key is unavailable. Ask them to send a new invite.";
		case "no_identity":
			return "Secure session not fully initialised. Please log out and log in again.";
		case "generic":
			return "Could not complete the connection. Please try again.";
	}
}

export function AcceptInviteModal({ inviteCode, onClose, onAccepted }: AcceptInviteModalProps) {
	const { sessionToken, deviceId, identityId } = useAuthStore();
	const cryptoWorker = useCryptoWorker();

	const [step, setStep] = useState<Step>("idle");
	const [errorKind, setErrorKind] = useState<ErrorKind>("generic");
	const [newGroupId, setNewGroupId] = useState("");
	const [pqBindingHex, setPqBindingHex] = useState<string | null>(null);

	const handleAccept = async () => {
		if (!sessionToken || !deviceId) return;
		if (!identityId || !cryptoWorker) {
			setErrorKind("no_identity");
			setStep("error");
			return;
		}

		setStep("loading");

		try {
			// Step 1: redeem the one-time code → inviter's DeviceId
			const { device_id: inviterDeviceId } = await redeemInvite(sessionToken, inviteCode);

			// Step 2: fetch inviter's KeyPackage (single-use, atomically consumed)
			let keyPackage: Uint8Array;
			try {
				keyPackage = await fetchKeyPackage(sessionToken, inviterDeviceId);
			} catch {
				setErrorKind("no_key_package");
				setStep("error");
				return;
			}

			// Step 3: create a new MLS group (this device is creator + sole member at epoch 0)
			const { groupId } = await cryptoWorker.mlsCreateGroup(identityId);

			// Step 4: add the inviter → produces a Welcome message; epoch advances to 1
			const { welcome } = await cryptoWorker.mlsAddMember(identityId, groupId, keyPackage);

			// Step 5a: register the group with the server (creator is initial member)
			await createGroup(sessionToken, groupId);

			// Step 5b: register the inviter as a server-side member at epoch 1
			await addMember(sessionToken, groupId, inviterDeviceId, 1);

			// Step 6: deliver the Welcome to the inviter (MLS ciphertext — server can't read it)
			await sendWelcome(sessionToken, groupId, welcome, inviterDeviceId);

			// Step 7 (PQ extension) — §5.3 Phase B: quantum-resistant group confirmation.
			// We encapsulate to the inviter's ML-KEM-768 key (embedded in their KeyPackage)
			// and send the ciphertext as a pq_init Application message.  The inviter decaps
			// on receipt and both sides derive the same HKDF-SHA256 binding hex.
			// All PQ steps are best-effort — failure leaves the classical E2EE channel intact.
			let derivedPqBindingHex: string | null = null;
			try {
				const members = await cryptoWorker.mlsGroupMembers(identityId, groupId);
				// Creator (us) is leaf 0; inviter is the other member.
				const peer = members.find((m) => m.leafIndex !== 0) ?? members[members.length - 1];
				const sigKeyBytes = new Uint8Array(peer.sigKeyHex.length / 2);
				for (let i = 0; i < sigKeyBytes.length; i++) {
					sigKeyBytes[i] = Number.parseInt(peer.sigKeyHex.slice(i * 2, i * 2 + 2), 16);
				}
				const { encapKey } = await cryptoWorker.mlsPqExtractAndVerifyEncapKey(
					keyPackage,
					sigKeyBytes,
				);
				const { ciphertext: pqCt, sharedSecretHandle } =
					await cryptoWorker.mlKem768EncapV2(encapKey);
				const pqPayload = JSON.stringify({ type: "pq_init", ct: Array.from(pqCt) });
				const { ciphertext: mlsCt } = await cryptoWorker.mlsEncrypt(
					identityId,
					groupId,
					new TextEncoder().encode(pqPayload),
				);
				await sendMessage(sessionToken, groupId, mlsCt);
				const { bindingHex } = await cryptoWorker.mlsPqDeriveBinding(sharedSecretHandle, groupId);
				derivedPqBindingHex = bindingHex;
			} catch {
				// PQ extension unavailable or peer has no PQ key — graceful degradation.
			}

			setNewGroupId(groupId);
			setPqBindingHex(derivedPqBindingHex);
			setStep("accepted");
		} catch (err) {
			const msg = err instanceof Error ? err.message : "";
			if (msg === "invite_not_found") {
				setErrorKind("expired");
			} else {
				setErrorKind("generic");
			}
			setStep("error");
		}
	};

	const handleClose = () => {
		setStep("idle");
		setErrorKind("generic");
		setNewGroupId("");
		setPqBindingHex(null);
		onClose();
	};

	const handleOpen = () => {
		onAccepted(newGroupId);
	};

	return (
		<dialog
			open
			aria-label="Accept contact invite"
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
				if (e.target === e.currentTarget && step !== "loading") handleClose();
			}}
			onKeyDown={(e) => {
				if (e.key === "Escape" && step !== "loading") handleClose();
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
						<Icon name="lock" size={16} color="#A8C8FF" />
						<span style={{ fontSize: 15, fontWeight: 500, color: "var(--fg-1)" }}>
							Secure invite
						</span>
					</div>
					{step !== "loading" && (
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
					)}
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
						Accepting establishes an end-to-end encrypted channel. Powehi servers never see message
						content.
					</span>
				</div>

				{/* Content by step */}
				{step === "idle" && (
					<div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
						<p style={{ margin: 0, fontSize: 13, color: "var(--fg-2)", lineHeight: 1.6 }}>
							You received a contact invite. Accepting will create a new encrypted conversation.
						</p>
						<button
							type="button"
							onClick={handleAccept}
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
							Connect
						</button>
					</div>
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
						Establishing encrypted channel…
					</div>
				)}

				{step === "accepted" && (
					<div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
						<div
							style={{
								display: "flex",
								alignItems: "center",
								gap: 8,
								padding: "12px 14px",
								background: "rgba(94,230,168,0.06)",
								border: "1px solid rgba(94,230,168,0.28)",
								borderRadius: 10,
								color: "#5EE6A8",
								fontSize: 13,
							}}
						>
							<Icon name="check" size={14} color="#5EE6A8" />
							<span>Encrypted channel established.</span>
						</div>
						{pqBindingHex && (
							<div
								style={{
									display: "flex",
									alignItems: "center",
									gap: 8,
									padding: "8px 12px",
									background: "rgba(168,200,255,0.06)",
									border: "1px solid rgba(168,200,255,0.22)",
									borderRadius: 10,
									fontSize: 11,
								}}
							>
								<Icon name="lock" size={11} color="#A8C8FF" />
								<span style={{ color: "#A8C8FF", fontWeight: 500 }}>PQ</span>
								<span style={{ color: "var(--fg-3)", fontFamily: "var(--font-mono)" }}>
									{pqBindingHex}
								</span>
							</div>
						)}
						<button
							type="button"
							data-testid="open-chat-btn"
							onClick={handleOpen}
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
							}}
						>
							Open chat
						</button>
					</div>
				)}

				{step === "error" && (
					<div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
						<div
							style={{
								padding: "12px 14px",
								background: "rgba(255,100,100,0.08)",
								border: "1px solid rgba(255,100,100,0.3)",
								borderRadius: 10,
								color: "#FF9999",
								fontSize: 13,
								lineHeight: 1.5,
							}}
						>
							{errorMessage(errorKind)}
						</div>
						<button
							type="button"
							onClick={handleClose}
							style={{
								width: "100%",
								padding: "11px 0",
								background: "var(--bg-elevated)",
								border: "1px solid var(--border-soft)",
								borderRadius: 10,
								color: "var(--fg-1)",
								fontSize: 13,
								fontWeight: 500,
								fontFamily: "var(--font-sans)",
								cursor: "pointer",
							}}
						>
							Close
						</button>
					</div>
				)}
			</div>
		</dialog>
	);
}
