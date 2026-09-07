/**
 * PendingRemovalBanner — surfaces server-tracked "pending MLS Remove" requests
 * for the currently open group.
 *
 * Trust boundary (prd.md §5.4): the server holds no MLS group state or keys,
 * so it can never construct or verify a Remove commit — this signal is a
 * REQUEST, never a proof, and a malicious/compromised server operator can
 * forge it to trick a user into evicting a legitimate device (prd.md §3.5.1
 * T3). There is no local cross-check yet (no group-scoped device-list
 * endpoint is wired), so the per-device human confirmation click is
 * currently the ONLY defense — the UI says so explicitly.
 *
 * IMPORTANT: confirming here only calls `removeMember`, which is server-side
 * `group_members` routing bookkeeping (stops future envelope fan-out to that
 * device) — it is NOT an MLS Remove commit and does NOT advance the group
 * epoch or heal PCS. The revoked device's existing group keys are unaffected
 * until the group's real members land an actual MLS Remove Commit in their
 * clients. This component MUST NEVER auto-execute anything from this signal;
 * every action is gated behind an explicit, per-device, time-delayed human
 * confirmation step (armed state disables the confirm control briefly so a
 * stray double-click on the same coordinates as the arming click cannot
 * trigger it).
 *
 * Scoping note: there is a server-side `RemovalRequired` WS event, but the
 * frontend has no WebSocket client yet. This component only polls the REST
 * endpoint on mount / group change — wiring a live WS push is out of scope.
 */

import { useCallback, useEffect, useRef, useState } from "react";
import { listPendingRemovals, removeMember } from "../api/groups";
import { useAuthStore } from "../store/auth";
import { Icon } from "./Icon";

interface PendingRemovalBannerProps {
	groupId: string;
}

/** Confirm control stays disabled this long after arming — see module doc. */
const CONFIRM_ARM_DELAY_MS = 500;

function shortDeviceLabel(deviceId: string): string {
	return `Device ${deviceId.slice(0, 8)}`;
}

export function PendingRemovalBanner({ groupId }: PendingRemovalBannerProps) {
	const sessionToken = useAuthStore((s) => s.sessionToken);

	const [pending, setPending] = useState<string[]>([]);
	const [loaded, setLoaded] = useState(false);
	const [confirming, setConfirming] = useState<string | null>(null);
	const [confirmArmed, setConfirmArmed] = useState(false);
	const [removing, setRemoving] = useState<string | null>(null);
	const [rowErrors, setRowErrors] = useState<Record<string, string>>({});
	const armTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

	useEffect(() => {
		return () => {
			if (armTimerRef.current) clearTimeout(armTimerRef.current);
		};
	}, []);

	const beginConfirm = useCallback((deviceId: string) => {
		setConfirming(deviceId);
		setConfirmArmed(false);
		if (armTimerRef.current) clearTimeout(armTimerRef.current);
		armTimerRef.current = setTimeout(() => setConfirmArmed(true), CONFIRM_ARM_DELAY_MS);
	}, []);

	const cancelConfirm = useCallback(() => {
		if (armTimerRef.current) clearTimeout(armTimerRef.current);
		setConfirming(null);
		setConfirmArmed(false);
	}, []);

	useEffect(() => {
		let cancelled = false;
		setLoaded(false);
		cancelConfirm();
		setRowErrors({});
		if (!sessionToken || !groupId) {
			setPending([]);
			setLoaded(true);
			return;
		}
		listPendingRemovals(sessionToken, groupId)
			.then((deviceIds) => {
				if (!cancelled) setPending(deviceIds);
			})
			.catch(() => {
				// Category-only failure — no plaintext/response-body logging
				// (no-plaintext-logging invariant). Fail closed: show nothing
				// rather than a stale or misleading list.
				if (!cancelled) setPending([]);
			})
			.finally(() => {
				if (!cancelled) setLoaded(true);
			});
		return () => {
			cancelled = true;
		};
	}, [sessionToken, groupId, cancelConfirm]);

	const handleConfirmRemove = useCallback(
		async (deviceId: string) => {
			if (!sessionToken) {
				setRowErrors((prev) => ({ ...prev, [deviceId]: "Session expired. Please reload." }));
				return;
			}
			setRemoving(deviceId);
			setRowErrors((prev) => {
				const next = { ...prev };
				delete next[deviceId];
				return next;
			});
			try {
				await removeMember(sessionToken, groupId, deviceId);
				setPending((prev) => prev.filter((id) => id !== deviceId));
				cancelConfirm();
			} catch {
				// Error category only — never echo the raw response body.
				setRowErrors((prev) => ({ ...prev, [deviceId]: "Failed to remove device." }));
			} finally {
				setRemoving(null);
			}
		},
		[sessionToken, groupId, cancelConfirm],
	);

	if (!loaded || pending.length === 0) return null;

	return (
		<div
			data-testid="pending-removal-banner"
			style={{
				display: "flex",
				flexDirection: "column",
				gap: 8,
				padding: "10px 14px",
				margin: "0 0 8px",
				background: "rgba(168,200,255,0.05)",
				border: "1px solid rgba(168,200,255,0.16)",
				borderRadius: 10,
			}}
		>
			<div style={{ display: "flex", alignItems: "center", gap: 8 }}>
				<Icon name="shield" size={14} color="var(--photon)" />
				<span style={{ fontSize: 12, color: "#C8DCFF", lineHeight: 1.45 }}>
					{pending.length === 1
						? "The server reports 1 device revoked from this group."
						: `The server reports ${pending.length} devices revoked from this group.`}
				</span>
			</div>
			<span
				data-testid="pending-removal-warning"
				style={{ fontSize: 11, color: "var(--fg-3)", lineHeight: 1.5 }}
			>
				This is reported by the server, not verified — confirm it matches a device you actually
				revoked. Stopping delivery here does not remove the device&apos;s existing group keys; a
				real MLS Remove must still land in your client.
			</span>

			<div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
				{pending.map((deviceId) => {
					const isConfirming = confirming === deviceId;
					const isRemoving = removing === deviceId;
					const rowError = rowErrors[deviceId];

					return (
						<div
							key={deviceId}
							data-testid={`pending-removal-row-${deviceId}`}
							style={{
								display: "flex",
								flexDirection: "column",
								gap: 4,
								padding: "8px 10px",
								background: "var(--bg-elevated)",
								border: "1px solid var(--border-faint)",
								borderRadius: 8,
							}}
						>
							<div style={{ display: "flex", alignItems: "center", gap: 10 }}>
								<span
									data-testid={`pending-removal-label-${deviceId}`}
									style={{
										flex: 1,
										fontSize: 12,
										color: "var(--fg-2)",
										fontFamily: "monospace",
									}}
								>
									{shortDeviceLabel(deviceId)}
								</span>

								{isConfirming ? (
									<div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
										<div style={{ display: "flex", gap: 6 }}>
											<button
												type="button"
												data-testid={`pending-removal-cancel-${deviceId}`}
												onClick={cancelConfirm}
												disabled={isRemoving}
												style={{
													background: "transparent",
													border: "1px solid var(--border-soft)",
													borderRadius: 6,
													padding: "4px 10px",
													color: "var(--fg-3)",
													fontSize: 12,
													cursor: isRemoving ? "not-allowed" : "pointer",
												}}
											>
												Cancel
											</button>
											<button
												type="button"
												data-testid={`pending-removal-confirm-${deviceId}`}
												onClick={() => void handleConfirmRemove(deviceId)}
												disabled={isRemoving || !confirmArmed}
												style={{
													background: "rgba(205,48,63,0.14)",
													border: "1px solid rgba(205,48,63,0.32)",
													borderRadius: 6,
													padding: "4px 10px",
													color: "#E05261",
													fontSize: 12,
													fontWeight: 600,
													opacity: confirmArmed ? 1 : 0.5,
													cursor: isRemoving ? "wait" : confirmArmed ? "pointer" : "not-allowed",
												}}
											>
												{isRemoving ? "Removing…" : "Confirm: stop delivery"}
											</button>
										</div>
										<span style={{ fontSize: 10, color: "var(--fg-4)" }}>
											This does not perform an MLS Remove.
										</span>
									</div>
								) : (
									<button
										type="button"
										data-testid={`pending-removal-btn-${deviceId}`}
										onClick={() => beginConfirm(deviceId)}
										style={{
											background: "transparent",
											border: "1px solid var(--border-soft)",
											borderRadius: 6,
											padding: "4px 10px",
											color: "var(--fg-3)",
											fontSize: 12,
											cursor: "pointer",
										}}
									>
										Stop delivery
									</button>
								)}
							</div>

							{rowError && (
								<span
									data-testid={`pending-removal-error-${deviceId}`}
									style={{ fontSize: 11, color: "#FF9999" }}
								>
									{rowError}
								</span>
							)}
						</div>
					);
				})}
			</div>
		</div>
	);
}
