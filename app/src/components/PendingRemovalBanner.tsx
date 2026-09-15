/**
 * PendingRemovalBanner — surfaces server-tracked "pending MLS Remove" requests
 * for the currently open group.
 *
 * Trust boundary (prd.md §5.4): the server holds no MLS group state or keys,
 * so it can never construct or verify a Remove commit — this signal is a
 * REQUEST, never a proof, and a malicious/compromised server operator can
 * forge it to trick a user into evicting a legitimate device (prd.md §3.5.1
 * T3). The per-device human confirmation click remains the primary defense
 * regardless of anything below — confirming is never gated on it.
 *
 * Partial local cross-check (prd.md §5.4): this component also fetches
 * `listMembers` (`GET /v1/groups/:groupId/members`) and flags a pending
 * device_id as "stale" (`data-testid="pending-removal-stale-{deviceId}"`)
 * when it does NOT appear in that list. This can catch server-side
 * INCONSISTENCY — e.g. a pending-removal entry for a device that was never
 * a member, or one already removed — but it is same-trust-domain
 * defense-in-depth, not a T3 mitigation: both signals come from the same
 * server, so a fully malicious/colluding server can forge both consistently
 * and this check catches nothing. It also does NOT join against the
 * client's own MLS ratchet tree (that device_id-to-leaf binding does not
 * exist yet), so it can never prove a device IS legitimately absent. When
 * the members response is `truncated`, the cross-check is skipped entirely
 * for that fetch (no row is marked stale) per the endpoint's own contract —
 * treating truncated-absence as meaningful would itself be the false-
 * eviction failure mode this check exists to avoid.
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
 * This component's confirm action can NEVER be wired to an MLS Remove commit
 * as it stands. `mlsRemoveMemberStage` requires a `leafIndex` taken from this
 * client's own `mlsGroupMembers` ratchet-tree roster, and this component only
 * ever holds server-supplied `device_id`s. No authenticated binding between a
 * server `device_id` and an MLS credential/leaf exists in this codebase
 * (`wasm_exports.rs`'s `mls_group_members` doc comment; prd.md §3.3 records
 * the cycle-456 crypto-reviewer NEEDS-REWORK). Bridging the two requires one
 * of the two follow-ups prd.md §3.3 names — bind `device_id` into the MLS
 * credential identity at registration/recovery, or re-evaluate the §5.6
 * safety number as the T3 local trust anchor — each of which needs its own
 * plan and a threat-model-checker pass. A real Remove UI must therefore be a
 * separate, ratchet-tree-driven entry point, not this banner.
 *
 * Scoping note: there is a server-side `RemovalRequired` WS event, but the
 * frontend has no WebSocket client yet. This component only polls the REST
 * endpoint on mount / group change — wiring a live WS push is out of scope.
 */

import { useCallback, useEffect, useRef, useState } from "react";
import { listMembers, listPendingRemovals, removeMember } from "../api/groups";
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
	// `null` means "unknown" — either not loaded yet or the fetch failed;
	// the cross-check is skipped entirely in that case, same as `truncated`.
	const [memberIds, setMemberIds] = useState<Set<string> | null>(null);
	const [membersTruncated, setMembersTruncated] = useState(false);
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
			setMemberIds(null);
			setMembersTruncated(false);
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

		// Partial local cross-check (module doc) — best-effort only. A
		// failure here must never block or alter the pending-removals
		// display, so it is handled independently of the fetch above.
		setMemberIds(null);
		setMembersTruncated(false);
		listMembers(sessionToken, groupId)
			.then(({ deviceIds, truncated }) => {
				if (!cancelled) {
					setMemberIds(new Set(deviceIds));
					setMembersTruncated(truncated);
				}
			})
			.catch(() => {
				// Category-only failure — no plaintext/response-body logging.
				// Skip the cross-check; pending rows still render normally.
				if (!cancelled) {
					setMemberIds(null);
					setMembersTruncated(false);
				}
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
				<Icon name="shield" size={14} color="var(--photon-300)" />
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
					// Skip the cross-check entirely when the members list is
					// unknown (not loaded / fetch failed) or truncated — see
					// module doc. Never treat truncated-absence as meaningful.
					const isStale = memberIds !== null && !membersTruncated && !memberIds.has(deviceId);

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

							{isStale && (
								<span
									data-testid={`pending-removal-stale-${deviceId}`}
									style={{ fontSize: 11, color: "var(--fg-4)" }}
								>
									Not currently listed as a group member — signal may be stale.
								</span>
							)}

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
