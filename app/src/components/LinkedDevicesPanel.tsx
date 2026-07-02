/**
 * LinkedDevicesPanel — manage devices linked to the authenticated account.
 *
 * Fetches GET /v1/auth/devices and renders a list. Each row shows the device
 * ID (last 8 hex chars), created date, and last-seen date. The current device
 * is highlighted. Non-current devices can be revoked (DELETE /v1/auth/devices/:id).
 *
 * Security notes (prd.md §5, §8):
 * - Session tokens travel as Bearer headers, never in URLs.
 * - Revoking a device invalidates ALL its active sessions server-side.
 * - The current device row has no revoke button — use logout to delink it.
 */

import { useCallback, useEffect, useState } from "react";
import { type DeviceInfo, listDevices, revokeDevice } from "../api/auth";
import { useAuthStore } from "../store/auth";
import { Icon } from "./Icon";

interface LinkedDevicesPanelProps {
	onClose: () => void;
}

function formatDate(iso: string): string {
	return new Date(iso).toLocaleDateString(undefined, {
		year: "numeric",
		month: "short",
		day: "numeric",
	});
}

function shortId(deviceId: string): string {
	// Show last 8 chars of the UUID for recognition without leaking the full ID.
	return deviceId.replace(/-/g, "").slice(-8).toUpperCase();
}

export function LinkedDevicesPanel({ onClose }: LinkedDevicesPanelProps) {
	const sessionToken = useAuthStore((s) => s.sessionToken);
	const currentDeviceId = useAuthStore((s) => s.deviceId);

	const [devices, setDevices] = useState<DeviceInfo[]>([]);
	const [loading, setLoading] = useState(true);
	const [error, setError] = useState<string | null>(null);
	const [revoking, setRevoking] = useState<string | null>(null);
	const [confirmRevoke, setConfirmRevoke] = useState<string | null>(null);

	const fetchDevices = useCallback(async () => {
		if (!sessionToken) return;
		setLoading(true);
		setError(null);
		try {
			const list = await listDevices(sessionToken);
			setDevices(list);
		} catch {
			setError("Could not load linked devices.");
		} finally {
			setLoading(false);
		}
	}, [sessionToken]);

	useEffect(() => {
		void fetchDevices();
	}, [fetchDevices]);

	const handleRevoke = useCallback(
		async (deviceId: string) => {
			if (!sessionToken) return;
			setRevoking(deviceId);
			setConfirmRevoke(null);
			try {
				await revokeDevice(sessionToken, deviceId);
				setDevices((prev) => prev.filter((d) => d.device_id !== deviceId));
			} catch {
				setError("Failed to revoke device. Please try again.");
			} finally {
				setRevoking(null);
			}
		},
		[sessionToken],
	);

	return (
		<div
			data-testid="linked-devices-panel"
			style={{
				display: "flex",
				flexDirection: "column",
				height: "100%",
				background: "var(--bg-surface)",
				color: "var(--fg-1)",
			}}
		>
			{/* Header */}
			<div
				style={{
					display: "flex",
					alignItems: "center",
					gap: 8,
					padding: "14px 16px",
					borderBottom: "1px solid var(--border-soft)",
					flexShrink: 0,
				}}
			>
				<button
					type="button"
					onClick={onClose}
					aria-label="Close linked devices"
					data-testid="linked-devices-close"
					style={{
						background: "none",
						border: "none",
						cursor: "pointer",
						padding: 4,
						color: "var(--fg-2)",
						display: "flex",
						alignItems: "center",
					}}
				>
					<Icon name="chevron-left" size={16} />
				</button>
				<span style={{ fontWeight: 600, fontSize: 15, color: "var(--fg-1)" }}>
					Linked Devices
				</span>
			</div>

			{/* Body */}
			<div style={{ flex: 1, overflowY: "auto", padding: "8px 0" }}>
				{loading && (
					<div
						data-testid="linked-devices-loading"
						style={{ padding: "32px 16px", textAlign: "center", color: "var(--fg-3)", fontSize: 13 }}
					>
						Loading…
					</div>
				)}

				{!loading && error && (
					<div
						data-testid="linked-devices-error"
						style={{ padding: "16px", color: "var(--flare)", fontSize: 13 }}
					>
						{error}
					</div>
				)}

				{!loading && !error && devices.length === 0 && (
					<div
						data-testid="linked-devices-empty"
						style={{ padding: "32px 16px", textAlign: "center", color: "var(--fg-3)", fontSize: 13 }}
					>
						No linked devices found.
					</div>
				)}

				{!loading &&
					!error &&
					devices.map((device) => {
						const isCurrent = device.device_id === currentDeviceId;
						const isBeingRevoked = revoking === device.device_id;
						const awaitingConfirm = confirmRevoke === device.device_id;

						return (
							<div
								key={device.device_id}
								data-testid={`device-row-${device.device_id}`}
								style={{
									display: "flex",
									alignItems: "center",
									gap: 12,
									padding: "10px 16px",
									borderBottom: "1px solid var(--border-faint)",
									background: isCurrent ? "var(--bg-elevated)" : undefined,
								}}
							>
								{/* Lock icon — photon blue per design system */}
								<Icon
									name="lock"
									size={16}
									color={isCurrent ? "var(--photon)" : "var(--fg-4)"}
								/>

								{/* Device info */}
								<div style={{ flex: 1, minWidth: 0 }}>
									<div
										style={{
											display: "flex",
											alignItems: "center",
											gap: 6,
											marginBottom: 2,
										}}
									>
										<span
											data-testid={`device-id-${device.device_id}`}
											style={{
												fontSize: 13,
												fontWeight: 500,
												color: isCurrent ? "var(--fg-1)" : "var(--fg-2)",
												fontFamily: "monospace",
											}}
										>
											…{shortId(device.device_id)}
										</span>
										{isCurrent && (
											<span
												data-testid={`device-current-badge-${device.device_id}`}
												style={{
													fontSize: 10,
													fontWeight: 600,
													color: "var(--orange)",
													background: "rgba(255,138,61,0.12)",
													borderRadius: 4,
													padding: "1px 5px",
													letterSpacing: "0.04em",
													textTransform: "uppercase",
												}}
											>
												This device
											</span>
										)}
									</div>
									<div style={{ fontSize: 11, color: "var(--fg-3)" }}>
										<span>Added {formatDate(device.created_at)}</span>
										{device.last_seen_at && (
											<>
												{" · "}
												<span>Last seen {formatDate(device.last_seen_at)}</span>
											</>
										)}
									</div>
								</div>

								{/* Revoke button — not shown for current device */}
								{!isCurrent && (
									<div style={{ flexShrink: 0 }}>
										{awaitingConfirm ? (
											<div style={{ display: "flex", gap: 6, alignItems: "center" }}>
												<button
													type="button"
													data-testid={`device-revoke-confirm-${device.device_id}`}
													disabled={isBeingRevoked}
													onClick={() => void handleRevoke(device.device_id)}
													style={{
														fontSize: 11,
														fontWeight: 600,
														color: "var(--flare)",
														background: "rgba(255,122,122,0.1)",
														border: "1px solid rgba(255,122,122,0.25)",
														borderRadius: 4,
														padding: "3px 8px",
														cursor: isBeingRevoked ? "wait" : "pointer",
													}}
												>
													{isBeingRevoked ? "Revoking…" : "Confirm revoke"}
												</button>
												<button
													type="button"
													data-testid={`device-revoke-cancel-${device.device_id}`}
													onClick={() => setConfirmRevoke(null)}
													style={{
														fontSize: 11,
														color: "var(--fg-3)",
														background: "none",
														border: "none",
														cursor: "pointer",
														padding: "3px 4px",
													}}
												>
													Cancel
												</button>
											</div>
										) : (
											<button
												type="button"
												data-testid={`device-revoke-btn-${device.device_id}`}
												onClick={() => setConfirmRevoke(device.device_id)}
												style={{
													fontSize: 11,
													color: "var(--fg-3)",
													background: "none",
													border: "1px solid var(--border-soft)",
													borderRadius: 4,
													padding: "3px 8px",
													cursor: "pointer",
												}}
											>
												Revoke
											</button>
										)}
									</div>
								)}
							</div>
						);
					})}
			</div>

			{/* Footer note */}
			{!loading && !error && devices.length > 0 && (
				<div
					style={{
						padding: "10px 16px",
						borderTop: "1px solid var(--border-faint)",
						fontSize: 11,
						color: "var(--fg-4)",
						lineHeight: 1.5,
					}}
				>
					Revoking a device immediately invalidates all its active sessions. It cannot re-access
					your account without re-authenticating.
				</div>
			)}
		</div>
	);
}
