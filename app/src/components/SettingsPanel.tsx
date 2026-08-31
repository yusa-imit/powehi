/**
 * SettingsPanel — account settings surface reached from the sidebar Settings icon.
 *
 * Currently exposes two actions:
 * - "Linked devices" — drills into LinkedDevicesPanel (device list + revoke).
 * - "Log out" — calls useAuthStore().logout(), which wipes worker key material
 *   (clearSessionState then dropDbKey, in that order — see store/auth.ts) before
 *   resetting auth state back to the login phase.
 *
 * Follows the same fixed-overlay dialog pattern as StatusEditor in ChatLayout.tsx
 * (backdrop + centered card) since, like the status editor, this panel is opened
 * from a top-level Sidebar action rather than being local to Sidebar's own layout
 * (contrast with StarredPanel, which lives entirely inside Sidebar).
 */

import { useState } from "react";
import { useAuthStore } from "../store/auth";
import { Icon } from "./Icon";
import { LinkedDevicesPanel } from "./LinkedDevicesPanel";

interface SettingsPanelProps {
	open: boolean;
	onClose: () => void;
}

export function SettingsPanel({ open, onClose }: SettingsPanelProps) {
	const [view, setView] = useState<"main" | "devices">("main");
	const [loggingOut, setLoggingOut] = useState(false);
	const [logoutFailed, setLogoutFailed] = useState(false);
	const logout = useAuthStore((s) => s.logout);

	if (!open) return null;

	const handleClose = () => {
		setView("main");
		onClose();
	};

	const handleLogout = async () => {
		setLoggingOut(true);
		setLogoutFailed(false);
		try {
			// logout() swallows a rejected clearSessionState internally (a WASM
			// panic must not block returning to the login screen), but a rejected
			// dropDbKey() is NOT swallowed — if the worker itself is dead, logout()
			// throws before `set({ phase: "login", ... })` runs, leaving the user
			// still fully authenticated (live sessionToken, DB key possibly still
			// resident) with no signal unless we surface it here.
			await logout();
		} catch {
			setLogoutFailed(true);
		} finally {
			setLoggingOut(false);
		}
	};

	return (
		<dialog
			open
			data-testid="settings-overlay"
			aria-label="Settings"
			onClick={(e) => {
				if (e.target === e.currentTarget) handleClose();
			}}
			onKeyDown={(e) => {
				if (e.key === "Escape") handleClose();
			}}
			style={{
				position: "fixed",
				inset: 0,
				width: "100vw",
				height: "100vh",
				maxWidth: "100vw",
				maxHeight: "100vh",
				background: "rgba(4,4,8,0.72)",
				display: "flex",
				alignItems: "center",
				justifyContent: "center",
				zIndex: 1000,
				border: "none",
				padding: 0,
				margin: 0,
			}}
		>
			<div
				data-testid="settings-panel"
				onClick={(e) => e.stopPropagation()}
				onKeyDown={(e) => e.stopPropagation()}
				style={{
					background: "var(--bg-surface)",
					border: "1px solid var(--border-soft)",
					borderRadius: 16,
					width: 360,
					maxHeight: "80vh",
					display: "flex",
					flexDirection: "column",
					overflow: "hidden",
				}}
			>
				{view === "devices" ? (
					<LinkedDevicesPanel onClose={() => setView("main")} />
				) : (
					<>
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
							<span style={{ fontWeight: 600, fontSize: 15, color: "var(--fg-1)", flex: 1 }}>
								Settings
							</span>
							<button
								type="button"
								onClick={handleClose}
								aria-label="Close settings"
								data-testid="settings-close"
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
								<Icon name="x" size={16} />
							</button>
						</div>

						{/* Rows */}
						<div style={{ padding: "8px 0" }}>
							<button
								type="button"
								data-testid="settings-linked-devices-row"
								disabled={loggingOut}
								onClick={() => setView("devices")}
								style={{
									display: "flex",
									alignItems: "center",
									gap: 12,
									width: "100%",
									padding: "10px 16px",
									background: "none",
									border: "none",
									cursor: loggingOut ? "wait" : "pointer",
									color: "var(--fg-1)",
									fontSize: 13,
									textAlign: "left",
								}}
							>
								<Icon name="lock" size={16} color="var(--photon-300)" />
								<span style={{ flex: 1 }}>Linked devices</span>
								<Icon name="chevron-right" size={14} color="var(--fg-4)" />
							</button>

							<button
								type="button"
								data-testid="settings-logout-btn"
								disabled={loggingOut}
								onClick={() => void handleLogout()}
								style={{
									display: "flex",
									alignItems: "center",
									gap: 12,
									width: "100%",
									padding: "10px 16px",
									background: "none",
									border: "none",
									cursor: loggingOut ? "wait" : "pointer",
									color: "var(--flare)",
									fontSize: 13,
									textAlign: "left",
								}}
							>
								<span>{loggingOut ? "Logging out…" : "Log out"}</span>
							</button>
							{logoutFailed && (
								<div
									data-testid="settings-logout-error"
									style={{
										padding: "0 16px 10px",
										color: "var(--flare)",
										fontSize: 12,
									}}
								>
									Log out failed — this device's secure session could not be fully cleared. Close
									the tab or reload to end the session.
								</div>
							)}
						</div>
					</>
				)}
			</div>
		</dialog>
	);
}
