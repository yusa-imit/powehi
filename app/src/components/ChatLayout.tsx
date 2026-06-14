import {
	type CSSProperties,
	type KeyboardEvent,
	useCallback,
	useEffect,
	useLayoutEffect,
	useMemo,
	useRef,
	useState,
} from "react";
import { sendMessage as sendMessageApi } from "../api/messages";
import { EncryptedPowehiDb } from "../db/encrypted-db";
import { db } from "../db/schema";
import { useCryptoWorker } from "../hooks/useCryptoWorker";
import { useMediaSend } from "../hooks/useMediaSend";
import {
	ALLOWED_REACTION_EMOJIS,
	type IncomingMessage,
	type MediaPayload,
	useMessages,
} from "../hooks/useMessages";
import { usePersistentMessages } from "../hooks/usePersistentMessages";
import { useRegionDetect } from "../hooks/useRegionDetect";
import { type NewGroupEvent, useWelcomePoller } from "../hooks/useWelcomePoller";
import { useAuthStore } from "../store/auth";
import { uint8ToBase64 } from "../utils/base64";
import { Icon } from "./Icon";
import { InviteModal } from "./InviteModal";
import { MediaImage } from "./MediaImage";
import { SafetyNumbers } from "./SafetyNumbers";

// ── Types ─────────────────────────────────────────────────────────────────────

interface ChatMessage {
	/** Envelope UUID — used as stable key for targeting reactions. Absent on optimistic sent msgs. */
	id?: string;
	day?: string;
	from: "me" | "them";
	text: string;
	continued?: boolean;
	last?: boolean;
	time?: string;
	read?: boolean;
	/** Unix ms — set when sent with a disappearing TTL. Client-side mock only. */
	expiresAt?: number;
	/** §9.2 media attachment — full payload for download + decrypt on the receiver path. */
	media?: MediaPayload;
	/** Emoji reactions: emoji → array of sender device IDs (deduped). */
	reactions?: Record<string, string[]>;
}

interface Chat {
	id: string;
	name: string;
	handle: string;
	online: boolean;
	lastSeen?: string;
	typing?: boolean;
	last: string;
	time: string;
	unread: number;
	verifiedAgo?: string;
	messages: ChatMessage[];
	/** Disappearing message TTL in seconds. undefined = off. */
	disappearingTtl?: number;
	/** MLS group UUID returned by mls_create_group. undefined until E2EE session established. */
	mlsGroupId?: string;
	/** Local MLS identity ID returned by mls_init_identity. undefined until identity created. */
	mlsIdentityId?: string;
	/** 16-char PQ group binding hex (§5.3 Phase B). Set after pq_init exchange completes. */
	pqBindingHex?: string;
}

// ── Disappearing messages helpers ──────────────────────────────────────────────

const TTL_OPTIONS = [undefined, 300, 3600, 86400, 604800] as const;
type TtlOption = (typeof TTL_OPTIONS)[number];

function formatTtl(s: number | undefined): string {
	if (!s) return "Off";
	if (s < 3600) return `${s / 60}m`;
	if (s < 86400) return `${s / 3600}h`;
	if (s < 604800) return `${s / 86400}d`;
	return "1w";
}

function nextTtl(current: number | undefined): TtlOption {
	const idx = TTL_OPTIONS.indexOf(current as TtlOption);
	return TTL_OPTIONS[(idx + 1) % TTL_OPTIONS.length];
}

// ── Mock data ─────────────────────────────────────────────────────────────────

const SEED_CHATS: Chat[] = [
	{
		id: "maya",
		name: "Maya Akana",
		handle: "maya",
		online: true,
		last: "Bringing the notebook.",
		time: "14:32",
		unread: 0,
		verifiedAgo: "2 days ago",
		mlsGroupId: "11111111-1111-1111-1111-111111111111",
		mlsIdentityId: "22222222-2222-2222-2222-222222222222",
		messages: [
			{ day: "Yesterday", from: "them", text: "Hey — are you free tomorrow morning?" },
			{
				from: "me",
				text: "Should be. What time?",
				continued: true,
				last: true,
				time: "20:14",
				read: true,
			},
			{ day: "Today", from: "them", text: "9am at the corner cafe?" },
			{
				from: "them",
				text: "I have a thing at 10:30 so let us keep it short",
				continued: true,
				last: true,
				time: "14:30",
			},
			{ from: "me", text: "Works for me." },
			{
				from: "me",
				text: "Bringing the notebook.",
				continued: true,
				last: true,
				time: "14:32",
				read: true,
			},
		],
	},
	{
		id: "jordan",
		name: "Jordan",
		handle: "jordan_b",
		online: false,
		lastSeen: "2h ago",
		last: "receipt.pdf",
		time: "12:08",
		unread: 2,
		mlsGroupId: "33333333-3333-3333-3333-333333333333",
		messages: [
			{ day: "Today", from: "them", text: "split for last night" },
			{ from: "them", text: "receipt.pdf", continued: true, last: true, time: "12:08" },
		],
	},
	{
		id: "ari",
		name: "Ari Work",
		handle: "ari",
		online: false,
		lastSeen: "yesterday",
		last: "You: see you tmrw",
		time: "Yesterday",
		unread: 0,
		messages: [
			{ day: "Yesterday", from: "them", text: "tomorrow 10am for the review?" },
			{ from: "me", text: "see you tmrw", continued: true, last: true, time: "17:42", read: true },
		],
	},
	{
		id: "sam",
		name: "Sam",
		handle: "sam.k",
		online: true,
		typing: true,
		last: "typing...",
		time: "14:33",
		unread: 0,
		messages: [
			{
				day: "Today",
				from: "me",
				text: "did the deploy go through?",
				last: true,
				time: "14:31",
				read: true,
			},
		],
	},
];

// ── Avatar ────────────────────────────────────────────────────────────────────

const PALETTE: [string, string][] = [
	["#A8C8FF", "#445C99"],
	["#FF8A3D", "#6E2700"],
	["#5EE6A8", "#1F6B4C"],
	["#FFD78A", "#B14507"],
	["#C8DCFF", "#6688CC"],
	["#FF9E52", "#B14507"],
];

function avatarColors(seed: string): [string, string] {
	const i = seed.split("").reduce((a, c) => a + c.charCodeAt(0), 0) % PALETTE.length;
	return PALETTE[i];
}

function Avatar({
	name,
	size = 40,
	online,
}: {
	name: string;
	size?: number;
	online?: boolean;
}) {
	const initials = name
		.split(" ")
		.map((s) => s[0])
		.join("")
		.slice(0, 2)
		.toUpperCase();
	const [a, b] = avatarColors(name);
	const isCool = a === "#A8C8FF" || a === "#C8DCFF" || a === "#5EE6A8" || a === "#FFD78A";
	return (
		<span
			style={{
				position: "relative",
				width: size,
				height: size,
				flex: "none",
				display: "inline-block",
			}}
		>
			<span
				style={{
					width: size,
					height: size,
					borderRadius: "50%",
					background: `linear-gradient(135deg, ${a}, ${b})`,
					color: isCool ? "#06060C" : "#fff",
					display: "flex",
					alignItems: "center",
					justifyContent: "center",
					fontWeight: 600,
					fontSize: size * 0.38,
				}}
			>
				{initials}
			</span>
			{online !== undefined && (
				<span
					style={{
						position: "absolute",
						bottom: -1,
						right: -1,
						width: Math.max(10, size * 0.28),
						height: Math.max(10, size * 0.28),
						borderRadius: "50%",
						background: online ? "#5EE6A8" : "var(--fg-4)",
						border: `${Math.max(2, size * 0.06)}px solid var(--bg-void)`,
						boxShadow: online ? "0 0 6px rgba(94,230,168,0.5)" : "none",
					}}
				/>
			)}
		</span>
	);
}

// ── HighlightedText ───────────────────────────────────────────────────────────

function HighlightedText({ text, highlight }: { text: string; highlight: string }) {
	if (!highlight) return <>{text}</>;
	const lc = text.toLowerCase();
	const hlLc = highlight.toLowerCase();
	const parts: React.ReactNode[] = [];
	let cursor = 0;
	let idx = lc.indexOf(hlLc, cursor);
	while (idx !== -1) {
		if (idx > cursor) parts.push(text.slice(cursor, idx));
		parts.push(
			<mark
				key={`${idx}-${cursor}`}
				style={{
					background: "rgba(255,138,61,0.35)",
					color: "inherit",
					borderRadius: 2,
					padding: "0 1px",
				}}
			>
				{text.slice(idx, idx + highlight.length)}
			</mark>,
		);
		cursor = idx + highlight.length;
		idx = lc.indexOf(hlLc, cursor);
	}
	if (cursor < text.length) parts.push(text.slice(cursor));
	return <>{parts}</>;
}

// ── Logo ──────────────────────────────────────────────────────────────────────

function Logo({ size = 28 }: { size?: number }) {
	const uid = `logo-sidebar-${size}`;
	return (
		<span style={{ display: "inline-flex", alignItems: "center", gap: 10 }}>
			<svg
				width={size}
				height={size}
				viewBox="0 0 256 256"
				fill="none"
				role="img"
				aria-label="Powehi logo"
			>
				<defs>
					<radialGradient id={uid} cx="50%" cy="50%" r="50%">
						<stop offset="0%" stopColor="#FFB155" />
						<stop offset="30%" stopColor="#FF8A3D" />
						<stop offset="60%" stopColor="#C75612" stopOpacity="0.7" />
						<stop offset="100%" stopColor="#3A1A06" stopOpacity="0" />
					</radialGradient>
				</defs>
				<ellipse cx="128" cy="128" rx="124" ry="84" fill={`url(#${uid})`} />
				<circle cx="128" cy="128" r="46" fill="#000000" />
				<circle cx="128" cy="128" r="46" fill="none" stroke="#E8F0FF" strokeWidth="1.4" />
			</svg>
			<span
				style={{
					fontFamily: "Geist, system-ui, sans-serif",
					fontWeight: 600,
					fontSize: size * 0.66,
					letterSpacing: "-0.03em",
					color: "var(--fg-1)",
				}}
			>
				powehi
			</span>
		</span>
	);
}

// ── IconBtn ───────────────────────────────────────────────────────────────────

function IconBtn({
	icon,
	onClick,
	active,
	size = 36,
	label,
	style,
	color,
}: {
	icon: Parameters<typeof Icon>[0]["name"];
	onClick?: () => void;
	active?: boolean;
	size?: number;
	label: string;
	style?: CSSProperties;
	color?: string;
}) {
	const [hover, setHover] = useState(false);
	return (
		<button
			type="button"
			onClick={onClick}
			aria-label={label}
			onMouseEnter={() => setHover(true)}
			onMouseLeave={() => setHover(false)}
			style={{
				width: size,
				height: size,
				borderRadius: 10,
				background: active ? "var(--bg-elevated)" : hover ? "var(--bg-surface)" : "transparent",
				color: color ?? (active ? "var(--accretion-400)" : "var(--fg-2)"),
				border: "1px solid transparent",
				display: "inline-flex",
				alignItems: "center",
				justifyContent: "center",
				cursor: "pointer",
				transition: "all 200ms cubic-bezier(0.22, 1, 0.36, 1)",
				...style,
			}}
		>
			<Icon name={icon} size={size * 0.5} />
		</button>
	);
}

// ── Sidebar ───────────────────────────────────────────────────────────────────

function ChatRow({
	chat,
	active,
	onClick,
}: {
	chat: Chat;
	active: boolean;
	onClick: () => void;
}) {
	const [hover, setHover] = useState(false);
	return (
		<button
			type="button"
			onClick={onClick}
			onMouseEnter={() => setHover(true)}
			onMouseLeave={() => setHover(false)}
			style={{
				display: "flex",
				alignItems: "center",
				gap: 12,
				padding: "11px 12px",
				borderRadius: 12,
				cursor: "pointer",
				background: active ? "var(--bg-elevated)" : hover ? "var(--bg-surface)" : "transparent",
				transition: "background 120ms",
				border: "none",
				width: "100%",
				textAlign: "left",
				color: "inherit",
				fontFamily: "inherit",
			}}
		>
			<Avatar name={chat.name} size={42} online={chat.online} />
			<div style={{ flex: 1, minWidth: 0 }}>
				<div
					style={{
						display: "flex",
						alignItems: "center",
						justifyContent: "space-between",
						gap: 8,
					}}
				>
					<span
						style={{
							fontSize: 14,
							fontWeight: 500,
							color: "var(--fg-1)",
							overflow: "hidden",
							textOverflow: "ellipsis",
							whiteSpace: "nowrap",
						}}
					>
						{chat.name}
					</span>
					<span
						style={{
							fontSize: 11,
							color: "var(--fg-3)",
							fontFamily: "var(--font-mono)",
							flex: "none",
						}}
					>
						{chat.time}
					</span>
				</div>
				<div style={{ display: "flex", alignItems: "center", gap: 6, marginTop: 2 }}>
					{chat.typing ? (
						<span
							style={{
								fontSize: 13,
								color: "#FF9E52",
								fontStyle: "italic",
							}}
						>
							typing...
						</span>
					) : (
						<span
							style={{
								fontSize: 13,
								color: active ? "var(--fg-2)" : "var(--fg-3)",
								overflow: "hidden",
								textOverflow: "ellipsis",
								whiteSpace: "nowrap",
								flex: 1,
							}}
						>
							{chat.last}
						</span>
					)}
					{chat.unread > 0 && (
						<span
							data-testid="unread-badge"
							style={{
								background: "#FF8A3D",
								color: "#2A0A00",
								fontWeight: 600,
								fontSize: 10,
								borderRadius: 9999,
								padding: "2px 7px",
								flex: "none",
							}}
						>
							{chat.unread > 9 ? "9+" : chat.unread}
						</span>
					)}
				</div>
			</div>
		</button>
	);
}

function Sidebar({
	chats,
	activeId,
	onSelect,
	onNewChat,
	onSettings,
	searchQuery,
	onSearch,
}: {
	chats: Chat[];
	activeId: string;
	onSelect: (id: string) => void;
	onNewChat: () => void;
	onSettings: () => void;
	searchQuery: string;
	onSearch: (q: string) => void;
}) {
	const regionId = useRegionDetect();
	const filtered = chats.filter(
		(c) =>
			!searchQuery ||
			c.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
			c.last.toLowerCase().includes(searchQuery.toLowerCase()),
	);

	return (
		<aside
			style={{
				width: 320,
				flex: "none",
				background: "var(--bg-surface)",
				borderRight: "1px solid var(--border-soft)",
				display: "flex",
				flexDirection: "column",
				height: "100%",
			}}
		>
			<div
				style={{
					padding: "18px 18px 14px",
					display: "flex",
					alignItems: "center",
					justifyContent: "space-between",
				}}
			>
				<Logo size={28} />
				<div style={{ display: "flex", gap: 2 }}>
					<IconBtn icon="plus" onClick={onNewChat} label="New chat" />
					<IconBtn icon="settings" onClick={onSettings} label="Settings" />
				</div>
			</div>

			{/* Search */}
			<div style={{ padding: "0 14px 12px" }}>
				<div
					style={{
						background: "var(--bg-input)",
						borderRadius: 10,
						border: "1px solid var(--border-faint)",
						display: "flex",
						alignItems: "center",
						gap: 8,
						padding: "8px 12px",
					}}
				>
					<Icon name="search" size={15} color="var(--fg-3)" />
					<input
						value={searchQuery}
						onChange={(e) => onSearch(e.target.value)}
						placeholder="Search chats"
						style={{
							flex: 1,
							background: "transparent",
							border: "none",
							outline: "none",
							color: "var(--fg-1)",
							fontFamily: "var(--font-sans)",
							fontSize: 13,
						}}
					/>
				</div>
			</div>

			{/* Encryption banner — photon blue lock, always */}
			<div
				style={{
					margin: "0 14px 8px",
					padding: "8px 12px",
					background: "rgba(168,200,255,0.05)",
					border: "1px solid rgba(168,200,255,0.16)",
					borderRadius: 10,
					display: "flex",
					alignItems: "center",
					gap: 9,
					fontSize: 11,
					color: "#C8DCFF",
					letterSpacing: "0.04em",
				}}
			>
				<Icon name="lock" size={13} color="#A8C8FF" />
				<span style={{ fontWeight: 500 }}>END-TO-END ENCRYPTED</span>
				<span style={{ marginLeft: "auto", opacity: 0.7 }}>·</span>
				<span style={{ opacity: 0.85 }}>only you</span>
			</div>

			{/* Chat list */}
			<div style={{ flex: 1, overflowY: "auto", padding: "6px 8px 12px" }}>
				{filtered.map((c) => (
					<ChatRow key={c.id} chat={c} active={c.id === activeId} onClick={() => onSelect(c.id)} />
				))}
				{filtered.length === 0 && (
					<div
						style={{
							padding: 24,
							textAlign: "center",
							color: "var(--fg-3)",
							fontSize: 13,
						}}
					>
						No chats match &ldquo;{searchQuery}&rdquo;.
					</div>
				)}
			</div>

			{/* Data residency indicator (prd.md §7.6) */}
			{regionId !== null && (
				<div
					data-testid="region-badge"
					style={{
						padding: "8px 16px",
						borderTop: "1px solid var(--border-faint)",
						display: "flex",
						alignItems: "center",
						gap: 6,
						fontSize: 11,
						color: "var(--fg-3)",
						letterSpacing: "0.03em",
					}}
				>
					<Icon name="globe" size={11} color="var(--fg-3)" />
					<span>{regionId}</span>
				</div>
			)}
		</aside>
	);
}

// ── Conversation ──────────────────────────────────────────────────────────────

function ConversationHeader({
	chat,
	onCall,
	onVideo,
	onInfo,
	infoOpen,
	pqBindingHex,
	msgSearch,
	onMsgSearch,
}: {
	chat: Chat;
	onCall: () => void;
	onVideo: () => void;
	onInfo: () => void;
	infoOpen: boolean;
	pqBindingHex?: string;
	msgSearch: string;
	onMsgSearch: (q: string) => void;
}) {
	const [searchOpen, setSearchOpen] = useState(false);

	// Close search when switching conversations so the header resets cleanly.
	// biome-ignore lint/correctness/useExhaustiveDependencies: chat.id is the trigger; setSearchOpen is stable
	useEffect(() => {
		setSearchOpen(false);
	}, [chat.id]);

	const handleOpenSearch = () => setSearchOpen(true);
	const handleCloseSearch = () => {
		setSearchOpen(false);
		onMsgSearch("");
	};

	return (
		<header
			style={{
				height: 64,
				flex: "none",
				padding: "0 18px",
				borderBottom: "1px solid var(--border-soft)",
				display: "flex",
				alignItems: "center",
				gap: 14,
				background: "var(--bg-void)",
			}}
		>
			{searchOpen ? (
				<>
					<Icon name="search" size={16} color="var(--fg-3)" />
					<input
						value={msgSearch}
						onChange={(e) => onMsgSearch(e.target.value)}
						placeholder="Search in conversation..."
						// biome-ignore lint/a11y/noAutofocus: search input opened by explicit user action
						autoFocus
						style={{
							flex: 1,
							background: "transparent",
							border: "none",
							outline: "none",
							color: "var(--fg-1)",
							fontFamily: "var(--font-sans)",
							fontSize: 14,
						}}
					/>
					<IconBtn icon="x" onClick={handleCloseSearch} label="Close search" size={28} />
				</>
			) : (
				<>
					<Avatar name={chat.name} size={38} online={chat.online} />
					<div style={{ flex: 1, minWidth: 0 }}>
						<div style={{ display: "flex", alignItems: "center", gap: 8 }}>
							<span style={{ fontSize: 15, fontWeight: 500, color: "var(--fg-1)" }}>
								{chat.name}
							</span>
							<Icon name="lock" size={11} color="#A8C8FF" />
							{pqBindingHex && (
								<span
									title={`PQ binding: ${pqBindingHex}`}
									style={{
										fontSize: 9,
										fontWeight: 600,
										letterSpacing: "0.06em",
										color: "#A8C8FF",
										background: "rgba(168,200,255,0.12)",
										border: "1px solid rgba(168,200,255,0.3)",
										borderRadius: 4,
										padding: "1px 5px",
									}}
								>
									PQ
								</span>
							)}
						</div>
						<div style={{ fontSize: 11, color: "var(--fg-3)", marginTop: 1 }}>
							{chat.online ? "online" : `last seen ${chat.lastSeen ?? "recently"}`}
							{chat.typing && (
								<span style={{ color: "#FF9E52", marginLeft: 8, fontStyle: "italic" }}>
									· typing
								</span>
							)}
						</div>
					</div>
					<div style={{ display: "flex", gap: 2 }}>
						<IconBtn icon="search" onClick={handleOpenSearch} label="Search in conversation" />
						<IconBtn icon="phone" onClick={onCall} label="Voice call" />
						<IconBtn icon="video" onClick={onVideo} label="Video call" />
						<IconBtn icon="more-horizontal" onClick={onInfo} active={infoOpen} label="Info" />
					</div>
				</>
			)}
		</header>
	);
}

function MessageBubble({
	msg,
	partner,
	highlight,
	onReact,
}: {
	msg: ChatMessage;
	partner: string;
	highlight?: string;
	onReact?: (emoji: string) => void;
}) {
	const isMe = msg.from === "me";
	const [pickerOpen, setPickerOpen] = useState(false);
	const reactionEntries = msg.reactions ? Object.entries(msg.reactions) : [];

	return (
		<div
			style={{
				display: "flex",
				flexDirection: "column",
				alignItems: isMe ? "flex-end" : "flex-start",
				marginTop: msg.continued ? 2 : 8,
			}}
		>
			<div
				style={{
					display: "flex",
					justifyContent: isMe ? "flex-end" : "flex-start",
					alignItems: "flex-end",
					gap: 8,
					width: "100%",
				}}
			>
				{!isMe && (
					<div style={{ width: 28, flex: "none" }}>
						{!msg.continued && <Avatar name={partner} size={28} />}
					</div>
				)}
				<div style={{ position: "relative", maxWidth: "72%" }}>
					<div
						style={{
							padding: "10px 14px",
							fontSize: 14,
							lineHeight: 1.45,
							borderRadius: 18,
							...(isMe
								? {
										background: "linear-gradient(135deg, #FF9E52, #F26F1F)",
										color: "#2A1100",
										borderBottomRightRadius: msg.last ? 6 : 18,
										boxShadow: "0 0 18px rgba(255,138,61,0.18)",
									}
								: {
										background: "var(--bg-elevated)",
										color: "var(--fg-1)",
										border: "1px solid var(--border-faint)",
										borderBottomLeftRadius: msg.last ? 6 : 18,
									}),
						}}
					>
						{msg.media ? (
							<MediaImage media={msg.media} />
						) : (
							<HighlightedText text={msg.text} highlight={highlight ?? ""} />
						)}
						{msg.last && msg.time && (
							<span
								style={{
									display: "inline-flex",
									alignItems: "center",
									gap: 4,
									marginLeft: 8,
									opacity: 0.7,
									fontSize: 10,
									fontFamily: "var(--font-mono)",
									verticalAlign: "2px",
								}}
							>
								{msg.time}
								{isMe && (
									<span data-testid="read-indicator" aria-label={msg.read ? "Read" : "Sent"}>
										<Icon
											name="doublecheck"
											size={12}
											color={msg.read ? "#A8C8FF" : "currentColor"}
										/>
									</span>
								)}
							</span>
						)}
						{msg.expiresAt && (
							<div
								style={{
									display: "flex",
									alignItems: "center",
									gap: 3,
									marginTop: 4,
									fontSize: 10,
									color: "#FF9E52",
									opacity: 0.85,
								}}
							>
								<Icon name="timer" size={10} color="#FF9E52" />
								<span>Disappearing</span>
							</div>
						)}
					</div>

					{/* Reaction picker trigger — only shown when message has a stable ID */}
					{onReact && msg.id && (
						<div
							style={{
								position: "absolute",
								bottom: -10,
								...(isMe ? { left: -28 } : { right: -28 }),
							}}
						>
							<button
								type="button"
								onClick={() => setPickerOpen((p) => !p)}
								aria-label="Add reaction"
								data-testid="reaction-trigger"
								style={{
									width: 22,
									height: 22,
									borderRadius: "50%",
									border: "1px solid var(--border-faint)",
									background: "var(--bg-elevated)",
									color: "var(--fg-3)",
									fontSize: 11,
									cursor: "pointer",
									display: "flex",
									alignItems: "center",
									justifyContent: "center",
									padding: 0,
								}}
							>
								+
							</button>

							{pickerOpen && (
								<div
									data-testid="reaction-picker"
									style={{
										position: "absolute",
										bottom: 28,
										...(isMe ? { right: 0 } : { left: 0 }),
										display: "flex",
										gap: 4,
										padding: "6px 8px",
										background: "var(--bg-elevated)",
										border: "1px solid var(--border-faint)",
										borderRadius: 20,
										boxShadow: "0 4px 16px rgba(0,0,0,0.4)",
										zIndex: 10,
									}}
								>
									{ALLOWED_REACTION_EMOJIS.map((e) => (
										<button
											key={e}
											type="button"
											onClick={() => {
												onReact(e);
												setPickerOpen(false);
											}}
											data-testid={`reaction-emoji-${e}`}
											style={{
												background: "none",
												border: "none",
												cursor: "pointer",
												fontSize: 18,
												padding: "2px 3px",
												borderRadius: 6,
												lineHeight: 1,
											}}
										>
											{e}
										</button>
									))}
								</div>
							)}
						</div>
					)}
				</div>
			</div>

			{/* Reaction chips row — rendered below the bubble */}
			{reactionEntries.length > 0 && (
				<div
					data-testid="reaction-chips"
					style={{
						display: "flex",
						gap: 4,
						marginTop: 4,
						flexWrap: "wrap",
						paddingLeft: isMe ? 0 : 36,
					}}
				>
					{reactionEntries.map(([emoji, senders]) => (
						<button
							key={emoji}
							type="button"
							onClick={() => onReact?.(emoji)}
							data-testid={`reaction-chip-${emoji}`}
							style={{
								background: "rgba(255,255,255,0.06)",
								border: "1px solid rgba(255,255,255,0.12)",
								borderRadius: 12,
								padding: "2px 8px",
								fontSize: 12,
								cursor: "pointer",
								display: "inline-flex",
								alignItems: "center",
								gap: 4,
								color: "var(--fg-2)",
							}}
						>
							{emoji}
							<span style={{ fontSize: 10, opacity: 0.75 }}>{senders.length}</span>
						</button>
					))}
				</div>
			)}
		</div>
	);
}

// Stable key for a message group entry — day labels use their text,
// messages use their position relative to day label.
type Group =
	| { type: "day"; label: string; key: string }
	| { type: "msg"; msg: ChatMessage; key: string };

function buildGroups(messages: ChatMessage[]): Group[] {
	const groups: Group[] = [];
	let lastDay: string | undefined = undefined;
	let dayMsgCount = 0;
	for (const m of messages) {
		if (m.day && m.day !== lastDay) {
			groups.push({ type: "day", label: m.day, key: `day-${m.day}` });
			lastDay = m.day;
			dayMsgCount = 0;
		}
		groups.push({
			type: "msg",
			msg: m,
			key: `msg-${lastDay ?? "no-day"}-${dayMsgCount++}-${m.from}-${m.text.slice(0, 8)}`,
		});
	}
	return groups;
}

function MessageList({
	messages,
	partner,
	searchQuery,
	onReact,
}: {
	messages: ChatMessage[];
	partner: string;
	searchQuery?: string;
	onReact?: (msgId: string, emoji: string) => void;
}) {
	const ref = useRef<HTMLDivElement>(null);

	useLayoutEffect(() => {
		if (ref.current) ref.current.scrollTop = ref.current.scrollHeight;
	});

	const groups = buildGroups(messages);

	const matchCount = searchQuery
		? messages.filter((m) => !m.media && m.text.toLowerCase().includes(searchQuery.toLowerCase()))
				.length
		: 0;

	return (
		<div
			ref={ref}
			style={{
				flex: 1,
				overflowY: "auto",
				padding: "24px 36px 16px",
				display: "flex",
				flexDirection: "column",
				gap: 4,
				background:
					"radial-gradient(ellipse 100% 60% at 50% 110%, rgba(255,138,61,0.07), transparent 60%), var(--bg-void)",
			}}
		>
			{/* Search results count — shown when in-conversation search is active */}
			{searchQuery && (
				<div
					style={{
						alignSelf: "center",
						padding: "5px 14px",
						marginBottom: 8,
						background: "rgba(255,138,61,0.08)",
						border: "1px solid rgba(255,138,61,0.22)",
						borderRadius: 20,
						fontSize: 11,
						color: "var(--fg-2)",
						letterSpacing: "0.03em",
					}}
					aria-live="polite"
				>
					{matchCount === 0
						? "No matches"
						: `${matchCount} ${matchCount === 1 ? "match" : "matches"}`}
				</div>
			)}

			{/* E2EE notice */}
			<div
				style={{
					alignSelf: "center",
					maxWidth: 480,
					textAlign: "center",
					padding: "14px 20px",
					margin: "8px 0 24px",
					background: "rgba(168,200,255,0.05)",
					border: "1px solid rgba(168,200,255,0.18)",
					borderRadius: 12,
				}}
			>
				<div
					style={{
						display: "inline-flex",
						alignItems: "center",
						gap: 6,
						fontSize: 11,
						fontWeight: 500,
						letterSpacing: "0.12em",
						color: "#C8DCFF",
						textTransform: "uppercase",
						marginBottom: 6,
					}}
				>
					<Icon name="lock" size={11} color="#A8C8FF" /> End-to-end encrypted
				</div>
				<div style={{ fontSize: 12, color: "var(--fg-3)", lineHeight: 1.5 }}>
					Only you and {partner.split(" ")[0]} can read these messages. Not even Powehi.
				</div>
			</div>

			{groups.map((g) =>
				g.type === "day" ? (
					<div
						key={g.key}
						style={{
							alignSelf: "center",
							margin: "12px 0 6px",
							fontSize: 10,
							fontWeight: 500,
							letterSpacing: "0.14em",
							color: "var(--fg-4)",
							textTransform: "uppercase",
						}}
					>
						{g.label}
					</div>
				) : (
					<MessageBubble
						key={g.key}
						msg={g.msg}
						partner={partner}
						highlight={searchQuery}
						onReact={
							g.msg.id && onReact
								? (emoji) => {
										const id = g.msg.id;
										if (id) onReact(id, emoji);
									}
								: undefined
						}
					/>
				),
			)}
		</div>
	);
}

function Composer({
	onSend,
	partner,
	ttl,
	onToggleTtl,
	onPhoto,
	onTyping,
}: {
	onSend: (text: string) => void;
	partner: string;
	ttl: TtlOption;
	onToggleTtl: () => void;
	/** Triggered when the user clicks the Photo button. */
	onPhoto?: () => void;
	/** Called on each keystroke so ChatLayout can throttle-send typing_indicator messages. */
	onTyping?: () => void;
}) {
	const [text, setText] = useState("");
	const send = () => {
		if (text.trim()) {
			onSend(text.trim());
			setText("");
		}
	};
	const handleKeyDown = (e: KeyboardEvent<HTMLTextAreaElement>) => {
		if (e.key === "Enter" && !e.shiftKey) {
			e.preventDefault();
			send();
		}
	};

	return (
		<div
			style={{
				flex: "none",
				padding: "12px 24px 18px",
				background: "var(--bg-void)",
			}}
		>
			<div
				style={{
					background: "var(--bg-surface)",
					border: "1px solid var(--border-soft)",
					borderRadius: 16,
					display: "flex",
					alignItems: "flex-end",
					gap: 4,
					padding: "6px 6px 6px 14px",
				}}
			>
				<IconBtn icon="attach" label="Attach" size={32} />
				<IconBtn icon="image" label="Photo" size={32} onClick={onPhoto} />
				<button
					type="button"
					onClick={onToggleTtl}
					aria-label={ttl ? `Disappearing: ${formatTtl(ttl)}` : "Set disappearing timer"}
					title={ttl ? `Disappearing: ${formatTtl(ttl)}` : "Set disappearing timer"}
					style={{
						display: "inline-flex",
						alignItems: "center",
						gap: 3,
						padding: "4px 6px",
						borderRadius: 8,
						border: "1px solid",
						borderColor: ttl ? "rgba(255,158,82,0.4)" : "transparent",
						background: ttl ? "rgba(255,158,82,0.1)" : "transparent",
						color: ttl ? "#FF9E52" : "var(--fg-3)",
						cursor: "pointer",
						fontSize: 10,
						fontFamily: "var(--font-mono)",
						height: 32,
						transition: "all 160ms",
					}}
				>
					<Icon name="timer" size={14} color={ttl ? "#FF9E52" : undefined} />
					{ttl && <span>{formatTtl(ttl)}</span>}
				</button>
				<textarea
					value={text}
					onChange={(e) => {
						setText(e.target.value);
						onTyping?.();
					}}
					onKeyDown={handleKeyDown}
					placeholder={`Message ${partner.split(" ")[0]} — encrypted`}
					rows={1}
					style={{
						flex: 1,
						background: "transparent",
						border: "none",
						outline: "none",
						color: "var(--fg-1)",
						fontFamily: "var(--font-sans)",
						fontSize: 14,
						resize: "none",
						padding: "8px 8px 8px 4px",
						maxHeight: 120,
						lineHeight: 1.4,
					}}
				/>
				<IconBtn icon="smile" label="Emoji" size={32} />
				{text.trim() ? (
					<button
						type="button"
						onClick={send}
						aria-label="Send message"
						style={{
							width: 36,
							height: 36,
							borderRadius: "50%",
							border: "none",
							background: "linear-gradient(180deg, #FF9E52, #FF7A2B)",
							color: "#2A0A00",
							display: "flex",
							alignItems: "center",
							justifyContent: "center",
							cursor: "pointer",
							boxShadow: "0 0 0 1px rgba(255,138,61,0.35), 0 0 14px rgba(255,138,61,0.3)",
							transition: "transform 120ms",
						}}
					>
						<Icon name="arrow-right" size={16} />
					</button>
				) : (
					<IconBtn icon="mic" label="Voice" size={36} />
				)}
			</div>
		</div>
	);
}

// ── InfoPanel ─────────────────────────────────────────────────────────────────

function InfoSection({
	title,
	children,
}: {
	title: string;
	children: React.ReactNode;
}) {
	return (
		<div style={{ borderTop: "1px solid var(--border-faint)" }}>
			<div
				style={{
					fontSize: 10,
					fontWeight: 500,
					letterSpacing: "0.14em",
					textTransform: "uppercase",
					color: "var(--fg-3)",
					padding: "14px 18px 4px",
				}}
			>
				{title}
			</div>
			{children}
		</div>
	);
}

function InfoRow({ label, trailing }: { label: string; trailing: string }) {
	return (
		<div
			style={{
				display: "flex",
				justifyContent: "space-between",
				padding: "10px 18px",
				fontSize: 13,
			}}
		>
			<span style={{ color: "var(--fg-1)" }}>{label}</span>
			<span style={{ color: "var(--fg-3)" }}>{trailing}</span>
		</div>
	);
}

function InfoPanel({
	chat,
	onClose,
	disappearingTtl,
}: {
	chat: Chat;
	onClose: () => void;
	disappearingTtl: TtlOption;
}) {
	const [safetyVerified, setSafetyVerified] = useState(false);
	const [verifiedAt, setVerifiedAt] = useState<number | undefined>(undefined);
	const [mitmAlert, setMitmAlert] = useState(false);
	const [computedSafetyNumber, setComputedSafetyNumber] = useState<string | null>(null);
	// useCryptoWorker() returns a module-level singleton — stable across re-renders.
	const cryptoWorker = useCryptoWorker();
	// EncryptedPowehiDb wraps the raw Dexie instance with AES-GCM-256 field encryption.
	// The CryptoKey lives in the worker; this wrapper never observes raw key bytes.
	// null when worker unavailable — all DB paths fail closed in that case.
	const encryptedDb = useMemo(
		() => (cryptoWorker ? new EncryptedPowehiDb(db, cryptoWorker) : null),
		[cryptoWorker],
	);

	// Compute the safety number from the MLS group members' Ed25519 signature keys.
	// Fails closed: if WASM unavailable or group not yet established, stays null.
	useEffect(() => {
		const worker = cryptoWorker;
		// Reset immediately so a stale value from a previous chat never triggers a
		// false MITM alarm during the async WASM call for the new chat (Y2).
		setComputedSafetyNumber(null);
		if (!worker || !chat.mlsGroupId || !chat.mlsIdentityId) {
			return;
		}
		let cancelled = false;
		const hexToBytes = (hex: string): Uint8Array => {
			if (hex.length % 2 !== 0 || !/^[0-9a-fA-F]+$/.test(hex)) throw new Error("invalid hex");
			const bytes = new Uint8Array(hex.length / 2);
			for (let i = 0; i < bytes.length; i++) {
				bytes[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
			}
			return bytes;
		};
		worker
			.mlsGroupMembers(chat.mlsIdentityId, chat.mlsGroupId)
			.then((members) => {
				// Require exactly 2 members — fail-closed for groups with >2 members.
				if (cancelled || members.length !== 2) return undefined;
				return worker.mlsComputeSafetyNumber(
					hexToBytes(members[0].sigKeyHex),
					hexToBytes(members[1].sigKeyHex),
				);
			})
			.then((result) => {
				if (cancelled || !result) return;
				setComputedSafetyNumber(result.safetyNumber);
			})
			.catch(() => {
				// Fail closed — WASM error or group absent (no-plaintext-logging invariant).
			});
		return () => {
			cancelled = true;
		};
	}, [cryptoWorker, chat.mlsGroupId, chat.mlsIdentityId]);

	// Load stored verification state; re-runs when computedSafetyNumber arrives so
	// MITM detection works even when WASM loads after the DB read completes.
	useEffect(() => {
		if (!encryptedDb) return;
		let cancelled = false;
		encryptedDb
			.getVerifiedContact(chat.id)
			.then((stored) => {
				if (cancelled) return;
				if (stored) {
					setSafetyVerified(true);
					setVerifiedAt(stored.verifiedAt);
					// MITM alert only when we have a computed value to compare.
					// Fail closed: if WASM unavailable (computed=null), do not false-alarm.
					setMitmAlert(
						computedSafetyNumber !== null && stored.safetyNumber !== computedSafetyNumber,
					);
				} else {
					setSafetyVerified(false);
					setVerifiedAt(undefined);
					setMitmAlert(false);
				}
			})
			.catch(() => {
				// DB read error — leave state as unverified (no-plaintext-logging).
				if (!cancelled) {
					setSafetyVerified(false);
					setVerifiedAt(undefined);
					setMitmAlert(false);
				}
			});
		return () => {
			cancelled = true;
		};
	}, [chat.id, computedSafetyNumber, encryptedDb]);

	const handleVerify = async () => {
		// Fail closed — cannot verify without a computed safety number or encrypted DB.
		if (computedSafetyNumber === null || !encryptedDb) return;
		await encryptedDb.putVerifiedContact({
			contactId: chat.id,
			safetyNumber: computedSafetyNumber,
			verifiedAt: Date.now(),
		});
		setSafetyVerified(true);
		setVerifiedAt(Date.now());
		setMitmAlert(false);
	};

	const handleReset = async () => {
		if (encryptedDb) await encryptedDb.deleteVerifiedContact(chat.id);
		setSafetyVerified(false);
		setVerifiedAt(undefined);
		setMitmAlert(false);
	};

	const destructiveButton: CSSProperties = {
		textAlign: "left",
		background: "transparent",
		border: "none",
		color: "#FF9999",
		padding: "10px 0",
		fontFamily: "var(--font-sans)",
		fontSize: 13,
		fontWeight: 500,
		cursor: "pointer",
		width: "100%",
	};

	return (
		<aside
			style={{
				width: 340,
				flex: "none",
				background: "var(--bg-surface)",
				borderLeft: "1px solid var(--border-soft)",
				display: "flex",
				flexDirection: "column",
				height: "100%",
				overflowY: "auto",
			}}
		>
			{/* Header */}
			<div
				style={{
					padding: "14px 18px",
					display: "flex",
					alignItems: "center",
					justifyContent: "space-between",
					borderBottom: "1px solid var(--border-faint)",
				}}
			>
				<span
					style={{
						fontSize: 11,
						fontWeight: 500,
						letterSpacing: "0.14em",
						textTransform: "uppercase",
						color: "var(--fg-3)",
					}}
				>
					Conversation
				</span>
				<IconBtn icon="x" onClick={onClose} label="Close" size={28} />
			</div>

			{/* User info */}
			<div style={{ padding: "24px 18px 20px", textAlign: "center" }}>
				<Avatar name={chat.name} size={80} />
				<div
					style={{
						fontSize: 18,
						fontWeight: 500,
						color: "var(--fg-1)",
						marginTop: 14,
					}}
				>
					{chat.name}
				</div>
				<div style={{ fontSize: 13, color: "var(--fg-3)", marginTop: 4 }}>@{chat.handle}</div>
				<div
					style={{
						display: "flex",
						gap: 8,
						justifyContent: "center",
						marginTop: 16,
					}}
				>
					<button
						type="button"
						aria-label="Call"
						style={{
							display: "inline-flex",
							alignItems: "center",
							gap: 6,
							padding: "7px 12px",
							fontSize: 13,
							fontFamily: "var(--font-sans)",
							fontWeight: 500,
							background: "var(--bg-elevated)",
							color: "var(--fg-1)",
							border: "1px solid var(--border-soft)",
							borderRadius: 8,
							cursor: "pointer",
						}}
					>
						<Icon name="phone" size={14} />
						Call
					</button>
					<button
						type="button"
						aria-label="Video"
						style={{
							display: "inline-flex",
							alignItems: "center",
							gap: 6,
							padding: "7px 12px",
							fontSize: 13,
							fontFamily: "var(--font-sans)",
							fontWeight: 500,
							background: "var(--bg-elevated)",
							color: "var(--fg-1)",
							border: "1px solid var(--border-soft)",
							borderRadius: 8,
							cursor: "pointer",
						}}
					>
						<Icon name="video" size={14} />
						Video
					</button>
				</div>
			</div>

			{/* Safety Numbers — photon blue encryption verification card */}
			<div style={{ padding: "0 14px 16px" }}>
				<div
					style={{
						background: "rgba(168,200,255,0.05)",
						border: "1px solid rgba(168,200,255,0.22)",
						borderRadius: 14,
						padding: 16,
					}}
				>
					<div
						style={{
							display: "flex",
							alignItems: "center",
							gap: 8,
							marginBottom: 12,
						}}
					>
						<Icon name="lock" size={14} color="#A8C8FF" />
						<span
							style={{
								fontSize: 11,
								fontWeight: 600,
								letterSpacing: "0.1em",
								textTransform: "uppercase",
								color: "#A8C8FF",
							}}
						>
							Safety Numbers
						</span>
					</div>
					{mitmAlert && (
						<div
							style={{
								display: "flex",
								alignItems: "center",
								gap: 8,
								background: "rgba(255,100,100,0.08)",
								border: "1px solid rgba(255,100,100,0.3)",
								borderRadius: 9,
								padding: "8px 10px",
								marginBottom: 10,
							}}
						>
							<Icon name="alert" size={14} color="#FF9999" />
							<span style={{ fontSize: 12, color: "#FF9999" }}>
								Safety number changed — verify again to confirm identity
							</span>
						</div>
					)}
					{computedSafetyNumber !== null ? (
						<SafetyNumbers
							safetyNumber={computedSafetyNumber}
							peerName={chat.name}
							verified={safetyVerified}
							verifiedAt={verifiedAt}
							onVerify={handleVerify}
							onReset={handleReset}
						/>
					) : (
						<div
							style={{
								padding: "12px 0 4px",
								fontSize: 12,
								color: "var(--fg-3)",
								textAlign: "center",
							}}
						>
							Safety number not available
						</div>
					)}
				</div>
			</div>

			<InfoSection title="Notifications">
				<InfoRow label="Mute" trailing="Off" />
				<InfoRow label="Pin to top" trailing="On" />
			</InfoSection>
			<InfoSection title="Disappearing messages">
				<InfoRow label="Auto-delete after" trailing={formatTtl(disappearingTtl)} />
			</InfoSection>
			<InfoSection title="Media">
				<div
					style={{
						display: "grid",
						gridTemplateColumns: "repeat(3, 1fr)",
						gap: 6,
						padding: "4px 18px 16px",
					}}
				>
					{[0, 1, 2, 3, 4, 5].map((i) => (
						<div
							key={i}
							style={{
								aspectRatio: "1/1",
								borderRadius: 8,
								background: `linear-gradient(135deg, hsl(${i * 40 + 20}, 40%, 28%), hsl(${i * 40 + 220}, 35%, 10%))`,
							}}
						/>
					))}
				</div>
			</InfoSection>

			<div
				style={{
					padding: "8px 18px 24px",
					display: "flex",
					flexDirection: "column",
					gap: 4,
				}}
			>
				<button type="button" style={destructiveButton}>
					Clear messages
				</button>
				<button type="button" style={destructiveButton}>
					Block · Report
				</button>
			</div>
		</aside>
	);
}

// ── ChatLayout (root export) ──────────────────────────────────────────────────

export function ChatLayout() {
	const [chats, setChats] = useState<Chat[]>(SEED_CHATS);
	const [activeId, setActiveId] = useState("maya");
	const [search, setSearch] = useState("");
	const [infoOpen, setInfoOpen] = useState(false);
	const [inviteOpen, setInviteOpen] = useState(false);
	const [disappearingTtl, setDisappearingTtl] = useState<TtlOption>(undefined);
	const [msgSearch, setMsgSearch] = useState("");

	// Stable ref so handleIncoming (useCallback) can read current activeId without
	// re-creating on every chat switch — avoids restarting the polling hook.
	const activeIdRef = useRef(activeId);
	useEffect(() => {
		activeIdRef.current = activeId;
	}, [activeId]);

	// Tracks auto-clear timers for peer typing indicators, keyed by mlsGroupId.
	// Stored in a ref so setChats callbacks can mutate it without triggering re-renders.
	const typingTimersRef = useRef<Map<string, ReturnType<typeof setTimeout>>>(new Map());
	useEffect(() => {
		const timers = typingTimersRef.current;
		return () => {
			for (const handle of timers.values()) clearTimeout(handle);
		};
	}, []);

	// Throttle ref for outgoing typing indicator signals (leading-edge, 3 s window).
	const typingThrottleRef = useRef<ReturnType<typeof setTimeout> | null>(null);

	// Ref holds the latest sendReadReceipt closure so handleIncoming (stable useCallback)
	// can call it without taking a dep on active/sessionToken/cryptoWorker.
	const sendReadReceiptRef = useRef<(ids: string[]) => void>(() => {});

	// Reset in-conversation search when switching chats.
	// biome-ignore lint/correctness/useExhaustiveDependencies: activeId is the trigger; setMsgSearch is stable
	useEffect(() => {
		setMsgSearch("");
	}, [activeId]);
	const active = chats.find((c) => c.id === activeId);

	const { sessionToken, identityId } = useAuthStore();
	const cryptoWorker = useCryptoWorker();
	const { persistIncoming, persistOutgoing, purgeExpired } = usePersistentMessages(
		active?.mlsGroupId,
	);
	const fileInputRef = useRef<HTMLInputElement>(null);
	const { sendMedia } = useMediaSend({
		identityId: active?.mlsIdentityId,
		groupId: active?.mlsGroupId,
	});

	// Load persisted disappearing timer when the active conversation changes.
	useEffect(() => {
		let cancelled = false;
		if (!active?.mlsGroupId) {
			setDisappearingTtl(undefined);
			return;
		}
		const groupId = active.mlsGroupId;
		db.groups
			.get(groupId)
			.then((row) => {
				if (cancelled) return;
				const persisted = row?.disappearingTtlSeconds;
				setDisappearingTtl(
					TTL_OPTIONS.includes(persisted as TtlOption) ? (persisted as TtlOption) : undefined,
				);
			})
			.catch(() => {
				if (!cancelled) setDisappearingTtl(undefined);
			});
		return () => {
			cancelled = true;
		};
	}, [active?.mlsGroupId]);

	const handleToggleTtl = () => {
		const next = nextTtl(disappearingTtl);
		setDisappearingTtl(next);
		if (active?.mlsGroupId) {
			db.groups.update(active.mlsGroupId, { disappearingTtlSeconds: next }).catch(() => {});
		}
	};

	/** Append a received message to the correct chat and persist it to Dexie. */
	const handleIncoming = useCallback(
		(msg: IncomingMessage) => {
			setChats((cs) =>
				cs.map((c) => {
					if (c.mlsGroupId !== msg.groupId) return c;
					const now = new Date();
					const time = `${String(now.getHours()).padStart(2, "0")}:${String(now.getMinutes()).padStart(2, "0")}`;
					const msgs = [...c.messages];
					for (let i = msgs.length - 1; i >= 0; i--) {
						if (msgs[i].from === "them" && msgs[i].last) {
							msgs[i] = { ...msgs[i], last: false, continued: true };
							break;
						}
					}
					const displayText = msg.media ? "Image attachment" : msg.text;
					msgs.push({
						id: msg.id,
						from: "them",
						text: displayText,
						last: true,
						time,
						continued: msgs.length > 0 && msgs[msgs.length - 1].from === "them",
						media: msg.media,
						expiresAt: msg.expiresAt,
					});
					// Increment unread only when the message arrives for a background chat.
					// activeIdRef.current reflects the current selection without making this
					// callback re-create on every chat switch.
					const isActive = c.id === activeIdRef.current;
					return {
						...c,
						messages: msgs,
						last: displayText,
						time,
						unread: isActive ? 0 : c.unread + 1,
					};
				}),
			);
			// Encrypt and persist to IndexedDB — fails closed if encryptedDb unavailable.
			persistIncoming(msg);
			// Notify sender that we read the message (best-effort, fire-and-forget).
			sendReadReceiptRef.current([msg.id]);
		},
		[persistIncoming],
	);

	/** Handle file selected via the hidden input — encrypt and send as §9.2 media message. */
	const handleFileSelect = useCallback(
		(e: React.ChangeEvent<HTMLInputElement>) => {
			const file = e.target.files?.[0];
			if (!file) return;
			// Reset so the same file can be re-selected.
			e.target.value = "";

			// Optimistic local update showing a placeholder.
			const now = new Date();
			const time = `${String(now.getHours()).padStart(2, "0")}:${String(now.getMinutes()).padStart(2, "0")}`;
			setChats((cs) =>
				cs.map((c) => {
					if (c.id !== activeId) return c;
					const msgs = [...c.messages];
					for (let i = msgs.length - 1; i >= 0; i--) {
						if (msgs[i].from === "me" && msgs[i].last) {
							msgs[i] = { ...msgs[i], last: false, continued: true };
							break;
						}
					}
					msgs.push({
						from: "me",
						text: "Image attachment",
						last: true,
						time,
						read: false,
						continued: msgs.length > 0 && msgs[msgs.length - 1].from === "me",
					});
					return { ...c, messages: msgs, last: "Image attachment", time };
				}),
			);

			// Async send — silent failure leaves optimistic placeholder.
			sendMedia(file).catch(() => {});
		},
		[activeId, sendMedia],
	);

	/** Record the PQ group binding once the pq_init exchange completes (§5.3 Phase B). */
	const handlePqBinding = useCallback((groupId: string, bindingHex: string) => {
		setChats((cs) =>
			cs.map((c) => (c.mlsGroupId === groupId ? { ...c, pqBindingHex: bindingHex } : c)),
		);
	}, []);

	/**
	 * Show "typing..." for the peer in the matching chat. Auto-clears after 3 s.
	 * Multiple signals within the 3 s window reset the timer (debounced clear).
	 */
	const handleIncomingTyping = useCallback((gId: string) => {
		const existing = typingTimersRef.current.get(gId);
		if (existing !== undefined) clearTimeout(existing);
		setChats((cs) => cs.map((c) => (c.mlsGroupId === gId ? { ...c, typing: true } : c)));
		const handle = setTimeout(() => {
			typingTimersRef.current.delete(gId);
			setChats((cs) => cs.map((c) => (c.mlsGroupId === gId ? { ...c, typing: false } : c)));
		}, 3_000);
		typingTimersRef.current.set(gId, handle);
	}, []);

	/**
	 * Apply an incoming emoji reaction to the target message in the matching chat.
	 * Deduplicates: a sender reacting twice with the same emoji is a no-op.
	 */
	const handleIncomingReaction = useCallback(
		(gId: string, targetId: string, emoji: string, senderId: string) => {
			setChats((cs) =>
				cs.map((c) => {
					if (c.mlsGroupId !== gId) return c;
					const msgs = c.messages.map((m) => {
						if (m.id !== targetId) return m;
						const existing = m.reactions ?? {};
						const senders = existing[emoji] ?? [];
						if (senders.includes(senderId)) return m;
						return { ...m, reactions: { ...existing, [emoji]: [...senders, senderId] } };
					});
					return { ...c, messages: msgs };
				}),
			);
		},
		[],
	);

	/**
	 * Send an emoji reaction to the active MLS group targeting a specific message.
	 * Optimistically applies the reaction locally before the server echo arrives.
	 * Fire-and-forget — failure leaves the optimistic update in place (best-effort UX).
	 */
	const sendReaction = useCallback(
		(targetId: string, emoji: string) => {
			if (!(ALLOWED_REACTION_EMOJIS as readonly string[]).includes(emoji)) return;
			if (!sessionToken || !active?.mlsGroupId || !active?.mlsIdentityId || !cryptoWorker) return;
			const { mlsGroupId, mlsIdentityId } = active;
			const myDeviceId = useAuthStore.getState().deviceId;
			if (myDeviceId) {
				handleIncomingReaction(mlsGroupId, targetId, emoji, myDeviceId);
			}
			const plaintext = new TextEncoder().encode(
				JSON.stringify({ type: "reaction", emoji, targetMessageId: targetId }),
			);
			cryptoWorker
				.mlsEncrypt(mlsIdentityId, mlsGroupId, plaintext)
				.then(({ ciphertext }) => sendMessageApi(sessionToken, mlsGroupId, ciphertext, undefined))
				.catch(() => {})
				.finally(() => plaintext.fill(0));
		},
		[active, cryptoWorker, handleIncomingReaction, sessionToken],
	);

	/**
	 * Mark messages as read when a peer's read_receipt arrives.
	 * Updates `read: true` on all messages (regardless of `from`) whose `id` is in `messageIds`.
	 * The read indicator UI only renders for `from === "me"` messages, so the update is harmless
	 * for peer messages that happen to share an ID with a receipt.
	 */
	const handleIncomingReadReceipt = useCallback(
		(gId: string, messageIds: string[], _readAt: number, _senderDeviceId: string) => {
			const idSet = new Set(messageIds);
			setChats((cs) =>
				cs.map((c) => {
					if (c.mlsGroupId !== gId) return c;
					const msgs = c.messages.map((m) => (m.id && idSet.has(m.id) ? { ...m, read: true } : m));
					return { ...c, messages: msgs };
				}),
			);
		},
		[],
	);

	/**
	 * Send a read_receipt to the active MLS group for the given envelope IDs.
	 * Fire-and-forget — a failed receipt is non-fatal (the UI shows "sent" vs "read" state).
	 * Not a useCallback: re-created each render so it always closes over current state.
	 * Exposed via sendReadReceiptRef so stable callbacks (handleIncoming) can call it.
	 */
	const sendReadReceipt = (messageIds: string[]) => {
		if (!sessionToken || !active?.mlsGroupId || !active?.mlsIdentityId || !cryptoWorker) return;
		const { mlsGroupId, mlsIdentityId } = active;
		const plaintext = new TextEncoder().encode(
			JSON.stringify({ type: "read_receipt", messageIds, readAt: Date.now() }),
		);
		cryptoWorker
			.mlsEncrypt(mlsIdentityId, mlsGroupId, plaintext)
			.then(({ ciphertext }) => sendMessageApi(sessionToken, mlsGroupId, ciphertext, undefined))
			.catch(() => {})
			.finally(() => plaintext.fill(0));
	};

	// Keep the ref fresh every render so handleIncoming always invokes the latest closure.
	useEffect(() => {
		sendReadReceiptRef.current = sendReadReceipt;
	});

	/**
	 * Send a typing_indicator signal to the active MLS group.
	 * Leading-edge throttled to once per 3 s (matches the receiver's display window).
	 * Fire-and-forget — failure is silently ignored (non-fatal UX signal).
	 */
	const sendTypingIndicator = () => {
		if (typingThrottleRef.current) return;
		if (!sessionToken || !active?.mlsGroupId || !active?.mlsIdentityId || !cryptoWorker) return;
		const { mlsGroupId, mlsIdentityId } = active;

		typingThrottleRef.current = setTimeout(() => {
			typingThrottleRef.current = null;
		}, 3_000);

		const plaintext = new TextEncoder().encode(JSON.stringify({ type: "typing_indicator" }));
		cryptoWorker
			.mlsEncrypt(mlsIdentityId, mlsGroupId, plaintext)
			.then(({ ciphertext }) => sendMessageApi(sessionToken, mlsGroupId, ciphertext, undefined))
			.catch(() => {})
			.finally(() => plaintext.fill(0));
	};

	// Poll for incoming messages whenever there's an active MLS group + session.
	useMessages(
		active?.mlsIdentityId,
		active?.mlsGroupId,
		handleIncoming,
		handlePqBinding,
		handleIncomingTyping,
		handleIncomingReaction,
		handleIncomingReadReceipt,
	);

	/** Select a chat and clear its unread badge atomically. */
	const handleSelectChat = useCallback((id: string) => {
		setActiveId(id);
		setChats((cs) => cs.map((c) => (c.id === id ? { ...c, unread: 0 } : c)));
	}, []);

	// Add a new chat entry when another device invites us (Welcome envelope received).
	const handleNewGroup = useCallback(
		(event: NewGroupEvent) => {
			setChats((prev) => {
				if (prev.some((c) => c.mlsGroupId === event.groupId)) return prev;
				const shortId = event.senderDeviceId.slice(0, 8);
				const now = new Date();
				const time = `${String(now.getHours()).padStart(2, "0")}:${String(now.getMinutes()).padStart(2, "0")}`;
				return [
					{
						id: event.groupId,
						name: `Contact ${shortId}`,
						handle: shortId,
						online: false,
						last: "",
						time,
						unread: 1,
						messages: [],
						mlsGroupId: event.groupId,
						mlsIdentityId: identityId ?? undefined,
					},
					...prev,
				];
			});
		},
		[identityId],
	);
	// Global Welcome poller — processes invitations from other devices.
	useWelcomePoller(identityId, handleNewGroup);

	// Disappearing messages sweep (prd.md §9.4.3): every 30 s filter expired
	// messages from React state and purge them from Dexie.
	useEffect(() => {
		const sweep = () => {
			const now = Date.now();
			setChats((cs) =>
				cs.map((c) => ({
					...c,
					messages: c.messages.filter((m) => !m.expiresAt || m.expiresAt > now),
				})),
			);
			purgeExpired();
		};
		const handle = setInterval(sweep, 30_000);
		return () => clearInterval(handle);
	}, [purgeExpired]);

	const sendMessage = async (text: string) => {
		const now = new Date();
		const time = `${String(now.getHours()).padStart(2, "0")}:${String(now.getMinutes()).padStart(2, "0")}`;
		const expiresAt = disappearingTtl ? Date.now() + disappearingTtl * 1000 : undefined;

		// Optimistic local update — always runs synchronously so UI is responsive.
		setChats((cs) =>
			cs.map((c) => {
				if (c.id !== activeId) return c;
				const msgs = [...c.messages];
				for (let i = msgs.length - 1; i >= 0; i--) {
					if (msgs[i].from === "me" && msgs[i].last) {
						msgs[i] = { ...msgs[i], last: false, continued: true };
						break;
					}
				}
				msgs.push({
					from: "me",
					text,
					last: true,
					time,
					read: false,
					continued: msgs.length > 0 && msgs[msgs.length - 1].from === "me",
					expiresAt,
				});
				return { ...c, messages: msgs, last: text, time };
			}),
		);

		// Real MLS encryption + REST API call when all context is available.
		if (sessionToken && active?.mlsGroupId && active?.mlsIdentityId && cryptoWorker) {
			const encoder = new TextEncoder();
			const plaintext = encoder.encode(text);
			try {
				const { ciphertext } = await cryptoWorker.mlsEncrypt(
					active.mlsIdentityId,
					active.mlsGroupId,
					plaintext,
				);
				const envelopeId = await sendMessageApi(
					sessionToken,
					active.mlsGroupId,
					ciphertext,
					disappearingTtl,
				);
				// Backfill the server-assigned envelope ID onto the optimistic "me" message so
				// an incoming read_receipt can match it by ID.
				const chatId = activeId;
				setChats((cs) =>
					cs.map((c) => {
						if (c.id !== chatId) return c;
						const msgs = [...c.messages];
						for (let i = msgs.length - 1; i >= 0; i--) {
							if (msgs[i].from === "me" && !msgs[i].id) {
								msgs[i] = { ...msgs[i], id: envelopeId };
								break;
							}
						}
						return { ...c, messages: msgs };
					}),
				);
				// Persist the sent message to Dexie (encrypted at rest).
				// uint8ToBase64 uses a safe byte-at-a-time loop — no spread/RangeError risk.
				const ciphertextB64 = uint8ToBase64(ciphertext);
				persistOutgoing(envelopeId, active.mlsGroupId, text, ciphertextB64);
			} catch {
				// Silent failure — optimistic message stays in UI.
				// In future: mark message as "failed" with retry affordance.
			} finally {
				plaintext.fill(0);
			}
		}
	};

	return (
		<div
			style={{
				height: "100vh",
				width: "100vw",
				display: "flex",
				background: "var(--bg-void)",
				color: "var(--fg-1)",
				fontFamily: "var(--font-sans)",
				overflow: "hidden",
			}}
		>
			<Sidebar
				chats={chats}
				activeId={activeId}
				onSelect={handleSelectChat}
				onNewChat={() => setInviteOpen(true)}
				onSettings={() => undefined}
				searchQuery={search}
				onSearch={setSearch}
			/>

			{active && (
				<main
					style={{
						flex: 1,
						display: "flex",
						flexDirection: "column",
						minWidth: 0,
					}}
				>
					<ConversationHeader
						chat={active}
						onCall={() => undefined}
						onVideo={() => undefined}
						onInfo={() => setInfoOpen((v) => !v)}
						infoOpen={infoOpen}
						pqBindingHex={active.pqBindingHex}
						msgSearch={msgSearch}
						onMsgSearch={setMsgSearch}
					/>
					<MessageList
						messages={active.messages}
						partner={active.name}
						searchQuery={msgSearch}
						onReact={sendReaction}
					/>
					<Composer
						onSend={sendMessage}
						partner={active.name}
						ttl={disappearingTtl}
						onToggleTtl={handleToggleTtl}
						onPhoto={() => fileInputRef.current?.click()}
						onTyping={sendTypingIndicator}
					/>
				</main>
			)}

			{/* Hidden file input for §9.2 media send — triggered by the Photo button. */}
			<input
				ref={fileInputRef}
				type="file"
				accept="image/*"
				aria-label="Select image to send"
				style={{ display: "none" }}
				onChange={handleFileSelect}
			/>

			{infoOpen && active && (
				<InfoPanel
					chat={active}
					onClose={() => setInfoOpen(false)}
					disappearingTtl={disappearingTtl}
				/>
			)}

			<InviteModal open={inviteOpen} onClose={() => setInviteOpen(false)} />
		</div>
	);
}
