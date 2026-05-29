import { type CSSProperties, type KeyboardEvent, useLayoutEffect, useRef, useState } from "react";
import { Icon } from "./Icon";
import { SafetyNumbers } from "./SafetyNumbers";

// ── Types ─────────────────────────────────────────────────────────────────────

interface ChatMessage {
	day?: string;
	from: "me" | "them";
	text: string;
	continued?: boolean;
	last?: boolean;
	time?: string;
	read?: boolean;
	/** Unix ms — set when sent with a disappearing TTL. Client-side mock only. */
	expiresAt?: number;
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
							{chat.unread}
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
}: {
	chat: Chat;
	onCall: () => void;
	onVideo: () => void;
	onInfo: () => void;
	infoOpen: boolean;
}) {
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
			<Avatar name={chat.name} size={38} online={chat.online} />
			<div style={{ flex: 1, minWidth: 0 }}>
				<div style={{ display: "flex", alignItems: "center", gap: 8 }}>
					<span style={{ fontSize: 15, fontWeight: 500, color: "var(--fg-1)" }}>{chat.name}</span>
					<Icon name="lock" size={11} color="#A8C8FF" />
				</div>
				<div style={{ fontSize: 11, color: "var(--fg-3)", marginTop: 1 }}>
					{chat.online ? "online" : `last seen ${chat.lastSeen ?? "recently"}`}
					{chat.typing && (
						<span style={{ color: "#FF9E52", marginLeft: 8, fontStyle: "italic" }}>· typing</span>
					)}
				</div>
			</div>
			<div style={{ display: "flex", gap: 2 }}>
				<IconBtn icon="phone" onClick={onCall} label="Voice call" />
				<IconBtn icon="video" onClick={onVideo} label="Video call" />
				<IconBtn icon="more-horizontal" onClick={onInfo} active={infoOpen} label="Info" />
			</div>
		</header>
	);
}

function MessageBubble({
	msg,
	partner,
}: {
	msg: ChatMessage;
	partner: string;
}) {
	const isMe = msg.from === "me";
	return (
		<div
			style={{
				display: "flex",
				justifyContent: isMe ? "flex-end" : "flex-start",
				alignItems: "flex-end",
				gap: 8,
				marginTop: msg.continued ? 2 : 8,
			}}
		>
			{!isMe && (
				<div style={{ width: 28, flex: "none" }}>
					{!msg.continued && <Avatar name={partner} size={28} />}
				</div>
			)}
			<div
				style={{
					maxWidth: "72%",
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
				{msg.text}
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
							<Icon name="doublecheck" size={12} color={msg.read ? "#A8C8FF" : "currentColor"} />
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
}: {
	messages: ChatMessage[];
	partner: string;
}) {
	const ref = useRef<HTMLDivElement>(null);

	useLayoutEffect(() => {
		if (ref.current) ref.current.scrollTop = ref.current.scrollHeight;
	});

	const groups = buildGroups(messages);

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
					<MessageBubble key={g.key} msg={g.msg} partner={partner} />
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
}: {
	onSend: (text: string) => void;
	partner: string;
	ttl: TtlOption;
	onToggleTtl: () => void;
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
				<IconBtn icon="image" label="Photo" size={32} />
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
					onChange={(e) => setText(e.target.value)}
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

// Mock safety number — in the real flow this is computed from the MLS group
// member signature keys via the crypto worker (mls_compute_safety_number).
// Mock safety number — 12 six-digit groups (prd.md §5.6).
// In production this is computed by the crypto worker via mls_compute_safety_number.
const MOCK_SAFETY_NUMBER =
	"689053 337949 184798 288064 134849 362568 560227 765408 921198 315305 693006 807986";

function InfoPanel({
	chat,
	onClose,
	disappearingTtl,
}: {
	chat: Chat;
	onClose: () => void;
	disappearingTtl: TtlOption;
}) {
	const [safetyVerified, setSafetyVerified] = useState(!!chat.verifiedAgo);
	const [verifiedAt, setVerifiedAt] = useState<number | undefined>(
		chat.verifiedAgo ? Date.now() - 2 * 86_400_000 : undefined,
	);
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
					<SafetyNumbers
						safetyNumber={MOCK_SAFETY_NUMBER}
						peerName={chat.name}
						verified={safetyVerified}
						verifiedAt={verifiedAt}
						onVerify={() => {
							setSafetyVerified(true);
							setVerifiedAt(Date.now());
						}}
						onReset={() => {
							setSafetyVerified(false);
							setVerifiedAt(undefined);
						}}
					/>
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
	const [disappearingTtl, setDisappearingTtl] = useState<TtlOption>(undefined);
	const active = chats.find((c) => c.id === activeId);

	const handleToggleTtl = () => setDisappearingTtl((t) => nextTtl(t));

	const sendMessage = (text: string) => {
		const now = new Date();
		const time = `${String(now.getHours()).padStart(2, "0")}:${String(now.getMinutes()).padStart(2, "0")}`;
		const expiresAt = disappearingTtl ? Date.now() + disappearingTtl * 1000 : undefined;
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
				onSelect={setActiveId}
				onNewChat={() => undefined}
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
					/>
					<MessageList messages={active.messages} partner={active.name} />
					<Composer
						onSend={sendMessage}
						partner={active.name}
						ttl={disappearingTtl}
						onToggleTtl={handleToggleTtl}
					/>
				</main>
			)}

			{infoOpen && active && (
				<InfoPanel
					chat={active}
					onClose={() => setInfoOpen(false)}
					disappearingTtl={disappearingTtl}
				/>
			)}
		</div>
	);
}
