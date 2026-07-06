import {
	type CSSProperties,
	type KeyboardEvent,
	type ReactNode,
	type RefObject,
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
	type ReplyContext,
	useMessages,
} from "../hooks/useMessages";
import { usePersistentMessages } from "../hooks/usePersistentMessages";
import { useRegionDetect } from "../hooks/useRegionDetect";
import { useTauriNotification } from "../hooks/useTauriNotification";
import { type NewGroupEvent, useWelcomePoller } from "../hooks/useWelcomePoller";
import { useAuthStore } from "../store/auth";
import { uint8ToBase64 } from "../utils/base64";
import { AddMemberModal } from "./AddMemberModal";
import { CreateGroupModal } from "./CreateGroupModal";
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
	/** Unix ms timestamp — set on new messages for time-window grouping. Absent on seed messages. */
	ts?: number;
	/** Peer's device received and decrypted this message (delivery_receipt received). */
	delivered?: boolean;
	/** Peer has read this message (read_receipt received). Supersedes delivered. */
	read?: boolean;
	/** Unix ms — set when sent with a disappearing TTL. Client-side mock only. */
	expiresAt?: number;
	/** §9.2 media attachment — full payload for download + decrypt on the receiver path. */
	media?: MediaPayload;
	/** Emoji reactions: emoji → array of sender device IDs (deduped). */
	reactions?: Record<string, string[]>;
	/** Quote-reply context: the message this is a reply to. */
	replyTo?: ReplyContext;
	/** True when the message has been edited after sending. */
	edited?: boolean;
	/** True when the message has been deleted (unsent) by the sender. */
	deleted?: boolean;
	/** True when a group member has pinned this message. */
	pinned?: boolean;
	/** True when the local user has starred this message (local-only, not synced). */
	starred?: boolean;
	/** Unix ms — when set the message is queued locally and fires at this time. Client-side only. */
	scheduledFor?: number;
	/** Group poll — options with voter lists. Local-only, not synced to server. */
	poll?: { question: string; options: { text: string; voters: string[] }[] };
}

interface ChatMember {
	id: string;
	name: string;
	handle: string;
	role?: "admin" | "member";
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
	/** Index into messages[] of the first unread message. Cleared when the chat is selected. */
	firstUnreadAt?: number;
	/** Envelope UUID of the currently pinned message, if any. */
	pinnedMessageId?: string;
	/** True for group chats with 3+ members (set by creator). */
	isGroup?: boolean;
	/** Number of members in the group. Starts at 1 (creator only). */
	memberCount?: number;
	/** Local member roster for group chats — never sent to server, never in MLS payload. */
	members?: ChatMember[];
	/** When true, incoming messages do not increment the unread badge. Local-only, never sent to server. */
	muted?: boolean;
	/** When false, incoming messages do not trigger notification sounds. Local-only, never sent to server. */
	sound?: boolean;
	/** When false, incoming messages do not trigger device vibration. Local-only, never sent to server. */
	vibrate?: boolean;
	/** Count of @mention messages in this chat that the user hasn't yet read. Local-only, never sent to server. */
	mentionCount?: number;
	/** True when the chat is archived (local-only, not synced). */
	archived?: boolean;
	/** True when the chat is pinned to the top of the sidebar (local-only, not synced). */
	pinnedTop?: boolean;
	/** Group description / topic text (local-only, not synced). Group chats only. */
	description?: string;
	/** Custom display name set by the local user for this DM contact (local-only, never sent to server). */
	nickname?: string;
}

// ── Day-label helpers ─────────────────────────────────────────────────────────

/**
 * Returns a human-readable day label for `ts` (Unix ms): "Today", "Yesterday",
 * or a locale-formatted string like "Mon, Jun 28". Pure — no side effects.
 */
export function getDayLabel(ts: number): string {
	const d = new Date(ts);
	const now = new Date();
	const todayStr = `${now.getFullYear()}-${now.getMonth()}-${now.getDate()}`;
	const msgStr = `${d.getFullYear()}-${d.getMonth()}-${d.getDate()}`;
	if (msgStr === todayStr) return "Today";
	const yesterday = new Date(now);
	yesterday.setDate(now.getDate() - 1);
	const yStr = `${yesterday.getFullYear()}-${yesterday.getMonth()}-${yesterday.getDate()}`;
	if (msgStr === yStr) return "Yesterday";
	return d.toLocaleDateString(undefined, { weekday: "short", month: "short", day: "numeric" });
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

// ── Slow mode helpers ──────────────────────────────────────────────────────────

const SLOW_MODE_OPTIONS = [0, 5, 30, 60, 300, 3600] as const;
type SlowModeDelay = (typeof SLOW_MODE_OPTIONS)[number];

function formatSlowMode(d: SlowModeDelay): string {
	if (d === 0) return "Off";
	if (d < 60) return `${d}s`;
	if (d < 3600) return `${d / 60}m`;
	return "1h";
}

function formatTimeLeft(expiresAt: number): string {
	const s = Math.max(0, Math.ceil((expiresAt - Date.now()) / 1000));
	if (s <= 0) return "soon";
	if (s < 3600) return `${Math.ceil(s / 60)}m`;
	if (s < 86400) return `${Math.ceil(s / 3600)}h`;
	if (s < 604800) return `${Math.ceil(s / 86400)}d`;
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
			{
				day: "Yesterday",
				from: "them",
				text: "Hey — are you free tomorrow morning?",
			},
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
				from: "them",
				text: "Great! Here's the menu: https://example.com/menu",
				continued: true,
			},
			{
				from: "them",
				text: "Also **bring your charger** — the `outlet` by the window is the *only one* that works.",
				continued: true,
			},
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
			{
				from: "them",
				text: "receipt.pdf",
				continued: true,
				last: true,
				time: "12:08",
			},
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
			{
				from: "me",
				text: "see you tmrw",
				continued: true,
				last: true,
				time: "17:42",
				read: true,
			},
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
	{
		id: "design-team",
		name: "Design Team",
		handle: "design-team",
		online: false,
		last: "Noa: Final mockup is up",
		time: "13:55",
		unread: 0,
		isGroup: true,
		memberCount: 4,
		members: [
			{ id: "dev-a", name: "Finn", handle: "finn", role: "admin" },
			{ id: "dev-b", name: "Maya", handle: "maya", role: "member" },
			{ id: "dev-c", name: "Jordan", handle: "jordan", role: "member" },
			{ id: "dev-d", name: "Noa", handle: "noa", role: "member" },
		],
		mlsGroupId: "44444444-4444-4444-4444-444444444444",
		description: "Where design meets code — share mockups, get feedback, ship it.",
		mentionCount: 2,
		messages: [
			{
				day: "Today",
				from: "them",
				text: "I pushed the color palette revisions.",
				time: "10:12",
				reactions: { "👍": ["dev-a", "dev-b", "dev-c"], "❤️": ["dev-d"] },
			},
			{
				from: "them",
				text: "@you can you review the final mockup? @all feedback welcome",
				continued: true,
				time: "13:45",
				reactions: { "👀": ["dev-a", "dev-b"] },
			},
			{
				from: "them",
				text: "Final mockup is up",
				continued: true,
				last: true,
				time: "13:55",
				reactions: { "🎉": ["dev-a", "dev-b", "dev-c"], "🔥": ["dev-d", "dev-e"] },
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

// ── parseMessageLinks ─────────────────────────────────────────────────────────
// Splits a message string into text/URL segments. Only https:// and http://
// URLs are linkified; javascript:, data:, and anything else stays as text.
// Trailing punctuation (.,;:!?)] that typically isn't part of a URL is stripped
// from the matched URL and emitted as a trailing text segment.

type MsgSegment = { type: "text" | "url"; value: string };

function parseMessageLinks(text: string): MsgSegment[] {
	const URL_RE = /https?:\/\/[^\s<>"']+/gi;
	const segs: MsgSegment[] = [];
	let last = 0;
	let m = URL_RE.exec(text);
	while (m !== null) {
		const fullMatch = m[0];
		const cleaned = fullMatch.replace(/[.,;:!?)\]]+$/, "");
		let valid = false;
		try {
			const u = new URL(cleaned);
			valid = u.protocol === "https:" || u.protocol === "http:";
		} catch {
			/* not a valid URL */
		}
		if (m.index > last) {
			segs.push({ type: "text", value: text.slice(last, m.index) });
		}
		if (valid) {
			segs.push({ type: "url", value: cleaned });
			if (cleaned.length < fullMatch.length) {
				segs.push({ type: "text", value: fullMatch.slice(cleaned.length) });
			}
		} else {
			segs.push({ type: "text", value: fullMatch });
		}
		last = m.index + fullMatch.length;
		m = URL_RE.exec(text);
	}
	if (last < text.length) {
		segs.push({ type: "text", value: text.slice(last) });
	}
	return segs.length > 0 ? segs : [{ type: "text", value: text }];
}

// ── HighlightedText ───────────────────────────────────────────────────────────

function applyHighlight(text: string, highlight: string, isCurrentMatch?: boolean): ReactNode {
	const lc = text.toLowerCase();
	const hlLc = highlight.toLowerCase();
	const parts: ReactNode[] = [];
	let cursor = 0;
	let idx = lc.indexOf(hlLc, cursor);
	if (idx === -1) return text;
	// Only the first occurrence in this bubble gets the current-match testid.
	let firstMark = true;
	while (idx !== -1) {
		if (idx > cursor) parts.push(text.slice(cursor, idx));
		const isCurrent = isCurrentMatch && firstMark;
		firstMark = false;
		parts.push(
			<mark
				key={`${idx}-${cursor}`}
				data-testid={isCurrent ? "search-current-match" : "search-highlight"}
				style={{
					background: isCurrent ? "rgba(255,138,61,0.60)" : "rgba(255,138,61,0.35)",
					color: "#F2EDE3",
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

// ── parseFormatting ───────────────────────────────────────────────────────────
// Splits a plain-text string into segments: bold (**text**), italic (*text*),
// inline code (`text`), or plain text. Bold must be matched before italic so
// that ** is consumed as a unit before the * alternative is tried.

type FmtSegment = { type: "text" | "bold" | "italic" | "code"; value: string };

function parseFormatting(text: string): FmtSegment[] {
	const segs: FmtSegment[] = [];
	const FMT_RE = /`([^`]+)`|\*\*([^*]+)\*\*|\*([^*]+)\*/g;
	let last = 0;
	let m: RegExpExecArray | null;
	// biome-ignore lint/suspicious/noAssignInExpressions: idiomatic exec loop
	while ((m = FMT_RE.exec(text)) !== null) {
		if (m.index > last) segs.push({ type: "text", value: text.slice(last, m.index) });
		if (m[1] !== undefined) segs.push({ type: "code", value: m[1] });
		else if (m[2] !== undefined) segs.push({ type: "bold", value: m[2] });
		else if (m[3] !== undefined) segs.push({ type: "italic", value: m[3] });
		last = m.index + m[0].length;
	}
	if (last < text.length) segs.push({ type: "text", value: text.slice(last) });
	return segs.length > 0 ? segs : [{ type: "text", value: text }];
}

// Renders an array of FmtSegment nodes applying optional search highlight.
function renderFmtWithHighlight(
	fmtSegs: FmtSegment[],
	highlight: string,
	kp: string,
	isCurrentMatch?: boolean,
): ReactNode {
	const inner = (v: string): ReactNode =>
		highlight ? applyHighlight(v, highlight, isCurrentMatch) : v;
	return fmtSegs.map((f, j) => {
		const fk = `${kp}-${j}`;
		switch (f.type) {
			case "bold":
				return (
					<strong key={fk} data-testid="fmt-bold" style={{ fontWeight: 700 }}>
						{inner(f.value)}
					</strong>
				);
			case "italic":
				return (
					<em key={fk} data-testid="fmt-italic">
						{inner(f.value)}
					</em>
				);
			case "code":
				return (
					<code
						key={fk}
						data-testid="fmt-code"
						style={{
							fontFamily: "monospace",
							background: "rgba(255,255,255,0.08)",
							borderRadius: 3,
							padding: "0 3px",
							fontSize: "0.9em",
						}}
					>
						{f.value}
					</code>
				);
			default:
				return <span key={fk}>{inner(f.value)}</span>;
		}
	});
}

function HighlightedText({
	text,
	highlight,
	isCurrentMatch,
}: {
	text: string;
	highlight: string;
	isCurrentMatch?: boolean;
}) {
	const urlSegs = parseMessageLinks(text);
	const isPlainText = urlSegs.length === 1 && urlSegs[0].type === "text";
	if (isPlainText) {
		const fmtSegs = parseFormatting(text);
		const noFmt = fmtSegs.length === 1 && fmtSegs[0].type === "text";
		if (noFmt && !highlight) return <>{text}</>;
		return <>{renderFmtWithHighlight(fmtSegs, highlight, "root", isCurrentMatch)}</>;
	}
	return (
		<>
			{urlSegs.map((seg, i) => {
				const k = `${seg.type}-${i}`;
				if (seg.type === "url") {
					return (
						<a
							key={k}
							href={seg.value}
							target="_blank"
							rel="noopener noreferrer"
							data-testid="message-link"
							style={{
								color: "#A8C8FF",
								textDecoration: "underline",
								wordBreak: "break-all",
							}}
						>
							{seg.value}
						</a>
					);
				}
				const fmtSegs = parseFormatting(seg.value);
				return <span key={k}>{renderFmtWithHighlight(fmtSegs, highlight, k, isCurrentMatch)}</span>;
			})}
		</>
	);
}

// ── PinnedBanner ─────────────────────────────────────────────────────────────

function PinnedBanner({
	pinnedMessageId,
	messages,
	onUnpin,
	onJumpToPin,
}: {
	pinnedMessageId: string;
	messages: ChatMessage[];
	onUnpin: () => void;
	onJumpToPin?: () => void;
}) {
	const msg = messages.find((m) => m.id === pinnedMessageId);
	const preview = msg?.deleted ? "This message was deleted" : (msg?.text ?? "Message");
	return (
		<div
			data-testid="pinned-banner"
			style={{
				display: "flex",
				alignItems: "center",
				gap: 8,
				paddingRight: 18,
				background: "rgba(255,138,61,0.06)",
				borderBottom: "1px solid rgba(255,138,61,0.18)",
				fontSize: 12,
				color: "var(--fg-2)",
				flex: "none",
			}}
		>
			<button
				type="button"
				onClick={onJumpToPin}
				data-testid="pinned-banner-jump"
				aria-label="Jump to pinned message"
				style={{
					display: "flex",
					alignItems: "center",
					gap: 8,
					flex: 1,
					background: "none",
					border: "none",
					padding: "6px 0 6px 18px",
					cursor: onJumpToPin ? "pointer" : "default",
					minWidth: 0,
					textAlign: "left",
				}}
			>
				<Icon name="pin" size={13} color="#FF8A3D" />
				<span
					style={{
						fontWeight: 600,
						fontSize: 10,
						letterSpacing: "0.1em",
						color: "#FF8A3D",
						flex: "none",
					}}
				>
					PINNED
				</span>
				<span
					style={{
						flex: 1,
						overflow: "hidden",
						textOverflow: "ellipsis",
						whiteSpace: "nowrap",
						color: "var(--fg-2)",
					}}
				>
					{preview}
				</span>
			</button>
			<button
				type="button"
				onClick={onUnpin}
				aria-label="Unpin message"
				data-testid="unpin-button"
				style={{
					background: "none",
					border: "none",
					color: "var(--fg-3)",
					cursor: "pointer",
					padding: 2,
					display: "flex",
					alignItems: "center",
					flex: "none",
				}}
			>
				<Icon name="x" size={13} />
			</button>
		</div>
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
	"data-testid": dataTestId,
}: {
	icon: Parameters<typeof Icon>[0]["name"];
	onClick?: () => void;
	active?: boolean;
	size?: number;
	label: string;
	style?: CSSProperties;
	color?: string;
	"data-testid"?: string;
}) {
	const [hover, setHover] = useState(false);
	return (
		<button
			type="button"
			onClick={onClick}
			aria-label={label}
			data-testid={dataTestId}
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

// ── StarredPanel ──────────────────────────────────────────────────────────────

function StarredPanel({
	chats,
	onClose,
	onJumpTo,
}: {
	chats: Chat[];
	onClose: () => void;
	onJumpTo: (chatId: string) => void;
}) {
	const starred = chats.flatMap((c) =>
		c.messages.filter((m) => m.starred).map((m) => ({ chatId: c.id, chatName: c.name, msg: m })),
	);

	return (
		<div
			data-testid="starred-panel"
			style={{
				position: "absolute",
				inset: 0,
				background: "var(--bg-surface)",
				zIndex: 20,
				display: "flex",
				flexDirection: "column",
			}}
		>
			<div
				style={{
					padding: "14px 18px",
					borderBottom: "1px solid var(--border-soft)",
					display: "flex",
					alignItems: "center",
					gap: 10,
				}}
			>
				<Icon name="star" size={16} color="#FF8A3D" />
				<span
					style={{
						fontFamily: "var(--font-sans)",
						fontWeight: 600,
						fontSize: 14,
						color: "var(--fg-1)",
						flex: 1,
					}}
				>
					Starred Messages
				</span>
				<IconBtn icon="x" onClick={onClose} label="Close starred" size={28} />
			</div>

			<div style={{ flex: 1, overflowY: "auto", padding: "8px 0" }}>
				{starred.length === 0 ? (
					<div
						style={{
							padding: 32,
							textAlign: "center",
							color: "var(--fg-3)",
							fontSize: 13,
						}}
					>
						No starred messages yet.
						<br />
						<span style={{ opacity: 0.6, fontSize: 12 }}>
							Hover a message and click ★ to star it.
						</span>
					</div>
				) : (
					starred.map(({ chatId, chatName, msg }, i) => (
						<button
							key={`${chatId}-${msg.id ?? i}`}
							type="button"
							data-testid="starred-item"
							onClick={() => onJumpTo(chatId)}
							style={{
								display: "block",
								width: "100%",
								textAlign: "left",
								background: "none",
								border: "none",
								borderBottom: "1px solid var(--border-faint)",
								padding: "10px 18px",
								cursor: "pointer",
							}}
						>
							<div
								style={{
									fontSize: 11,
									color: "#FF8A3D",
									fontFamily: "var(--font-mono)",
									letterSpacing: "0.06em",
									marginBottom: 4,
								}}
							>
								{chatName}
							</div>
							<div
								style={{
									fontSize: 13,
									color: "var(--fg-2)",
									lineHeight: 1.4,
									overflow: "hidden",
									textOverflow: "ellipsis",
									whiteSpace: "nowrap",
								}}
							>
								{msg.media ? "Image attachment" : msg.text}
							</div>
						</button>
					))
				)}
			</div>
		</div>
	);
}

// ── Custom user status ────────────────────────────────────────────────────────

type CustomStatus = { emoji: string; text: string } | null;

const STATUS_PRESETS = [
	{ emoji: "🎉", text: "Be right back" },
	{ emoji: "🏠", text: "Working from home" },
	{ emoji: "📵", text: "Do not disturb" },
	{ emoji: "🎧", text: "In a meeting" },
	{ emoji: "🌴", text: "On vacation" },
] as const;

function StatusEditor({
	current,
	onSave,
	onClose,
}: {
	current: CustomStatus;
	onSave: (status: CustomStatus) => void;
	onClose: () => void;
}) {
	const [emoji, setEmoji] = useState(current?.emoji ?? "");
	const [text, setText] = useState(current?.text ?? "");

	const handleSave = () => {
		const trimmedText = text.trim();
		const trimmedEmoji = emoji.trim();
		onSave(trimmedText || trimmedEmoji ? { emoji: trimmedEmoji, text: trimmedText } : null);
		onClose();
	};

	const handleClear = () => {
		onSave(null);
		onClose();
	};

	return (
		<dialog
			open
			data-testid="status-editor-overlay"
			aria-label="Set your status"
			onClick={(e) => {
				if (e.target === e.currentTarget) onClose();
			}}
			onKeyDown={(e) => {
				if (e.key === "Escape") onClose();
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
				data-testid="status-editor"
				onClick={(e) => e.stopPropagation()}
				onKeyDown={(e) => e.stopPropagation()}
				style={{
					background: "var(--bg-surface)",
					border: "1px solid var(--border-soft)",
					borderRadius: 16,
					padding: "24px 28px 20px",
					width: 360,
					display: "flex",
					flexDirection: "column",
					gap: 16,
				}}
			>
				<div style={{ fontSize: 15, fontWeight: 600, color: "var(--fg-1)" }}>Set a status</div>

				{/* Emoji + text row */}
				<div style={{ display: "flex", gap: 8 }}>
					<input
						data-testid="status-emoji-input"
						value={emoji}
						onChange={(e) => setEmoji(e.target.value)}
						placeholder="😊"
						maxLength={4}
						style={{
							width: 52,
							textAlign: "center",
							background: "var(--bg-input)",
							border: "1px solid var(--border-faint)",
							borderRadius: 8,
							padding: "8px 4px",
							fontSize: 20,
							outline: "none",
							color: "var(--fg-1)",
							fontFamily: "var(--font-sans)",
						}}
					/>
					<input
						data-testid="status-text-input"
						value={text}
						onChange={(e) => setText(e.target.value)}
						onKeyDown={(e) => {
							if (e.key === "Enter") handleSave();
							if (e.key === "Escape") onClose();
						}}
						placeholder="What's your status?"
						maxLength={80}
						style={{
							flex: 1,
							background: "var(--bg-input)",
							border: "1px solid var(--border-faint)",
							borderRadius: 8,
							padding: "8px 12px",
							fontSize: 13,
							outline: "none",
							color: "var(--fg-1)",
							fontFamily: "var(--font-sans)",
						}}
					/>
				</div>

				{/* Quick presets */}
				<div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
					<div
						style={{
							fontSize: 10,
							fontWeight: 600,
							letterSpacing: "0.14em",
							textTransform: "uppercase",
							color: "var(--fg-4)",
						}}
					>
						Quick presets
					</div>
					<div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
						{STATUS_PRESETS.map((p) => (
							<button
								key={p.text}
								type="button"
								data-testid={`status-preset-${p.text.toLowerCase().replace(/\s+/g, "-")}`}
								onClick={() => {
									setEmoji(p.emoji);
									setText(p.text);
								}}
								style={{
									background: "var(--bg-input)",
									border: "1px solid var(--border-faint)",
									borderRadius: 20,
									padding: "5px 10px",
									fontSize: 12,
									cursor: "pointer",
									color: "var(--fg-2)",
									fontFamily: "var(--font-sans)",
									display: "flex",
									alignItems: "center",
									gap: 4,
								}}
							>
								<span>{p.emoji}</span>
								<span>{p.text}</span>
							</button>
						))}
					</div>
				</div>

				{/* Action buttons */}
				<div
					style={{
						display: "flex",
						justifyContent: "space-between",
						alignItems: "center",
						marginTop: 4,
					}}
				>
					{current ? (
						<button
							type="button"
							data-testid="status-clear-btn"
							onClick={handleClear}
							style={{
								background: "none",
								border: "none",
								cursor: "pointer",
								fontSize: 12,
								color: "var(--fg-3)",
								fontFamily: "var(--font-sans)",
								padding: "6px 0",
							}}
						>
							Clear status
						</button>
					) : (
						<span />
					)}
					<div style={{ display: "flex", gap: 8 }}>
						<button
							type="button"
							data-testid="status-cancel-btn"
							onClick={onClose}
							style={{
								background: "none",
								border: "1px solid var(--border-soft)",
								borderRadius: 8,
								padding: "7px 16px",
								fontSize: 13,
								cursor: "pointer",
								color: "var(--fg-2)",
								fontFamily: "var(--font-sans)",
							}}
						>
							Cancel
						</button>
						<button
							type="button"
							data-testid="status-save-btn"
							onClick={handleSave}
							style={{
								background: "#FF8A3D",
								border: "none",
								borderRadius: 8,
								padding: "7px 16px",
								fontSize: 13,
								fontWeight: 600,
								cursor: "pointer",
								color: "#fff",
								fontFamily: "var(--font-sans)",
							}}
						>
							Save
						</button>
					</div>
				</div>
			</div>
		</dialog>
	);
}

// ── Sidebar ───────────────────────────────────────────────────────────────────

function lastMsgReactionSummary(chat: Chat): string | null {
	if (!chat.isGroup) return null;
	const msgs = chat.messages;
	const lastMsg = msgs[msgs.length - 1];
	if (!lastMsg?.reactions) return null;
	const entries = Object.entries(lastMsg.reactions).filter(([, s]) => s.length > 0);
	if (entries.length === 0) return null;
	return entries
		.map(([emoji, senders]) => `${emoji}${senders.length > 1 ? senders.length : ""}`)
		.join(" ");
}

function TypingDots({ color = "#FF9E52" }: { color?: string }) {
	return (
		<span
			data-testid="typing-dots"
			aria-label="typing"
			style={{ display: "inline-flex", alignItems: "center", gap: 3, color }}
		>
			<span className="powehi-typing-dot" />
			<span className="powehi-typing-dot" />
			<span className="powehi-typing-dot" />
		</span>
	);
}

function ChatRow({
	chat,
	active,
	draft,
	onClick,
}: {
	chat: Chat;
	active: boolean;
	draft?: string;
	onClick: () => void;
}) {
	const [hover, setHover] = useState(false);
	const reactionSummary = lastMsgReactionSummary(chat);
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
			<Avatar name={chat.nickname ?? chat.name} size={42} online={chat.online} />
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
						{chat.nickname ?? chat.name}
					</span>
					{chat.pinnedTop && (
						<span data-testid="pin-top-indicator" style={{ lineHeight: 0 }}>
							<Icon name="pin" size={10} color="#A8C8FF" />
						</span>
					)}
					{chat.isGroup && (
						<span
							data-testid="group-badge"
							style={{
								fontSize: 9,
								fontWeight: 600,
								letterSpacing: "0.06em",
								color: "#FF8A3D",
								background: "rgba(255,138,61,0.12)",
								border: "1px solid rgba(255,138,61,0.25)",
								borderRadius: 4,
								padding: "1px 5px",
								flex: "none",
							}}
						>
							GROUP
						</span>
					)}
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
					{chat.muted && (
						<span
							data-testid="muted-icon"
							title="Muted"
							aria-hidden="true"
							style={{ display: "flex", alignItems: "center" }}
						>
							<Icon name="bell-off" size={11} color="var(--fg-3)" />
						</span>
					)}
				</div>
				<div
					style={{
						display: "flex",
						alignItems: "center",
						gap: 6,
						marginTop: 2,
					}}
				>
					{chat.typing ? (
						<TypingDots />
					) : !active && draft ? (
						<span
							data-testid="draft-preview"
							style={{
								fontSize: 13,
								overflow: "hidden",
								textOverflow: "ellipsis",
								whiteSpace: "nowrap",
								flex: 1,
							}}
						>
							<span style={{ color: "#FF9E52", fontWeight: 600 }}>Draft: </span>
							<span style={{ color: "var(--fg-3)" }}>{draft}</span>
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
					{reactionSummary && !chat.typing && (
						<span
							data-testid="last-msg-reaction-summary"
							title="Reactions on last message"
							style={{
								fontSize: 11,
								color: "var(--fg-3)",
								flex: "none",
								letterSpacing: "0.02em",
							}}
						>
							{reactionSummary}
						</span>
					)}
					{(chat.mentionCount ?? 0) > 0 && (
						<span
							data-testid="mention-badge"
							title={`${chat.mentionCount} mention${(chat.mentionCount ?? 0) > 1 ? "s" : ""}`}
							style={{
								background: "rgba(168,200,255,0.15)",
								color: "#A8C8FF",
								border: "1px solid rgba(168,200,255,0.4)",
								fontWeight: 700,
								fontSize: 10,
								borderRadius: 9999,
								padding: "2px 6px",
								flex: "none",
								lineHeight: "14px",
							}}
						>
							@{(chat.mentionCount ?? 0) > 9 ? "9+" : chat.mentionCount}
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
	drafts,
	onSelect,
	onNewChat,
	onNewGroup,
	onSettings,
	searchQuery,
	onSearch,
	onJumpToMessage,
	onMarkAllRead,
	customStatus,
	onEditStatus,
}: {
	chats: Chat[];
	activeId: string;
	drafts: Record<string, string>;
	onSelect: (id: string) => void;
	onNewChat: () => void;
	onNewGroup: () => void;
	onSettings: () => void;
	searchQuery: string;
	onSearch: (q: string) => void;
	onJumpToMessage?: (chatId: string, messageId?: string) => void;
	onMarkAllRead?: () => void;
	customStatus: CustomStatus;
	onEditStatus: () => void;
}) {
	const [starredOpen, setStarredOpen] = useState(false);
	const [chatFilter, setChatFilter] = useState<"all" | "dms" | "groups" | "archived">("all");
	const regionId = useRegionDetect();
	const dmUnread = chats.filter((c) => !c.isGroup).reduce((s, c) => s + c.unread, 0);
	const groupUnread = chats.filter((c) => !!c.isGroup).reduce((s, c) => s + c.unread, 0);
	const groupMentions = chats
		.filter((c) => !!c.isGroup)
		.reduce((s, c) => s + (c.mentionCount ?? 0), 0);
	const totalUnread = chats.reduce((s, c) => s + c.unread, 0);
	const totalMentions = chats.reduce((s, c) => s + (c.mentionCount ?? 0), 0);
	const hasUnread = totalUnread > 0 || totalMentions > 0;
	const filtered = chats.filter((c) => {
		const matchesTab =
			chatFilter === "archived"
				? !!c.archived
				: !c.archived &&
					(chatFilter === "all" ||
						(chatFilter === "dms" && !c.isGroup) ||
						(chatFilter === "groups" && !!c.isGroup));
		const matchesSearch =
			!searchQuery ||
			c.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
			c.last.toLowerCase().includes(searchQuery.toLowerCase());
		return matchesTab && matchesSearch;
	});

	// Message-body search: scan all messages for the query (local only — no server contact).
	// Excludes deleted messages, image placeholders, and media-only entries.
	// Capped at 3 results per chat and 10 total to keep the UI manageable.
	const msgResults = searchQuery
		? chats
				.filter((c) =>
					chatFilter === "archived"
						? !!c.archived
						: !c.archived &&
							(chatFilter === "all" ||
								(chatFilter === "dms" && !c.isGroup) ||
								(chatFilter === "groups" && !!c.isGroup)),
				)
				.flatMap((c) =>
					c.messages
						.filter(
							(m) =>
								!m.media &&
								!m.deleted &&
								m.text !== "[image]" &&
								m.text.toLowerCase().includes(searchQuery.toLowerCase()),
						)
						.slice(0, 3)
						.map((m) => ({ chatId: c.id, chatName: c.name, text: m.text, messageId: m.id })),
				)
				.slice(0, 10)
		: [];

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
				position: "relative",
			}}
		>
			{starredOpen && (
				<StarredPanel
					chats={chats}
					onClose={() => setStarredOpen(false)}
					onJumpTo={(id) => {
						onSelect(id);
						setStarredOpen(false);
					}}
				/>
			)}
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
					<IconBtn icon="users" onClick={onNewGroup} label="New group" />
					<IconBtn icon="plus" onClick={onNewChat} label="New chat" />
					{hasUnread && onMarkAllRead && (
						<IconBtn icon="check-square" onClick={onMarkAllRead} label="Mark all as read" />
					)}
					<IconBtn icon="star" onClick={() => setStarredOpen(true)} label="Starred messages" />
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

			{/* Chat filter tabs */}
			<div style={{ display: "flex", gap: 4, padding: "0 14px 10px" }}>
				{(["all", "dms", "groups", "archived"] as const).map((tab) => {
					const label =
						tab === "all"
							? "All"
							: tab === "dms"
								? "Chats"
								: tab === "groups"
									? "Groups"
									: "Archived";
					const badge = tab === "dms" ? dmUnread : tab === "groups" ? groupUnread : 0;
					const isActive = chatFilter === tab;
					return (
						<button
							key={tab}
							type="button"
							data-testid={`filter-tab-${tab}`}
							onClick={() => setChatFilter(tab)}
							style={{
								flex: 1,
								background: isActive ? "rgba(255,138,61,0.12)" : "transparent",
								border: isActive
									? "1px solid rgba(255,138,61,0.3)"
									: "1px solid var(--border-faint)",
								borderRadius: 8,
								padding: "6px 0",
								cursor: "pointer",
								color: isActive ? "#FF8A3D" : "var(--fg-3)",
								fontFamily: "var(--font-sans)",
								fontSize: 12,
								fontWeight: isActive ? 600 : 400,
								display: "flex",
								alignItems: "center",
								justifyContent: "center",
								gap: 5,
							}}
						>
							{label}
							{badge > 0 && (
								<span
									data-testid={`filter-tab-${tab}-badge`}
									style={{
										background: "#FF8A3D",
										color: "#2A0A00",
										fontWeight: 700,
										fontSize: 9,
										borderRadius: 9999,
										padding: "1px 5px",
										lineHeight: "14px",
									}}
								>
									{badge > 9 ? "9+" : badge}
								</span>
							)}
							{tab === "groups" && groupMentions > 0 && (
								<span
									data-testid="filter-tab-groups-mention-badge"
									style={{
										background: "rgba(168,200,255,0.15)",
										color: "#A8C8FF",
										border: "1px solid rgba(168,200,255,0.4)",
										fontWeight: 700,
										fontSize: 9,
										borderRadius: 9999,
										padding: "1px 5px",
										lineHeight: "14px",
									}}
								>
									@{groupMentions > 9 ? "9+" : groupMentions}
								</span>
							)}
						</button>
					);
				})}
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
				{[...filtered]
					.sort((a, b) => (b.pinnedTop ? 1 : 0) - (a.pinnedTop ? 1 : 0))
					.map((c) => (
						<ChatRow
							key={c.id}
							chat={c}
							active={c.id === activeId}
							draft={drafts[c.id]}
							onClick={() => onSelect(c.id)}
						/>
					))}
				{filtered.length === 0 && msgResults.length === 0 && searchQuery && (
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

				{/* Message-body search results — only shown when search is active */}
				{msgResults.length > 0 && (
					<div style={{ marginTop: filtered.length > 0 ? 12 : 0 }}>
						<div
							data-testid="msg-search-section-header"
							style={{
								fontSize: 10,
								fontWeight: 600,
								letterSpacing: "0.14em",
								textTransform: "uppercase",
								color: "var(--fg-4)",
								padding: "8px 12px 4px",
							}}
						>
							Messages ({msgResults.length})
						</div>
						{msgResults.map(({ chatId, chatName, text, messageId }) => (
							<button
								key={`msgresult-${chatId}-${messageId ?? text.slice(0, 20)}`}
								type="button"
								data-testid="msg-search-result"
								onClick={() => onJumpToMessage?.(chatId, messageId)}
								style={{
									display: "block",
									width: "100%",
									textAlign: "left",
									background: "none",
									border: "none",
									borderRadius: 10,
									padding: "8px 12px",
									cursor: "pointer",
									color: "inherit",
									fontFamily: "inherit",
								}}
							>
								<div
									style={{
										fontSize: 11,
										fontWeight: 600,
										color: "#FF8A3D",
										marginBottom: 2,
										overflow: "hidden",
										textOverflow: "ellipsis",
										whiteSpace: "nowrap",
									}}
								>
									{chatName}
								</div>
								<div
									style={{
										fontSize: 12,
										color: "var(--fg-3)",
										overflow: "hidden",
										textOverflow: "ellipsis",
										whiteSpace: "nowrap",
									}}
								>
									<HighlightedText
										text={text.length > 80 ? `${text.slice(0, 80)}…` : text}
										highlight={searchQuery}
									/>
								</div>
							</button>
						))}
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

			{/* User status bar */}
			<div
				data-testid="user-status-bar"
				style={{
					padding: "10px 14px",
					borderTop: "1px solid var(--border-faint)",
					display: "flex",
					alignItems: "center",
					gap: 10,
				}}
			>
				<div
					style={{
						width: 32,
						height: 32,
						borderRadius: "50%",
						background: "#A8C8FF",
						color: "#040408",
						display: "flex",
						alignItems: "center",
						justifyContent: "center",
						fontSize: 13,
						fontWeight: 700,
						flex: "none",
					}}
				>
					Y
				</div>
				<div style={{ flex: 1, minWidth: 0 }}>
					<div
						style={{
							fontSize: 13,
							fontWeight: 600,
							color: "var(--fg-1)",
							lineHeight: 1.2,
						}}
					>
						You
					</div>
					{customStatus ? (
						<div
							data-testid="user-status-text"
							style={{
								fontSize: 11,
								color: "var(--fg-3)",
								overflow: "hidden",
								textOverflow: "ellipsis",
								whiteSpace: "nowrap",
								lineHeight: 1.3,
							}}
						>
							{customStatus.emoji && <span style={{ marginRight: 3 }}>{customStatus.emoji}</span>}
							{customStatus.text}
						</div>
					) : (
						<div
							data-testid="user-status-placeholder"
							style={{ fontSize: 11, color: "var(--fg-4)", lineHeight: 1.3 }}
						>
							Set a status...
						</div>
					)}
				</div>
				<button
					type="button"
					data-testid="user-status-edit-btn"
					onClick={onEditStatus}
					aria-label="Edit status"
					style={{
						background: "none",
						border: "none",
						cursor: "pointer",
						padding: 4,
						borderRadius: 6,
						color: "var(--fg-3)",
						display: "flex",
						alignItems: "center",
					}}
				>
					<Icon name="edit-2" size={14} color="var(--fg-3)" />
				</button>
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
	pqBindingHex,
	msgSearch,
	onMsgSearch,
	onAddMember,
}: {
	chat: Chat;
	onCall: () => void;
	onVideo: () => void;
	onInfo: () => void;
	infoOpen: boolean;
	pqBindingHex?: string;
	msgSearch: string;
	onMsgSearch: (q: string) => void;
	onAddMember?: () => void;
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
					<Avatar name={chat.nickname ?? chat.name} size={38} online={chat.online} />
					<div style={{ flex: 1, minWidth: 0 }}>
						<div style={{ display: "flex", alignItems: "center", gap: 8 }}>
							<span
								data-testid="conversation-header-name"
								style={{ fontSize: 15, fontWeight: 500, color: "var(--fg-1)" }}
							>
								{chat.nickname ?? chat.name}
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
							{chat.isGroup ? (
								<span data-testid="group-status">
									Group
									{chat.memberCount && chat.memberCount > 1 ? ` · ${chat.memberCount} members` : ""}
								</span>
							) : (
								<>
									{chat.online ? "online" : `last seen ${chat.lastSeen ?? "recently"}`}
									{chat.typing && (
										<span style={{ marginLeft: 8 }}>
											· <TypingDots />
										</span>
									)}
								</>
							)}
						</div>
					</div>
					<div style={{ display: "flex", gap: 2 }}>
						<IconBtn icon="search" onClick={handleOpenSearch} label="Search in conversation" />
						{chat.isGroup && onAddMember && (
							<IconBtn icon="user-plus" onClick={onAddMember} label="Add member" />
						)}
						<IconBtn icon="phone" onClick={onCall} label="Voice call" />
						<IconBtn icon="video" onClick={onVideo} label="Video call" />
						<IconBtn icon="more-horizontal" onClick={onInfo} active={infoOpen} label="Info" />
					</div>
				</>
			)}
		</header>
	);
}

function getReactionHandles(
	senders: string[],
	members: ChatMember[] | undefined,
	myDeviceId: string | undefined,
): string[] {
	return senders.map((id) => {
		if (myDeviceId && id === myDeviceId) return "You";
		const member = members?.find((m) => m.id === id);
		return member ? member.handle : id.slice(0, 8);
	});
}

function MessageBubble({
	msg,
	partner,
	highlight,
	highlightQuery,
	isCurrentMatch,
	myDeviceId,
	isGroup,
	members,
	showAvatar,
	onReact,
	onReply,
	onEdit,
	onDelete,
	onPin,
	onForward,
	onStar,
	onShare,
	onCopy,
	onCancelScheduled,
	onVote,
	onOpenLightbox,
	onJumpToReply,
	countdownTick,
}: {
	msg: ChatMessage;
	partner: string;
	highlight?: string;
	/** Query string from the in-chat search bar — produces search-highlight marks. */
	highlightQuery?: string;
	/** True when this bubble is the current navigated match in the in-chat search. */
	isCurrentMatch?: boolean;
	myDeviceId?: string;
	isGroup?: boolean;
	members?: ChatMember[];
	/** When false, suppress the sender avatar and collapse the top margin (same-group continuation). */
	showAvatar?: boolean;
	onReact?: (emoji: string) => void;
	onReply?: () => void;
	onEdit?: () => void;
	onDelete?: () => void;
	onPin?: () => void;
	onForward?: () => void;
	onStar?: () => void;
	onShare?: () => void;
	onCopy?: () => void;
	/** Called when the user cancels a pending scheduled message. */
	onCancelScheduled?: () => void;
	/** Called when the user votes on a poll option. */
	onVote?: (optionIdx: number) => void;
	/** Called when the user clicks a media image to view it full-screen. */
	onOpenLightbox?: () => void;
	/** Called when the user clicks the reply quote to scroll to the original message. */
	onJumpToReply?: (messageId: string) => void;
	/** Incremented every second when there are expiring messages; drives countdown re-render. */
	countdownTick?: number;
}) {
	const isMe = msg.from === "me";
	const [pickerOpen, setPickerOpen] = useState(false);
	const [hovered, setHovered] = useState(false);
	const [copied, setCopied] = useState(false);
	const [hoveredReaction, setHoveredReaction] = useState<string | null>(null);
	const hasLightbox = !!onOpenLightbox && !!msg.media;
	const reactionEntries = msg.reactions ? Object.entries(msg.reactions) : [];
	const totalReactionCount = reactionEntries.reduce((sum, [, senders]) => sum + senders.length, 0);

	// showAvatar defaults to !msg.continued for backward-compat with seed data that lacks ts.
	const avatarVisible = showAvatar ?? !msg.continued;

	return (
		<div
			data-testid="message-bubble"
			style={{
				display: "flex",
				flexDirection: "column",
				alignItems: isMe ? "flex-end" : "flex-start",
				marginTop: avatarVisible ? 8 : 2,
			}}
			onMouseEnter={() => setHovered(true)}
			onMouseLeave={() => setHovered(false)}
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
						{avatarVisible && (
							<div data-testid="msg-avatar">
								<Avatar name={partner} size={28} />
							</div>
						)}
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
						{msg.deleted ? (
							<span
								data-testid="deleted-placeholder"
								style={{ fontStyle: "italic", opacity: 0.55, fontSize: 13 }}
							>
								This message was deleted
							</span>
						) : (
							<>
								{msg.replyTo && (
									<button
										type="button"
										data-testid="reply-quote"
										onClick={
											onJumpToReply && msg.replyTo.messageId
												? () => onJumpToReply(msg.replyTo?.messageId ?? "")
												: undefined
										}
										style={{
											display: "block",
											background: "none",
											border: "none",
											padding: 0,
											cursor: onJumpToReply ? "pointer" : "default",
											textAlign: "left",
											borderLeft: `2px solid ${isMe ? "rgba(42,17,0,0.4)" : "rgba(168,200,255,0.5)"}`,
											paddingLeft: 8,
											marginBottom: 6,
											fontSize: 12,
											lineHeight: 1.4,
											color: isMe ? "rgba(42,17,0,0.65)" : "var(--fg-3)",
											overflow: "hidden",
											textOverflow: "ellipsis",
											whiteSpace: "nowrap",
											maxWidth: "100%",
										}}
									>
										{msg.replyTo.excerpt}
									</button>
								)}
								{msg.poll ? (
									<PollView poll={msg.poll} isMe={isMe} onVote={onVote} />
								) : msg.media ? (
									hasLightbox ? (
										<button
											type="button"
											onClick={onOpenLightbox}
											data-testid="media-open-lightbox"
											aria-label="View image full screen"
											style={{
												background: "none",
												border: "none",
												padding: 0,
												cursor: "pointer",
												display: "block",
											}}
										>
											<MediaImage media={msg.media} />
										</button>
									) : (
										<MediaImage media={msg.media} />
									)
								) : (
									<HighlightedText
										text={msg.text}
										highlight={highlightQuery ?? highlight ?? ""}
										isCurrentMatch={isCurrentMatch}
									/>
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
										{isMe &&
											(msg.read ? (
												<span data-testid="read-indicator" aria-label="Read">
													<Icon name="doublecheck" size={12} color="#A8C8FF" />
												</span>
											) : msg.delivered ? (
												<span data-testid="read-indicator" aria-label="Delivered">
													<Icon name="doublecheck" size={12} color="currentColor" />
												</span>
											) : msg.id && !msg.id.startsWith("opt_") ? (
												<span data-testid="read-indicator" aria-label="Sent">
													<Icon name="check" size={12} color="currentColor" />
												</span>
											) : (
												<span data-testid="read-indicator" aria-label="Sending">
													<Icon
														name="timer"
														size={12}
														color="currentColor"
														style={{ opacity: 0.45 }}
													/>
												</span>
											))}
									</span>
								)}
								{msg.edited && (
									<span
										data-testid="edited-badge"
										style={{
											display: "inline-block",
											marginLeft: 6,
											fontSize: 10,
											opacity: 0.6,
											fontStyle: "italic",
											verticalAlign: "2px",
										}}
									>
										edited
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
										<span data-testid="disappearing-badge" data-countdown-tick={countdownTick ?? 0}>
											Disappearing · {formatTimeLeft(msg.expiresAt)}
										</span>
									</div>
								)}
								{msg.scheduledFor && (
									<div
										style={{
											display: "flex",
											alignItems: "center",
											gap: 4,
											marginTop: 4,
											fontSize: 10,
											color: "#A8C8FF",
											opacity: 0.9,
										}}
									>
										<Icon name="timer" size={10} color="#A8C8FF" />
										<span data-testid="scheduled-badge">
											Scheduled ·{" "}
											{new Date(msg.scheduledFor).toLocaleTimeString([], {
												hour: "2-digit",
												minute: "2-digit",
											})}
										</span>
										{onCancelScheduled && (
											<button
												type="button"
												onClick={onCancelScheduled}
												data-testid="cancel-scheduled-btn"
												aria-label="Cancel scheduled message"
												style={{
													background: "none",
													border: "none",
													color: "#A8C8FF",
													cursor: "pointer",
													padding: 0,
													fontSize: 10,
													textDecoration: "underline",
													lineHeight: 1,
												}}
											>
												Cancel
											</button>
										)}
									</div>
								)}
							</>
						)}
					</div>

					{/* Delete button — appears on hover for own messages with a stable id, when not already deleted */}
					{onDelete && isMe && hovered && msg.id && !msg.deleted && (
						<div
							style={{
								position: "absolute",
								top: -10,
								right: 26,
							}}
						>
							<button
								type="button"
								onClick={onDelete}
								aria-label="Delete message"
								data-testid="delete-button"
								style={{
									width: 22,
									height: 22,
									borderRadius: "50%",
									border: "1px solid var(--border-faint)",
									background: "var(--bg-elevated)",
									color: "var(--fg-3)",
									cursor: "pointer",
									display: "flex",
									alignItems: "center",
									justifyContent: "center",
									padding: 0,
								}}
							>
								<Icon name="trash" size={11} />
							</button>
						</div>
					)}

					{/* Pin button — appears on hover for messages with a stable ID, not deleted */}
					{onPin && msg.id && hovered && !msg.deleted && (
						<div
							style={{
								position: "absolute",
								top: -10,
								left: 0,
							}}
						>
							<button
								type="button"
								onClick={onPin}
								aria-label={msg.pinned ? "Unpin message" : "Pin message"}
								data-testid="pin-button"
								style={{
									width: 22,
									height: 22,
									borderRadius: "50%",
									border: "1px solid var(--border-faint)",
									background: msg.pinned ? "rgba(255,138,61,0.18)" : "var(--bg-elevated)",
									color: msg.pinned ? "#FF8A3D" : "var(--fg-3)",
									cursor: "pointer",
									display: "flex",
									alignItems: "center",
									justifyContent: "center",
									padding: 0,
								}}
							>
								<Icon name="pin" size={11} />
							</button>
						</div>
					)}

					{/* Forward button — appears on hover for non-deleted messages with a stable ID */}
					{onForward && msg.id && hovered && !msg.deleted && (
						<div
							style={{
								position: "absolute",
								top: -10,
								left: 26,
							}}
						>
							<button
								type="button"
								onClick={onForward}
								aria-label="Forward message"
								data-testid="forward-button"
								style={{
									width: 22,
									height: 22,
									borderRadius: "50%",
									border: "1px solid var(--border-faint)",
									background: "var(--bg-elevated)",
									color: "var(--fg-3)",
									cursor: "pointer",
									display: "flex",
									alignItems: "center",
									justifyContent: "center",
									padding: 0,
								}}
							>
								<Icon name="forward" size={11} />
							</button>
						</div>
					)}

					{/* Star button — appears on hover for non-deleted messages (optimistic msgs included) */}
					{onStar && hovered && !msg.deleted && (
						<div
							style={{
								position: "absolute",
								top: -10,
								left: 52,
							}}
						>
							<button
								type="button"
								onClick={onStar}
								aria-label={msg.starred ? "Unstar message" : "Star message"}
								data-testid="star-button"
								style={{
									width: 22,
									height: 22,
									borderRadius: "50%",
									border: "1px solid var(--border-faint)",
									background: msg.starred ? "rgba(255,138,61,0.18)" : "var(--bg-elevated)",
									color: msg.starred ? "#FF8A3D" : "var(--fg-3)",
									cursor: "pointer",
									display: "flex",
									alignItems: "center",
									justifyContent: "center",
									padding: 0,
								}}
							>
								<Icon name="star" size={11} />
							</button>
						</div>
					)}

					{/* Share button — Web Share API; appears on hover for non-deleted text messages */}
					{onShare && hovered && !msg.deleted && msg.text && msg.text !== "[image]" && (
						<div
							style={{
								position: "absolute",
								top: -10,
								left: 78,
							}}
						>
							<button
								type="button"
								onClick={onShare}
								aria-label="Share message"
								data-testid="share-button"
								style={{
									width: 22,
									height: 22,
									borderRadius: "50%",
									border: "1px solid var(--border-faint)",
									background: "var(--bg-elevated)",
									color: "var(--fg-3)",
									cursor: "pointer",
									display: "flex",
									alignItems: "center",
									justifyContent: "center",
									padding: 0,
								}}
							>
								<Icon name="share-2" size={11} />
							</button>
						</div>
					)}

					{/* Copy button — clipboard; appears on hover for non-deleted text messages */}
					{onCopy && hovered && !msg.deleted && msg.text && msg.text !== "[image]" && (
						<div
							style={{
								position: "absolute",
								top: -10,
								left: 104,
							}}
						>
							<button
								type="button"
								onClick={() => {
									onCopy();
									setCopied(true);
									setTimeout(() => setCopied(false), 1500);
								}}
								aria-label="Copy message"
								data-testid="copy-button"
								style={{
									width: 22,
									height: 22,
									borderRadius: "50%",
									border: "1px solid var(--border-faint)",
									background: copied ? "rgba(255,138,61,0.18)" : "var(--bg-elevated)",
									color: copied ? "#FF8A3D" : "var(--fg-3)",
									cursor: "pointer",
									display: "flex",
									alignItems: "center",
									justifyContent: "center",
									padding: 0,
								}}
							>
								<Icon name={copied ? "check" : "copy"} size={11} />
							</button>
						</div>
					)}

					{/* Edit button — appears on hover for own messages only, when not deleted */}
					{onEdit && isMe && hovered && !msg.deleted && (
						<div
							style={{
								position: "absolute",
								top: -10,
								right: 0,
							}}
						>
							<button
								type="button"
								onClick={onEdit}
								aria-label="Edit message"
								data-testid="edit-button"
								style={{
									width: 22,
									height: 22,
									borderRadius: "50%",
									border: "1px solid var(--border-faint)",
									background: "var(--bg-elevated)",
									color: "var(--fg-3)",
									cursor: "pointer",
									display: "flex",
									alignItems: "center",
									justifyContent: "center",
									padding: 0,
								}}
							>
								<Icon name="pencil" size={11} />
							</button>
						</div>
					)}

					{/* Reply button — appears on hover, hidden for deleted messages */}
					{onReply && hovered && !msg.deleted && (
						<div
							style={{
								position: "absolute",
								bottom: -10,
								...(isMe ? { right: -28 } : { left: -28 }),
							}}
						>
							<button
								type="button"
								onClick={onReply}
								aria-label="Reply"
								data-testid="reply-button"
								style={{
									width: 22,
									height: 22,
									borderRadius: "50%",
									border: "1px solid var(--border-faint)",
									background: "var(--bg-elevated)",
									color: "var(--fg-3)",
									cursor: "pointer",
									display: "flex",
									alignItems: "center",
									justifyContent: "center",
									padding: 0,
								}}
							>
								<Icon name="reply" size={11} />
							</button>
						</div>
					)}

					{/* Reaction picker trigger — only shown when message has a stable ID and is not deleted */}
					{onReact && msg.id && !msg.deleted && (
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
					{reactionEntries.map(([emoji, senders]) => {
						const isMine = myDeviceId ? senders.includes(myDeviceId) : false;
						const isChipHovered = hoveredReaction === emoji;
						const tooltipHandles = getReactionHandles(senders, members, myDeviceId);
						return (
							<div
								key={emoji}
								data-testid={`reaction-chip-wrapper-${emoji}`}
								style={{ position: "relative", display: "inline-flex" }}
								onMouseEnter={() => setHoveredReaction(emoji)}
								onMouseLeave={() => setHoveredReaction(null)}
							>
								{isChipHovered && tooltipHandles.length > 0 && (
									<div
										data-testid={`reaction-tooltip-${emoji}`}
										style={{
											position: "absolute",
											bottom: "calc(100% + 6px)",
											left: "50%",
											transform: "translateX(-50%)",
											background: "rgba(14,14,22,0.96)",
											border: "1px solid var(--border-faint)",
											borderRadius: 8,
											padding: "4px 10px",
											fontSize: 11,
											color: "var(--fg-1)",
											whiteSpace: "nowrap",
											pointerEvents: "none",
											zIndex: 20,
											boxShadow: "0 2px 8px rgba(0,0,0,0.45)",
											lineHeight: 1.6,
										}}
									>
										{emoji} {tooltipHandles.join(", ")}
									</div>
								)}
								<button
									type="button"
									onClick={() => onReact?.(emoji)}
									data-testid={`reaction-chip-${emoji}`}
									aria-pressed={isMine}
									style={{
										background: isMine ? "rgba(255,138,61,0.18)" : "rgba(255,255,255,0.06)",
										border: isMine
											? "1px solid rgba(255,138,61,0.5)"
											: "1px solid rgba(255,255,255,0.12)",
										borderRadius: 12,
										padding: "2px 8px",
										fontSize: 12,
										cursor: "pointer",
										display: "inline-flex",
										alignItems: "center",
										gap: 4,
										color: isMine ? "#FF8A3D" : "var(--fg-2)",
									}}
								>
									{emoji}
									<span style={{ fontSize: 10, opacity: 0.75 }}>{senders.length}</span>
								</button>
							</div>
						);
					})}
				</div>
			)}
			{isGroup && totalReactionCount >= 2 && (
				<span
					data-testid="reaction-total-summary"
					style={{
						fontSize: 11,
						color: "var(--fg-4)",
						paddingLeft: isMe ? 0 : 36,
						marginTop: reactionEntries.length > 0 ? 2 : 4,
						letterSpacing: "0.01em",
					}}
				>
					{`· ${totalReactionCount} reaction${totalReactionCount === 1 ? "" : "s"}`}
				</span>
			)}
		</div>
	);
}

// Stable key for a message group entry — day labels use their text,
// messages use their position relative to day label.
type Group =
	| { type: "day"; label: string; key: string }
	| { type: "msg"; msg: ChatMessage; showAvatar: boolean; key: string }
	| { type: "new-messages"; key: string };

/** Messages from the same sender within this window form a visual group. */
const TIME_GROUP_WINDOW_MS = 3 * 60 * 1000;

function buildGroups(messages: ChatMessage[], firstUnreadIndex?: number): Group[] {
	const groups: Group[] = [];
	let lastDay: string | undefined = undefined;
	let dayMsgCount = 0;
	let markerInserted = false;
	let lastFrom: string | undefined = undefined;
	let lastTs: number | undefined = undefined;
	for (let i = 0; i < messages.length; i++) {
		const m = messages[i];
		if (firstUnreadIndex !== undefined && i === firstUnreadIndex && !markerInserted) {
			groups.push({ type: "new-messages", key: "new-messages-divider" });
			markerInserted = true;
		}
		if (m.day && m.day !== lastDay) {
			groups.push({ type: "day", label: m.day, key: `day-${m.day}` });
			lastDay = m.day;
			dayMsgCount = 0;
			// Day boundary always breaks any visual group.
			lastFrom = undefined;
			lastTs = undefined;
		}
		// Compute whether this message starts a new visual group:
		// - Different sender from the previous message → always show avatar/name header.
		// - Same sender with both timestamps present → show when gap ≥ 3 minutes.
		// - Same sender but no timestamps (legacy seed data) → fall back to continued flag.
		const consecutive = m.from === lastFrom;
		let showAvatar: boolean;
		if (!consecutive) {
			showAvatar = true;
		} else if (m.ts !== undefined && lastTs !== undefined) {
			showAvatar = m.ts - lastTs >= TIME_GROUP_WINDOW_MS;
		} else {
			showAvatar = !m.continued;
		}
		groups.push({
			type: "msg",
			msg: m,
			showAvatar,
			key: `msg-${lastDay ?? "no-day"}-${dayMsgCount++}-${m.from}-${m.text.slice(0, 8)}`,
		});
		lastFrom = m.from;
		lastTs = m.ts;
	}
	return groups;
}

function MessageList({
	chatId,
	messages,
	partner,
	searchQuery,
	searchMatchIds,
	searchMatchIndex,
	searchMatchQuery,
	myDeviceId,
	isGroup,
	members,
	isTyping,
	onReact,
	onReply,
	onEdit,
	onDelete,
	onPin,
	onForward,
	onStar,
	onShare,
	onCopy,
	onCancelScheduled,
	onVote,
	onOpenLightbox,
	onJumpToReply,
	firstUnreadIndex,
	jumpToMessageId,
	onJumpComplete,
	countdownTick,
}: {
	chatId: string;
	messages: ChatMessage[];
	partner: string;
	searchQuery?: string;
	/** Message IDs matching the in-chat search bar query (from ChatLayout). */
	searchMatchIds?: string[];
	/** 0-based index of the currently navigated match. */
	searchMatchIndex?: number;
	/** The raw query string for the in-chat search bar — used to highlight matched text. */
	searchMatchQuery?: string;
	myDeviceId?: string;
	isGroup?: boolean;
	members?: ChatMember[];
	isTyping?: boolean;
	onReact?: (msgId: string, emoji: string) => void;
	onReply?: (msg: ChatMessage) => void;
	onEdit?: (msg: ChatMessage) => void;
	onDelete?: (msgId: string) => void;
	onPin?: (msgId: string) => void;
	onForward?: (msg: ChatMessage) => void;
	onStar?: (msgId: string | undefined, msgText: string) => void;
	onShare?: (msg: ChatMessage) => void;
	onCopy?: (msg: ChatMessage) => void;
	onCancelScheduled?: (msgId: string) => void;
	onVote?: (msgId: string | undefined, optionIdx: number) => void;
	onOpenLightbox?: (msg: ChatMessage) => void;
	/** Called when the user clicks a reply quote to scroll to the original message. */
	onJumpToReply?: (messageId: string) => void;
	firstUnreadIndex?: number;
	jumpToMessageId?: string;
	onJumpComplete?: () => void;
	/** Incremented every second when there are expiring messages; drives countdown re-render. */
	countdownTick?: number;
}) {
	const ref = useRef<HTMLDivElement>(null);
	const [flashingId, setFlashingId] = useState<string | null>(null);
	const isAtBottomRef = useRef(true);
	const [isAtBottom, setIsAtBottom] = useState(true);
	const [newMsgCount, setNewMsgCount] = useState(0);
	const prevMsgCountRef = useRef(messages.length);

	// Scroll to bottom on every render — gated off when a jump is active or the user has scrolled up.
	useLayoutEffect(() => {
		if (ref.current && !jumpToMessageId && isAtBottomRef.current) {
			ref.current.scrollTop = ref.current.scrollHeight;
		}
	});

	// Scroll to the jumped-to message and apply the flash highlight.
	useEffect(() => {
		if (!jumpToMessageId || !ref.current) return;
		const el = ref.current.querySelector(`[data-msg-id="${CSS.escape(jumpToMessageId)}"]`);
		if (el) {
			el.scrollIntoView({ block: "center", behavior: "smooth" });
			setFlashingId(jumpToMessageId);
			const timer = setTimeout(() => {
				setFlashingId(null);
				onJumpComplete?.();
			}, 1400);
			return () => clearTimeout(timer);
		}
		// Message not found in DOM (no server-assigned ID) — still clear jump state.
		onJumpComplete?.();
	}, [jumpToMessageId, onJumpComplete]);

	// Reset scroll-to-bottom state when the active chat changes so the new chat
	// always starts at the bottom. Must be declared before the messages.length
	// effect so prevMsgCountRef is updated first on a chat switch.
	// biome-ignore lint/correctness/useExhaustiveDependencies: messages.length read as snapshot at chat-switch time; intentional reset on chatId only
	useEffect(() => {
		isAtBottomRef.current = true;
		setIsAtBottom(true);
		setNewMsgCount(0);
		prevMsgCountRef.current = messages.length;
	}, [chatId]);

	// Count new messages that arrive while the user is scrolled up.
	useEffect(() => {
		const added = messages.length - prevMsgCountRef.current;
		prevMsgCountRef.current = messages.length;
		if (added > 0 && !isAtBottomRef.current) {
			setNewMsgCount((c) => Math.min(c + added, 99));
		}
	}, [messages.length]);

	const handleScroll = useCallback(() => {
		const el = ref.current;
		if (!el) return;
		const atBottom = el.scrollTop + el.clientHeight >= el.scrollHeight - 80;
		isAtBottomRef.current = atBottom;
		setIsAtBottom(atBottom);
		if (atBottom) setNewMsgCount(0);
	}, []);

	const handleJumpToBottom = useCallback(() => {
		if (ref.current) {
			ref.current.scrollTop = ref.current.scrollHeight;
		}
		isAtBottomRef.current = true;
		setIsAtBottom(true);
		setNewMsgCount(0);
	}, []);

	const groups = buildGroups(messages, firstUnreadIndex);

	const matchCount = searchQuery
		? messages.filter((m) => !m.media && m.text.toLowerCase().includes(searchQuery.toLowerCase()))
				.length
		: 0;

	return (
		<div
			style={{
				position: "relative",
				flex: 1,
				overflow: "hidden",
				display: "flex",
				flexDirection: "column",
			}}
		>
			<div
				ref={ref}
				data-testid="message-list-scroll"
				onScroll={handleScroll}
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
							data-testid="date-separator"
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
					) : g.type === "new-messages" ? (
						<div
							key={g.key}
							data-testid="new-messages-divider"
							style={{
								display: "flex",
								alignItems: "center",
								gap: 10,
								margin: "8px 0",
							}}
						>
							<div
								style={{
									flex: 1,
									height: 1,
									background: "rgba(255,138,61,0.35)",
								}}
							/>
							<span
								style={{
									fontSize: 10,
									fontWeight: 600,
									letterSpacing: "0.12em",
									color: "#FF8A3D",
									textTransform: "uppercase",
									whiteSpace: "nowrap",
								}}
							>
								New Messages
							</span>
							<div
								style={{
									flex: 1,
									height: 1,
									background: "rgba(255,138,61,0.35)",
								}}
							/>
						</div>
					) : (
						<div
							key={g.key}
							data-msg-id={g.msg.id ?? undefined}
							data-jump-flash={flashingId != null && flashingId === g.msg.id ? "true" : undefined}
						>
							<MessageBubble
								msg={g.msg}
								partner={partner}
								highlight={searchQuery}
								highlightQuery={
									searchMatchIds && searchMatchIds.length > 0 && g.msg.id
										? searchMatchIds.includes(g.msg.id)
											? (searchMatchQuery ?? searchQuery ?? "")
											: undefined
										: undefined
								}
								isCurrentMatch={
									searchMatchIds && searchMatchIds.length > 0 && searchMatchIndex !== undefined
										? searchMatchIds[searchMatchIndex] === g.msg.id
										: false
								}
								myDeviceId={myDeviceId}
								isGroup={isGroup}
								members={members}
								showAvatar={g.showAvatar}
								onReact={
									g.msg.id && onReact
										? (emoji) => {
												const id = g.msg.id;
												if (id) onReact(id, emoji);
											}
										: undefined
								}
								onReply={onReply ? () => onReply(g.msg) : undefined}
								onEdit={g.msg.from === "me" && onEdit ? () => onEdit(g.msg) : undefined}
								onDelete={(() => {
									const msgId = g.msg.id;
									return msgId && g.msg.from === "me" && onDelete
										? () => onDelete(msgId)
										: undefined;
								})()}
								onPin={(() => {
									const msgId = g.msg.id;
									return msgId && onPin ? () => onPin(msgId) : undefined;
								})()}
								onForward={onForward && !g.msg.deleted ? () => onForward(g.msg) : undefined}
								onStar={onStar ? () => onStar(g.msg.id, g.msg.text) : undefined}
								onShare={onShare && !g.msg.deleted ? () => onShare(g.msg) : undefined}
								onCopy={
									onCopy && !g.msg.deleted && g.msg.text && g.msg.text !== "[image]"
										? () => onCopy(g.msg)
										: undefined
								}
								onCancelScheduled={(() => {
									const msgId = g.msg.id;
									return msgId && g.msg.scheduledFor && onCancelScheduled
										? () => onCancelScheduled(msgId)
										: undefined;
								})()}
								onVote={onVote ? (optIdx) => onVote(g.msg.id, optIdx) : undefined}
								onOpenLightbox={
									onOpenLightbox && g.msg.media ? () => onOpenLightbox(g.msg) : undefined
								}
								onJumpToReply={onJumpToReply}
								countdownTick={countdownTick}
							/>
						</div>
					),
				)}
				{isTyping && (
					<div
						data-testid="typing-bubble"
						style={{ display: "flex", alignItems: "flex-end", gap: 8, paddingTop: 4 }}
					>
						<div
							style={{
								width: 30,
								height: 30,
								borderRadius: "50%",
								background: "rgba(168,200,255,0.18)",
								display: "flex",
								alignItems: "center",
								justifyContent: "center",
								fontSize: 12,
								fontWeight: 700,
								color: "#A8C8FF",
								flexShrink: 0,
							}}
						>
							{partner[0]?.toUpperCase() ?? "?"}
						</div>
						<div
							style={{
								background: "rgba(255,255,255,0.06)",
								border: "1px solid rgba(255,255,255,0.10)",
								borderRadius: "4px 16px 16px 16px",
								padding: "10px 16px",
								minWidth: 60,
								display: "flex",
								alignItems: "center",
							}}
						>
							<TypingDots />
						</div>
					</div>
				)}
			</div>
			{!isAtBottom && (
				<button
					type="button"
					data-testid="jump-to-bottom-btn"
					aria-label="Jump to bottom"
					onClick={handleJumpToBottom}
					style={{
						position: "absolute",
						bottom: 16,
						right: 20,
						width: 40,
						height: 40,
						borderRadius: "50%",
						background: "rgba(255,138,61,0.15)",
						border: "1px solid rgba(255,138,61,0.4)",
						color: "#FF8A3D",
						display: "flex",
						alignItems: "center",
						justifyContent: "center",
						cursor: "pointer",
						zIndex: 10,
					}}
				>
					<Icon name="chevron-down" size={18} color="#FF8A3D" />
					{newMsgCount > 0 && (
						<span
							data-testid="jump-to-bottom-badge"
							style={{
								position: "absolute",
								top: -6,
								right: -6,
								minWidth: 18,
								height: 18,
								borderRadius: 9,
								background: "#FF8A3D",
								color: "#040408",
								fontSize: 10,
								fontWeight: 700,
								display: "flex",
								alignItems: "center",
								justifyContent: "center",
								padding: "0 4px",
							}}
						>
							{newMsgCount >= 99 ? "99+" : newMsgCount}
						</span>
					)}
				</button>
			)}
		</div>
	);
}

// ── EmojiPickerPopup ─────────────────────────────────────────────────────────

const EMOJI_CATEGORIES = [
	{
		label: "Smileys",
		emojis: [
			"😊",
			"😂",
			"🥰",
			"😍",
			"😭",
			"😅",
			"🤣",
			"😎",
			"🙄",
			"😤",
			"🥺",
			"😬",
			"😴",
			"🤔",
			"😏",
			"🤩",
		],
	},
	{
		label: "Gestures",
		emojis: ["👍", "👎", "👏", "🙌", "👋", "🤝", "🤞", "💪", "✌️", "🫶"],
	},
	{
		label: "Symbols",
		emojis: ["❤️", "💔", "🔥", "✨", "💯", "🎉", "💡", "🌟", "💫", "🎊"],
	},
] as const;

function EmojiPickerPopup({ onSelect }: { onSelect: (emoji: string) => void }) {
	return (
		<div
			data-testid="emoji-picker"
			style={{
				position: "absolute",
				bottom: "calc(100% + 8px)",
				right: 0,
				background: "var(--bg-surface)",
				border: "1px solid var(--border-soft)",
				borderRadius: 12,
				padding: "10px 12px 12px",
				width: 284,
				boxShadow: "0 8px 32px rgba(0,0,0,0.45)",
				zIndex: 100,
			}}
		>
			{EMOJI_CATEGORIES.map((cat) => (
				<div key={cat.label} style={{ marginBottom: 8 }}>
					<div
						style={{
							fontSize: 10,
							color: "var(--fg-3)",
							fontFamily: "var(--font-mono)",
							letterSpacing: "0.06em",
							marginBottom: 6,
						}}
					>
						{cat.label.toUpperCase()}
					</div>
					<div style={{ display: "flex", flexWrap: "wrap", gap: 2 }}>
						{cat.emojis.map((emoji) => (
							<button
								key={emoji}
								type="button"
								onClick={() => onSelect(emoji)}
								aria-label={emoji}
								data-testid="emoji-btn"
								style={{
									fontSize: 20,
									width: 36,
									height: 36,
									display: "flex",
									alignItems: "center",
									justifyContent: "center",
									background: "transparent",
									border: "none",
									borderRadius: 6,
									cursor: "pointer",
									transition: "background 100ms",
								}}
								onMouseEnter={(ev) => {
									(ev.currentTarget as HTMLButtonElement).style.background = "var(--bg-elevated)";
								}}
								onMouseLeave={(ev) => {
									(ev.currentTarget as HTMLButtonElement).style.background = "transparent";
								}}
							>
								{emoji}
							</button>
						))}
					</div>
				</div>
			))}
		</div>
	);
}

// ── PollView ──────────────────────────────────────────────────────────────────

function PollView({
	poll,
	isMe,
	onVote,
}: {
	poll: NonNullable<ChatMessage["poll"]>;
	isMe: boolean;
	onVote?: (optionIdx: number) => void;
}) {
	const totalVotes = poll.options.reduce((s, o) => s + o.voters.length, 0);
	return (
		<div data-testid="poll-view" style={{ minWidth: 200 }}>
			<div
				data-testid="poll-question"
				style={{ fontWeight: 600, fontSize: 14, marginBottom: 10, lineHeight: 1.3 }}
			>
				{poll.question}
			</div>
			{poll.options.map((opt, idx) => {
				const voted = opt.voters.includes("me");
				const pct = totalVotes > 0 ? Math.round((opt.voters.length / totalVotes) * 100) : 0;
				const barColor = isMe ? "rgba(42,17,0,0.25)" : "rgba(168,200,255,0.25)";
				const barFill = voted ? (isMe ? "rgba(42,17,0,0.5)" : "rgba(168,200,255,0.55)") : barColor;
				return (
					<button
						// biome-ignore lint/suspicious/noArrayIndexKey: stable option index
						key={idx}
						type="button"
						data-testid={`poll-option-${idx}`}
						onClick={() => onVote?.(idx)}
						style={{
							position: "relative",
							display: "flex",
							justifyContent: "space-between",
							alignItems: "center",
							width: "100%",
							marginBottom: 6,
							padding: "7px 10px",
							borderRadius: 8,
							border: voted
								? `1px solid ${isMe ? "rgba(42,17,0,0.4)" : "rgba(168,200,255,0.5)"}`
								: "1px solid transparent",
							background: "transparent",
							cursor: "pointer",
							fontFamily: "var(--font-sans)",
							fontSize: 13,
							color: "inherit",
							overflow: "hidden",
							textAlign: "left",
						}}
					>
						{/* Fill bar */}
						<div
							data-testid={`poll-bar-${idx}`}
							style={{
								position: "absolute",
								inset: 0,
								width: `${pct}%`,
								background: barFill,
								borderRadius: 8,
								transition: "width 300ms ease",
								zIndex: 0,
							}}
						/>
						<span style={{ position: "relative", zIndex: 1 }}>{opt.text}</span>
						<span
							data-testid={`poll-pct-${idx}`}
							style={{ position: "relative", zIndex: 1, opacity: 0.7, fontSize: 11 }}
						>
							{totalVotes > 0 ? `${pct}%` : ""}
						</span>
					</button>
				);
			})}
			<div data-testid="poll-total-votes" style={{ fontSize: 10, opacity: 0.55, marginTop: 4 }}>
				{totalVotes} {totalVotes === 1 ? "vote" : "votes"}
			</div>
		</div>
	);
}

// ── PollCreatorPopup ──────────────────────────────────────────────────────────

function PollCreatorPopup({
	onCreate,
	onClose,
}: {
	onCreate: (question: string, options: string[]) => void;
	onClose: () => void;
}) {
	const [question, setQuestion] = useState("");
	const [options, setOptions] = useState(["", ""]);

	const handleSubmit = () => {
		const q = question.trim();
		const opts = options.map((o) => o.trim()).filter(Boolean);
		if (!q || opts.length < 2) return;
		onCreate(q, opts);
	};

	const updateOption = (idx: number, val: string) =>
		setOptions((prev) => prev.map((o, i) => (i === idx ? val : o)));

	const addOption = () => {
		if (options.length >= 4) return;
		setOptions((prev) => [...prev, ""]);
	};

	return (
		<div
			data-testid="poll-creator"
			style={{
				position: "absolute",
				bottom: "calc(100% + 8px)",
				left: 0,
				background: "var(--bg-surface)",
				border: "1px solid var(--border-soft)",
				borderRadius: 12,
				padding: "14px 16px",
				boxShadow: "0 8px 32px rgba(0,0,0,0.45)",
				zIndex: 100,
				minWidth: 260,
				display: "flex",
				flexDirection: "column",
				gap: 8,
			}}
		>
			<div style={{ fontSize: 12, fontWeight: 600, color: "var(--fg-2)", letterSpacing: "0.04em" }}>
				Create poll
			</div>
			<input
				data-testid="poll-question-input"
				value={question}
				onChange={(e) => setQuestion(e.target.value)}
				placeholder="Ask a question…"
				style={{
					background: "var(--bg-void)",
					border: "1px solid var(--border-soft)",
					borderRadius: 8,
					color: "var(--fg-1)",
					fontFamily: "var(--font-sans)",
					fontSize: 13,
					padding: "6px 10px",
					outline: "none",
					width: "100%",
					boxSizing: "border-box",
				}}
			/>
			{options.map((opt, idx) => (
				<input
					// biome-ignore lint/suspicious/noArrayIndexKey: stable fixed-size array of poll options
					key={idx}
					data-testid={`poll-option-input-${idx}`}
					value={opt}
					onChange={(e) => updateOption(idx, e.target.value)}
					placeholder={`Option ${idx + 1}`}
					style={{
						background: "var(--bg-void)",
						border: "1px solid var(--border-soft)",
						borderRadius: 8,
						color: "var(--fg-1)",
						fontFamily: "var(--font-sans)",
						fontSize: 13,
						padding: "6px 10px",
						outline: "none",
						width: "100%",
						boxSizing: "border-box",
					}}
				/>
			))}
			{options.length < 4 && (
				<button
					type="button"
					onClick={addOption}
					data-testid="poll-add-option"
					style={{
						background: "transparent",
						border: "1px dashed var(--border-soft)",
						borderRadius: 8,
						color: "var(--fg-3)",
						cursor: "pointer",
						fontSize: 12,
						padding: "5px 10px",
						textAlign: "left",
					}}
				>
					+ Add option
				</button>
			)}
			<div style={{ display: "flex", gap: 8, justifyContent: "flex-end", marginTop: 2 }}>
				<button
					type="button"
					onClick={onClose}
					data-testid="poll-cancel"
					style={{
						background: "transparent",
						border: "1px solid var(--border-soft)",
						borderRadius: 8,
						color: "var(--fg-3)",
						cursor: "pointer",
						fontSize: 12,
						padding: "5px 12px",
					}}
				>
					Cancel
				</button>
				<button
					type="button"
					onClick={handleSubmit}
					data-testid="poll-create"
					style={{
						background: "linear-gradient(180deg,#FF9E52,#FF7A2B)",
						border: "none",
						borderRadius: 8,
						color: "#2A0A00",
						cursor: "pointer",
						fontSize: 12,
						fontWeight: 600,
						padding: "5px 12px",
					}}
				>
					Create
				</button>
			</div>
		</div>
	);
}

// ── SchedulePickerPopup ───────────────────────────────────────────────────────

function SchedulePickerPopup({
	onSchedule,
	onClose,
}: {
	onSchedule: (at: number) => void;
	onClose: () => void;
}) {
	const minDt = (() => {
		const d = new Date(Date.now() + 60_000);
		const pad = (n: number) => String(n).padStart(2, "0");
		return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
	})();
	const [value, setValue] = useState(minDt);

	const handleSubmit = () => {
		const ms = new Date(value).getTime();
		if (!Number.isFinite(ms) || ms <= Date.now()) return;
		onSchedule(ms);
	};

	return (
		<div
			data-testid="schedule-picker"
			style={{
				position: "absolute",
				bottom: "calc(100% + 8px)",
				right: 0,
				background: "var(--bg-surface)",
				border: "1px solid var(--border-soft)",
				borderRadius: 12,
				padding: "14px 16px",
				boxShadow: "0 8px 32px rgba(0,0,0,0.45)",
				zIndex: 100,
				minWidth: 240,
				display: "flex",
				flexDirection: "column",
				gap: 10,
			}}
		>
			<div style={{ fontSize: 12, fontWeight: 600, color: "var(--fg-2)", letterSpacing: "0.04em" }}>
				Send later
			</div>
			<input
				type="datetime-local"
				value={value}
				min={minDt}
				onChange={(e) => setValue(e.target.value)}
				data-testid="schedule-datetime-input"
				style={{
					background: "var(--bg-void)",
					border: "1px solid var(--border-soft)",
					borderRadius: 8,
					color: "var(--fg-1)",
					fontFamily: "var(--font-mono)",
					fontSize: 12,
					padding: "6px 8px",
					outline: "none",
					width: "100%",
					boxSizing: "border-box",
				}}
			/>
			<div style={{ display: "flex", gap: 8, justifyContent: "flex-end" }}>
				<button
					type="button"
					onClick={onClose}
					data-testid="schedule-cancel"
					style={{
						background: "transparent",
						border: "1px solid var(--border-soft)",
						borderRadius: 8,
						color: "var(--fg-3)",
						cursor: "pointer",
						fontSize: 12,
						padding: "5px 12px",
					}}
				>
					Cancel
				</button>
				<button
					type="button"
					onClick={handleSubmit}
					data-testid="schedule-confirm"
					style={{
						background: "linear-gradient(180deg,#FF9E52,#FF7A2B)",
						border: "none",
						borderRadius: 8,
						color: "#2A0A00",
						cursor: "pointer",
						fontSize: 12,
						fontWeight: 600,
						padding: "5px 12px",
					}}
				>
					Schedule
				</button>
			</div>
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
	replyTo,
	onCancelReply,
	editingMessage,
	onEdit,
	onCancelEdit,
	onEditLast,
	chatId,
	initialDraft,
	onDraftChange,
	onScheduleSend,
	onCreatePoll,
	isGroupChat,
	slowModeCooldownSec = 0,
	slowModeDelay: composerSlowModeDelay = 0,
}: {
	onSend: (text: string) => void;
	partner: string;
	ttl: TtlOption;
	onToggleTtl: () => void;
	/** Triggered when the user clicks the Photo button. */
	onPhoto?: () => void;
	/** Called on each keystroke so ChatLayout can throttle-send typing_indicator messages. */
	onTyping?: () => void;
	/** When set, a reply preview bar is shown above the input. */
	replyTo?: { text: string; from: "me" | "them" } | null;
	/** Called when the user dismisses the reply preview. */
	onCancelReply?: () => void;
	/** When set, the composer is in edit mode — pre-filled with this message's text. */
	editingMessage?: ChatMessage | null;
	/** Called with the new text when the user confirms an edit. */
	onEdit?: (newText: string) => void;
	/** Called when the user cancels an edit. */
	onCancelEdit?: () => void;
	/** Called when the user presses ↑ in an empty composer to edit the last own message. */
	onEditLast?: () => void;
	chatId: string;
	initialDraft: string;
	onDraftChange: (chatId: string, draft: string) => void;
	/** Called with the message text and Unix-ms target time when user schedules a send. */
	onScheduleSend?: (text: string, at: number) => void;
	/** Called with poll question + options when user creates a poll (group chats only). */
	onCreatePoll?: (question: string, options: string[]) => void;
	/** True when composing in a group chat — enables poll button. */
	isGroupChat?: boolean;
	/** Seconds remaining in slow-mode cooldown (0 = no cooldown active). */
	slowModeCooldownSec?: number;
	/** Active slow-mode delay for this chat (seconds). 0 = disabled. */
	slowModeDelay?: SlowModeDelay;
}) {
	const [text, setText] = useState(initialDraft);
	const [emojiPickerOpen, setEmojiPickerOpen] = useState(false);
	const [schedulePickerOpen, setSchedulePickerOpen] = useState(false);
	const [pollCreatorOpen, setPollCreatorOpen] = useState(false);
	const pollCreatorRef = useRef<HTMLDivElement>(null);
	const prevChatIdRef = useRef(chatId);
	const textareaRef = useRef<HTMLTextAreaElement>(null);
	const emojiPickerRef = useRef<HTMLDivElement>(null);
	const schedulePickerRef = useRef<HTMLDivElement>(null);

	// Restore saved draft when the active chat changes.
	// biome-ignore lint/correctness/useExhaustiveDependencies: chatId is the trigger; initialDraft is the new chat's draft
	useEffect(() => {
		if (prevChatIdRef.current !== chatId) {
			prevChatIdRef.current = chatId;
			if (!editingMessage) {
				setText(initialDraft);
			}
		}
	}, [chatId]);

	// Pre-fill textarea when entering edit mode; restore draft when exiting.
	// biome-ignore lint/correctness/useExhaustiveDependencies: editingMessage.id is the semantic trigger; initialDraft read at fire time
	useEffect(() => {
		if (editingMessage) {
			setText(editingMessage.text);
		} else {
			// Restore the saved draft when exiting edit mode (cancelled or completed).
			setText(initialDraft);
		}
	}, [editingMessage?.id]);

	// Close emoji picker on click outside.
	useEffect(() => {
		if (!emojiPickerOpen) return;
		const handler = (ev: MouseEvent) => {
			if (emojiPickerRef.current && !emojiPickerRef.current.contains(ev.target as Node)) {
				setEmojiPickerOpen(false);
			}
		};
		document.addEventListener("mousedown", handler);
		return () => document.removeEventListener("mousedown", handler);
	}, [emojiPickerOpen]);

	// Close schedule picker on click outside.
	useEffect(() => {
		if (!schedulePickerOpen) return;
		const handler = (ev: MouseEvent) => {
			if (schedulePickerRef.current && !schedulePickerRef.current.contains(ev.target as Node)) {
				setSchedulePickerOpen(false);
			}
		};
		document.addEventListener("mousedown", handler);
		return () => document.removeEventListener("mousedown", handler);
	}, [schedulePickerOpen]);

	// Close poll creator on click outside.
	useEffect(() => {
		if (!pollCreatorOpen) return;
		const handler = (ev: MouseEvent) => {
			if (pollCreatorRef.current && !pollCreatorRef.current.contains(ev.target as Node)) {
				setPollCreatorOpen(false);
			}
		};
		document.addEventListener("mousedown", handler);
		return () => document.removeEventListener("mousedown", handler);
	}, [pollCreatorOpen]);

	const handleInsertEmoji = useCallback(
		(emoji: string) => {
			const el = textareaRef.current;
			const start = el?.selectionStart ?? text.length;
			const end = el?.selectionEnd ?? text.length;
			const next = text.slice(0, start) + emoji + text.slice(end);
			setText(next);
			onDraftChange(chatId, next);
			setEmojiPickerOpen(false);
			requestAnimationFrame(() => {
				el?.focus();
				el?.setSelectionRange(start + emoji.length, start + emoji.length);
			});
		},
		[text, chatId, onDraftChange],
	);

	const send = () => {
		if (slowModeCooldownSec > 0) return;
		const trimmed = text.trim();
		if (!trimmed) return;
		if (editingMessage && onEdit) {
			onEdit(trimmed);
		} else {
			onSend(trimmed);
		}
		setText("");
		onDraftChange(chatId, "");
	};
	const handleKeyDown = (e: KeyboardEvent<HTMLTextAreaElement>) => {
		if (e.key === "Enter" && !e.shiftKey) {
			e.preventDefault();
			send();
		} else if (e.key === "ArrowUp" && text === "" && !editingMessage) {
			e.preventDefault();
			onEditLast?.();
		} else if (e.key === "Escape") {
			if (editingMessage) {
				e.preventDefault();
				onCancelEdit?.();
			} else if (replyTo) {
				e.preventDefault();
				onCancelReply?.();
			}
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
			{/* Slow-mode banner — shown when slow mode is active for this group */}
			{composerSlowModeDelay > 0 && (
				<div
					data-testid="slow-mode-banner"
					style={{
						display: "flex",
						alignItems: "center",
						gap: 6,
						padding: "4px 14px",
						marginBottom: 4,
						background: "var(--bg-surface)",
						border: "1px solid var(--border-soft)",
						borderRadius: "8px 8px 0 0",
						borderBottom: "none",
						fontSize: 12,
						color: "var(--fg-3)",
					}}
				>
					<Icon name="clock" size={12} color="var(--fg-3)" />
					<span>Slow mode: {formatSlowMode(composerSlowModeDelay)} between messages</span>
				</div>
			)}
			{/* Edit mode bar — shown when editing a sent message */}
			{editingMessage && (
				<div
					data-testid="edit-preview"
					style={{
						display: "flex",
						alignItems: "center",
						gap: 8,
						padding: "6px 12px 6px 14px",
						marginBottom: 4,
						background: "var(--bg-surface)",
						border: "1px solid var(--border-soft)",
						borderRadius: "10px 10px 0 0",
						borderBottom: "none",
						fontSize: 12,
						color: "var(--fg-3)",
					}}
				>
					<Icon name="pencil" size={13} color="var(--fg-3)" />
					<span
						style={{
							flex: 1,
							overflow: "hidden",
							textOverflow: "ellipsis",
							whiteSpace: "nowrap",
						}}
					>
						Editing: <span style={{ color: "var(--fg-2)" }}>{editingMessage.text}</span>
					</span>
					<button
						type="button"
						onClick={onCancelEdit}
						aria-label="Cancel edit"
						data-testid="cancel-edit"
						style={{
							background: "none",
							border: "none",
							color: "var(--fg-3)",
							cursor: "pointer",
							padding: 2,
							display: "flex",
							alignItems: "center",
						}}
					>
						<Icon name="x" size={14} />
					</button>
				</div>
			)}
			{/* Reply preview bar — shown when replying to a message */}
			{replyTo && (
				<div
					data-testid="reply-preview"
					style={{
						display: "flex",
						alignItems: "center",
						gap: 8,
						padding: "6px 12px 6px 14px",
						marginBottom: 4,
						background: "var(--bg-surface)",
						border: "1px solid var(--border-soft)",
						borderRadius: "10px 10px 0 0",
						borderBottom: "none",
						fontSize: 12,
						color: "var(--fg-3)",
					}}
				>
					<Icon name="reply" size={13} color="var(--fg-3)" />
					<span
						style={{
							flex: 1,
							overflow: "hidden",
							textOverflow: "ellipsis",
							whiteSpace: "nowrap",
						}}
					>
						{replyTo.from === "me" ? "You" : partner.split(" ")[0]}:{" "}
						<span style={{ color: "var(--fg-2)" }}>{replyTo.text}</span>
					</span>
					<button
						type="button"
						onClick={onCancelReply}
						aria-label="Cancel reply"
						data-testid="cancel-reply"
						style={{
							background: "none",
							border: "none",
							color: "var(--fg-3)",
							cursor: "pointer",
							padding: 2,
							display: "flex",
							alignItems: "center",
						}}
					>
						<Icon name="x" size={14} />
					</button>
				</div>
			)}
			<div
				style={{
					background: "var(--bg-surface)",
					border: "1px solid var(--border-soft)",
					borderRadius: replyTo || editingMessage ? "0 0 16px 16px" : 16,
					display: "flex",
					alignItems: "flex-end",
					gap: 4,
					padding: "6px 6px 6px 14px",
				}}
			>
				<IconBtn icon="attach" label="Attach" size={32} />
				<IconBtn icon="image" label="Photo" size={32} onClick={onPhoto} />
				{isGroupChat && (
					<div ref={pollCreatorRef} style={{ position: "relative" }}>
						<IconBtn
							icon="bar-chart"
							label="Create poll"
							size={32}
							onClick={() => setPollCreatorOpen((o) => !o)}
						/>
						{pollCreatorOpen && (
							<PollCreatorPopup
								onCreate={(q, opts) => {
									onCreatePoll?.(q, opts);
									setPollCreatorOpen(false);
								}}
								onClose={() => setPollCreatorOpen(false)}
							/>
						)}
					</div>
				)}
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
					ref={textareaRef}
					data-testid="composer-textarea"
					value={text}
					onChange={(e) => {
						const next = e.target.value;
						setText(next);
						onTyping?.();
						onDraftChange(chatId, next);
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
				<div ref={emojiPickerRef} style={{ position: "relative" }}>
					<IconBtn
						icon="smile"
						label="Emoji"
						size={32}
						onClick={() => setEmojiPickerOpen((o) => !o)}
					/>
					{emojiPickerOpen && <EmojiPickerPopup onSelect={handleInsertEmoji} />}
				</div>
				{slowModeCooldownSec > 0 ? (
					<div
						data-testid="slow-mode-countdown"
						style={{
							display: "flex",
							alignItems: "center",
							justifyContent: "center",
							minWidth: 52,
							height: 36,
							borderRadius: 18,
							background: "var(--bg-elevated)",
							border: "1px solid var(--border-soft)",
							fontSize: 12,
							fontWeight: 600,
							color: "var(--fg-3)",
							letterSpacing: "0.02em",
							padding: "0 10px",
						}}
					>
						{slowModeCooldownSec}s
					</div>
				) : text.trim() ? (
					<div style={{ display: "flex", alignItems: "center", gap: 4 }}>
						{/* Send later button — only visible when text is present and onScheduleSend is wired */}
						{onScheduleSend && (
							<div ref={schedulePickerRef} style={{ position: "relative" }}>
								<button
									type="button"
									onClick={() => setSchedulePickerOpen((o) => !o)}
									aria-label="Send later"
									data-testid="send-later-btn"
									style={{
										width: 32,
										height: 32,
										borderRadius: "50%",
										border: "1px solid var(--border-soft)",
										background: schedulePickerOpen ? "var(--bg-surface)" : "transparent",
										color: "var(--fg-3)",
										display: "flex",
										alignItems: "center",
										justifyContent: "center",
										cursor: "pointer",
										transition: "all 120ms",
									}}
								>
									<Icon name="timer" size={14} />
								</button>
								{schedulePickerOpen && (
									<SchedulePickerPopup
										onSchedule={(at) => {
											const trimmed = text.trim();
											if (!trimmed) return;
											onScheduleSend(trimmed, at);
											setText("");
											onDraftChange(chatId, "");
											setSchedulePickerOpen(false);
										}}
										onClose={() => setSchedulePickerOpen(false)}
									/>
								)}
							</div>
						)}
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
					</div>
				) : (
					<IconBtn icon="mic" label="Voice" size={36} />
				)}
			</div>
		</div>
	);
}

// ── Quick Switcher ────────────────────────────────────────────────────────────

function QuickSwitcher({
	chats,
	query,
	activeIdx,
	inputRef,
	onQueryChange,
	onActiveChange,
	onSelect,
	onClose,
}: {
	chats: Chat[];
	query: string;
	activeIdx: number;
	inputRef: RefObject<HTMLInputElement | null>;
	onQueryChange: (q: string) => void;
	onActiveChange: (idx: number) => void;
	onSelect: (id: string) => void;
	onClose: () => void;
}) {
	const q = query.toLowerCase();
	const filtered = chats.filter(
		(c) =>
			!q ||
			(c.nickname ?? c.name).toLowerCase().includes(q) ||
			c.name.toLowerCase().includes(q) ||
			c.handle.toLowerCase().includes(q),
	);
	const clampedActive = Math.min(activeIdx, Math.max(0, filtered.length - 1));

	useEffect(() => {
		inputRef.current?.focus();
	}, [inputRef]);

	function handleKeyDown(e: React.KeyboardEvent) {
		if (e.key === "Escape") {
			onClose();
		} else if (e.key === "ArrowDown") {
			e.preventDefault();
			onActiveChange(Math.min(clampedActive + 1, filtered.length - 1));
		} else if (e.key === "ArrowUp") {
			e.preventDefault();
			onActiveChange(Math.max(clampedActive - 1, 0));
		} else if (e.key === "Enter") {
			const target = filtered[clampedActive];
			if (target) onSelect(target.id);
		}
	}

	return (
		<div
			data-testid="quick-switcher-backdrop"
			style={{
				position: "fixed",
				inset: 0,
				background: "rgba(4,4,8,0.72)",
				display: "flex",
				alignItems: "flex-start",
				justifyContent: "center",
				paddingTop: "15vh",
				zIndex: 120,
			}}
			onClick={onClose}
			onKeyDown={(e) => {
				if (e.key === "Escape") onClose();
			}}
		>
			<div
				data-testid="quick-switcher"
				style={{
					background: "var(--bg-elevated)",
					border: "1px solid var(--border-faint)",
					borderRadius: 14,
					width: 400,
					maxHeight: 360,
					display: "flex",
					flexDirection: "column",
					boxShadow: "0 12px 48px rgba(0,0,0,0.6)",
					overflow: "hidden",
				}}
				onClick={(e) => e.stopPropagation()}
				onKeyDown={handleKeyDown}
			>
				<div
					style={{
						display: "flex",
						alignItems: "center",
						gap: 10,
						padding: "10px 14px",
						borderBottom: "1px solid var(--border-faint)",
					}}
				>
					<Icon name="search" size={14} color="var(--fg-3)" />
					<input
						ref={inputRef}
						data-testid="quick-switcher-input"
						type="text"
						placeholder="Jump to conversation…"
						value={query}
						onChange={(e) => onQueryChange(e.target.value)}
						style={{
							flex: 1,
							background: "none",
							border: "none",
							outline: "none",
							color: "var(--fg-1)",
							fontSize: 14,
							fontFamily: "var(--font-sans)",
						}}
					/>
					<span
						style={{
							fontSize: 11,
							color: "var(--fg-4)",
							fontFamily: "var(--font-mono)",
							padding: "2px 5px",
							border: "1px solid var(--border-faint)",
							borderRadius: 4,
						}}
					>
						Esc
					</span>
				</div>
				<div style={{ overflowY: "auto" }}>
					{filtered.length === 0 ? (
						<div
							style={{
								padding: "20px",
								textAlign: "center",
								fontSize: 13,
								color: "var(--fg-4)",
							}}
							data-testid="quick-switcher-empty"
						>
							No conversations found
						</div>
					) : (
						filtered.map((c, i) => (
							<button
								key={c.id}
								type="button"
								data-testid={`quick-switcher-item-${c.id}`}
								aria-selected={i === clampedActive}
								onClick={() => onSelect(c.id)}
								style={{
									display: "flex",
									alignItems: "center",
									gap: 10,
									width: "100%",
									padding: "9px 14px",
									background: i === clampedActive ? "var(--bg-surface)" : "none",
									border: "none",
									cursor: "pointer",
									textAlign: "left",
									color: "var(--fg-1)",
								}}
							>
								<div
									style={{
										width: 32,
										height: 32,
										borderRadius: "50%",
										background: "var(--bg-surface)",
										display: "flex",
										alignItems: "center",
										justifyContent: "center",
										fontSize: 12,
										fontWeight: 600,
										color: "var(--fg-2)",
										flexShrink: 0,
									}}
								>
									{(c.nickname ?? c.name).charAt(0).toUpperCase()}
								</div>
								<div style={{ minWidth: 0 }}>
									<div
										style={{
											fontWeight: 500,
											fontSize: 13,
											color: "var(--fg-1)",
											overflow: "hidden",
											textOverflow: "ellipsis",
											whiteSpace: "nowrap",
										}}
									>
										{c.nickname ?? c.name}
									</div>
									<div
										style={{
											fontSize: 11,
											color: "var(--fg-3)",
											overflow: "hidden",
											textOverflow: "ellipsis",
											whiteSpace: "nowrap",
										}}
									>
										{c.nickname ? c.name : `@${c.handle}`}
									</div>
								</div>
							</button>
						))
					)}
				</div>
				{filtered.length > 0 && (
					<div
						style={{
							borderTop: "1px solid var(--border-faint)",
							padding: "6px 14px",
							display: "flex",
							gap: 12,
							fontSize: 11,
							color: "var(--fg-4)",
						}}
					>
						<span>↑↓ navigate</span>
						<span>↵ open</span>
					</div>
				)}
			</div>
		</div>
	);
}

// ── Lightbox ──────────────────────────────────────────────────────────────────

function Lightbox({
	mediaMsgs,
	idx,
	onClose,
	onPrev,
	onNext,
}: {
	mediaMsgs: ChatMessage[];
	idx: number;
	onClose: () => void;
	onPrev: () => void;
	onNext: () => void;
}) {
	const current = mediaMsgs[idx];

	useEffect(() => {
		function onKey(e: globalThis.KeyboardEvent) {
			if (e.key === "Escape") onClose();
			else if (e.key === "ArrowLeft") onPrev();
			else if (e.key === "ArrowRight") onNext();
		}
		window.addEventListener("keydown", onKey);
		return () => window.removeEventListener("keydown", onKey);
	}, [onClose, onPrev, onNext]);

	if (!current?.media) return null;
	const hasPrev = idx > 0;
	const hasNext = idx < mediaMsgs.length - 1;

	return (
		<div
			data-testid="lightbox"
			aria-label="Image lightbox"
			onClick={onClose}
			onKeyDown={(e) => {
				if (e.key === "Escape") onClose();
				else if (e.key === "ArrowLeft") onPrev();
				else if (e.key === "ArrowRight") onNext();
			}}
			style={{
				position: "fixed",
				inset: 0,
				background: "rgba(4,4,8,0.94)",
				zIndex: 60,
				display: "flex",
				alignItems: "center",
				justifyContent: "center",
			}}
		>
			<button
				type="button"
				aria-label="Close lightbox"
				data-testid="lightbox-close"
				onClick={(e) => {
					e.stopPropagation();
					onClose();
				}}
				style={{
					position: "absolute",
					top: 18,
					right: 18,
					width: 36,
					height: 36,
					borderRadius: "50%",
					background: "rgba(255,255,255,0.1)",
					border: "1px solid rgba(255,255,255,0.12)",
					color: "var(--fg-1)",
					cursor: "pointer",
					display: "flex",
					alignItems: "center",
					justifyContent: "center",
				}}
			>
				<Icon name="x" size={16} />
			</button>

			{mediaMsgs.length > 1 && (
				<div
					data-testid="lightbox-counter"
					style={{
						position: "absolute",
						top: 24,
						left: "50%",
						transform: "translateX(-50%)",
						fontSize: 12,
						fontFamily: "var(--font-mono)",
						color: "var(--fg-3)",
						pointerEvents: "none",
					}}
				>
					{idx + 1} / {mediaMsgs.length}
				</div>
			)}

			{hasPrev && (
				<button
					type="button"
					aria-label="Previous image"
					data-testid="lightbox-prev"
					onClick={(e) => {
						e.stopPropagation();
						onPrev();
					}}
					style={{
						position: "absolute",
						left: 18,
						top: "50%",
						transform: "translateY(-50%)",
						width: 40,
						height: 40,
						borderRadius: "50%",
						background: "rgba(255,255,255,0.1)",
						border: "1px solid rgba(255,255,255,0.12)",
						color: "var(--fg-1)",
						cursor: "pointer",
						display: "flex",
						alignItems: "center",
						justifyContent: "center",
					}}
				>
					<Icon name="arrow-left" size={18} />
				</button>
			)}

			{hasNext && (
				<button
					type="button"
					aria-label="Next image"
					data-testid="lightbox-next"
					onClick={(e) => {
						e.stopPropagation();
						onNext();
					}}
					style={{
						position: "absolute",
						right: 18,
						top: "50%",
						transform: "translateY(-50%)",
						width: 40,
						height: 40,
						borderRadius: "50%",
						background: "rgba(255,255,255,0.1)",
						border: "1px solid rgba(255,255,255,0.12)",
						color: "var(--fg-1)",
						cursor: "pointer",
						display: "flex",
						alignItems: "center",
						justifyContent: "center",
					}}
				>
					<Icon name="arrow-right" size={18} />
				</button>
			)}

			<div
				data-testid="lightbox-image-container"
				onClick={(e) => e.stopPropagation()}
				onKeyDown={(e) => e.stopPropagation()}
				style={{ maxWidth: "90vw", maxHeight: "85vh", display: "flex", alignItems: "center" }}
			>
				<MediaImage
					media={current.media}
					imgStyle={{ maxWidth: "90vw", maxHeight: "85vh", borderRadius: 12 }}
				/>
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

function InfoRow({
	label,
	trailing,
	onClick,
}: {
	label: string;
	trailing: string;
	onClick?: () => void;
}) {
	if (onClick) {
		return (
			<button
				type="button"
				onClick={onClick}
				style={{
					display: "flex",
					justifyContent: "space-between",
					padding: "10px 18px",
					fontSize: 13,
					width: "100%",
					background: "transparent",
					border: "none",
					cursor: "pointer",
					color: "inherit",
					fontFamily: "inherit",
				}}
			>
				<span style={{ color: "var(--fg-1)" }}>{label}</span>
				<span style={{ color: "var(--fg-3)" }}>{trailing}</span>
			</button>
		);
	}
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
	muted,
	onToggleMute,
	sound,
	onToggleSound,
	vibrate,
	onToggleVibrate,
	archived,
	onToggleArchive,
	pinnedTop,
	onTogglePinTop,
	myHandle,
	onUpdateDescription,
	onUpdateNickname,
	onClearMessages,
	onExportChat,
	mediaMessages,
	onOpenLightbox,
	onOpenDm,
	slowModeDelay: infoPanelSlowMode = 0,
	onSetSlowMode,
	isAdmin = false,
}: {
	chat: Chat;
	onClose: () => void;
	disappearingTtl: TtlOption;
	muted: boolean;
	onToggleMute: () => void;
	sound: boolean;
	onToggleSound: () => void;
	vibrate: boolean;
	onToggleVibrate: () => void;
	archived: boolean;
	onToggleArchive: () => void;
	pinnedTop: boolean;
	onTogglePinTop: () => void;
	myHandle?: string;
	onUpdateDescription?: (desc: string) => void;
	onUpdateNickname?: (nickname: string) => void;
	onClearMessages?: () => void;
	onExportChat?: (format: "json" | "text") => void;
	mediaMessages?: ChatMessage[];
	onOpenLightbox?: (msg: ChatMessage) => void;
	onOpenDm?: (handle: string) => void;
	slowModeDelay?: SlowModeDelay;
	onSetSlowMode?: (d: SlowModeDelay) => void;
	isAdmin?: boolean;
}) {
	const [descEditing, setDescEditing] = useState(false);
	const [contactCard, setContactCard] = useState<ChatMember | null>(null);
	const [descDraft, setDescDraft] = useState("");
	const [nicknameEditing, setNicknameEditing] = useState(false);
	const [nicknameDraft, setNicknameDraft] = useState("");
	const [clearConfirm, setClearConfirm] = useState(false);
	const [exportConfirm, setExportConfirm] = useState(false);
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
		if (!worker || !chat.mlsGroupId || !chat.mlsIdentityId || chat.isGroup) {
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
	}, [cryptoWorker, chat.mlsGroupId, chat.mlsIdentityId, chat.isGroup]);

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
				position: "relative",
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
				<Avatar name={chat.nickname ?? chat.name} size={80} />
				<div
					data-testid="info-panel-display-name"
					style={{
						fontSize: 18,
						fontWeight: 500,
						color: "var(--fg-1)",
						marginTop: 14,
					}}
				>
					{chat.nickname ?? chat.name}
				</div>
				<div style={{ fontSize: 13, color: "var(--fg-3)", marginTop: 4 }}>
					{chat.nickname ? (
						<>
							<span data-testid="info-panel-real-name">{chat.name}</span>
							{" · "}@{chat.handle}
						</>
					) : (
						<>@{chat.handle}</>
					)}
				</div>
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

			{!chat.isGroup && onUpdateNickname && (
				/* Nickname — DM only, local-only, never sent to server */
				<InfoSection title="Nickname">
					<div style={{ padding: "0 18px 12px" }}>
						{nicknameEditing ? (
							<div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
								<input
									data-testid="nickname-input"
									type="text"
									maxLength={50}
									value={nicknameDraft}
									onChange={(e) => setNicknameDraft(e.target.value)}
									onKeyDown={(e) => {
										if (e.key === "Enter") {
											e.preventDefault();
											onUpdateNickname(nicknameDraft.trim());
											setNicknameEditing(false);
										} else if (e.key === "Escape") {
											setNicknameEditing(false);
										}
									}}
									placeholder={`Nickname for ${chat.name}`}
									style={{
										background: "var(--bg-void)",
										border: "1px solid var(--border-soft)",
										borderRadius: 8,
										padding: "7px 10px",
										color: "var(--fg-1)",
										fontSize: 13,
										fontFamily: "var(--font-sans)",
										outline: "none",
										width: "100%",
										boxSizing: "border-box",
									}}
									// biome-ignore lint/a11y/noAutofocus: edit mode opened by explicit user action
									autoFocus
								/>
								<div style={{ display: "flex", gap: 6, justifyContent: "flex-end" }}>
									<button
										type="button"
										data-testid="nickname-cancel"
										onClick={() => setNicknameEditing(false)}
										style={{
											fontSize: 12,
											padding: "4px 10px",
											borderRadius: 6,
											border: "1px solid var(--border-soft)",
											background: "none",
											color: "var(--fg-3)",
											cursor: "pointer",
											fontFamily: "var(--font-sans)",
										}}
									>
										Cancel
									</button>
									<button
										type="button"
										data-testid="nickname-save"
										onClick={() => {
											onUpdateNickname(nicknameDraft.trim());
											setNicknameEditing(false);
										}}
										style={{
											fontSize: 12,
											padding: "4px 10px",
											borderRadius: 6,
											border: "none",
											background: "#FF8A3D",
											color: "#2A1100",
											cursor: "pointer",
											fontFamily: "var(--font-sans)",
											fontWeight: 600,
										}}
									>
										Save
									</button>
								</div>
							</div>
						) : (
							<div
								style={{
									display: "flex",
									alignItems: "center",
									justifyContent: "space-between",
									gap: 8,
								}}
							>
								<span
									data-testid="nickname-display"
									style={{ fontSize: 13, color: chat.nickname ? "var(--fg-1)" : "var(--fg-4)" }}
								>
									{chat.nickname || "No nickname set"}
								</span>
								<button
									type="button"
									data-testid="nickname-edit-btn"
									onClick={() => {
										setNicknameDraft(chat.nickname ?? "");
										setNicknameEditing(true);
									}}
									style={{
										background: "none",
										border: "none",
										cursor: "pointer",
										padding: 4,
										color: "var(--fg-3)",
										lineHeight: 0,
									}}
									aria-label="Edit nickname"
								>
									<Icon name="edit-2" size={13} />
								</button>
							</div>
						)}
					</div>
				</InfoSection>
			)}

			{chat.isGroup && (
				/* Group description / topic */
				<InfoSection title="About">
					<div style={{ padding: "0 18px 12px" }}>
						{descEditing ? (
							<div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
								<textarea
									data-testid="group-description-input"
									rows={3}
									maxLength={200}
									value={descDraft}
									onChange={(e) => setDescDraft(e.target.value)}
									onKeyDown={(e) => {
										if (e.key === "Enter" && !e.shiftKey) {
											e.preventDefault();
											const trimmed = descDraft.trim();
											onUpdateDescription?.(trimmed);
											setDescEditing(false);
										} else if (e.key === "Escape") {
											setDescEditing(false);
										}
									}}
									style={{
										width: "100%",
										background: "var(--bg-elevated)",
										color: "var(--fg-1)",
										border: "1px solid var(--border-soft)",
										borderRadius: 6,
										padding: "6px 8px",
										fontSize: 13,
										fontFamily: "var(--font-sans)",
										resize: "none",
										outline: "none",
										boxSizing: "border-box",
									}}
								/>
								<div style={{ display: "flex", gap: 6 }}>
									<button
										type="button"
										data-testid="group-description-save"
										onClick={() => {
											const trimmed = descDraft.trim();
											onUpdateDescription?.(trimmed);
											setDescEditing(false);
										}}
										style={{
											padding: "4px 12px",
											fontSize: 12,
											fontFamily: "var(--font-sans)",
											fontWeight: 600,
											background: "#FF8A3D",
											color: "#040408",
											border: "none",
											borderRadius: 5,
											cursor: "pointer",
										}}
									>
										Save
									</button>
									<button
										type="button"
										data-testid="group-description-cancel"
										onClick={() => setDescEditing(false)}
										style={{
											padding: "4px 12px",
											fontSize: 12,
											fontFamily: "var(--font-sans)",
											fontWeight: 500,
											background: "var(--bg-elevated)",
											color: "var(--fg-3)",
											border: "1px solid var(--border-soft)",
											borderRadius: 5,
											cursor: "pointer",
										}}
									>
										Cancel
									</button>
								</div>
							</div>
						) : (
							<div style={{ display: "flex", alignItems: "flex-start", gap: 8 }}>
								<span
									data-testid="group-description-text"
									style={{
										flex: 1,
										fontSize: 13,
										color: chat.description ? "var(--fg-2)" : "var(--fg-4)",
										lineHeight: 1.5,
									}}
								>
									{chat.description || "No description set"}
								</span>
								{onUpdateDescription && (
									<button
										type="button"
										data-testid="group-description-edit-btn"
										aria-label="Edit group description"
										onClick={() => {
											setDescDraft(chat.description ?? "");
											setDescEditing(true);
										}}
										style={{
											flex: "none",
											background: "transparent",
											border: "none",
											color: "var(--fg-3)",
											cursor: "pointer",
											padding: 2,
											display: "flex",
											alignItems: "center",
										}}
									>
										<Icon name="edit-2" size={13} />
									</button>
								)}
							</div>
						)}
					</div>
				</InfoSection>
			)}
			{chat.isGroup ? (
				<>
					{/* Group member list */}
					<InfoSection title={`Members (${chat.members?.length ?? chat.memberCount ?? 0})`}>
						<div
							data-testid="group-member-list"
							style={{
								display: "flex",
								flexDirection: "column",
								gap: 0,
								padding: "0 18px 8px",
							}}
						>
							{(chat.members ?? []).map((member) => {
								const isMe =
									myHandle != null && member.handle.toLowerCase() === myHandle.toLowerCase();
								return (
									<button
										key={member.id}
										type="button"
										data-testid="group-member-row"
										onClick={() => setContactCard(member)}
										style={{
											display: "flex",
											alignItems: "center",
											gap: 10,
											padding: "7px 0",
											borderBottom: "1px solid var(--border-faint)",
											background: "none",
											border: "none",
											borderTop: "none",
											textAlign: "left",
											width: "100%",
											cursor: "pointer",
											borderRadius: 0,
										}}
									>
										<Avatar name={member.name} size={30} />
										<div style={{ flex: 1, minWidth: 0 }}>
											<div
												style={{
													fontSize: 13,
													fontWeight: 500,
													color: "var(--fg-1)",
													display: "flex",
													alignItems: "center",
													gap: 6,
												}}
											>
												{member.name}
												{isMe && (
													<span
														data-testid="member-you-badge"
														style={{
															fontSize: 10,
															fontWeight: 600,
															color: "#FF9E52",
															background: "rgba(255,158,82,0.12)",
															borderRadius: 4,
															padding: "1px 5px",
														}}
													>
														You
													</span>
												)}
												{member.role === "admin" && (
													<span
														data-testid="member-admin-badge"
														style={{
															fontSize: 10,
															fontWeight: 600,
															color: "#A8C8FF",
															background: "rgba(168,200,255,0.1)",
															borderRadius: 4,
															padding: "1px 5px",
														}}
													>
														Admin
													</span>
												)}
											</div>
											<div style={{ fontSize: 11, color: "var(--fg-4)", marginTop: 1 }}>
												@{member.handle}
											</div>
										</div>
									</button>
								);
							})}
						</div>
					</InfoSection>
					{/* Contact card overlay — appears when a member row is tapped */}
					{contactCard !== null && (
						<dialog
							open
							data-testid="contact-card-overlay"
							aria-label={`Contact card for ${contactCard.name}`}
							style={{
								position: "absolute",
								inset: 0,
								width: "100%",
								height: "100%",
								maxWidth: "100%",
								maxHeight: "100%",
								background: "rgba(4,4,8,0.72)",
								display: "flex",
								alignItems: "center",
								justifyContent: "center",
								zIndex: 20,
								border: "none",
								padding: 0,
								margin: 0,
							}}
							onClick={(e) => {
								if (e.target === e.currentTarget) setContactCard(null);
							}}
							onKeyDown={(e) => {
								if (e.key === "Escape") setContactCard(null);
							}}
						>
							<div
								data-testid="contact-card"
								style={{
									background: "var(--surface-2, #111118)",
									border: "1px solid var(--border-faint)",
									borderRadius: 16,
									padding: 24,
									width: 240,
									display: "flex",
									flexDirection: "column",
									alignItems: "center",
									gap: 10,
								}}
							>
								<Avatar name={contactCard.name} size={60} />
								<div
									style={{
										fontSize: 16,
										fontWeight: 600,
										color: "var(--fg-1)",
										display: "flex",
										alignItems: "center",
										gap: 6,
										flexWrap: "wrap",
										justifyContent: "center",
									}}
								>
									{contactCard.name}
									{myHandle != null &&
										contactCard.handle.toLowerCase() === myHandle.toLowerCase() && (
											<span
												data-testid="contact-card-you-badge"
												style={{
													fontSize: 10,
													fontWeight: 600,
													color: "#FF9E52",
													background: "rgba(255,158,82,0.12)",
													borderRadius: 4,
													padding: "1px 5px",
												}}
											>
												You
											</span>
										)}
									{contactCard.role === "admin" && (
										<span
											data-testid="contact-card-admin-badge"
											style={{
												fontSize: 10,
												fontWeight: 600,
												color: "#A8C8FF",
												background: "rgba(168,200,255,0.1)",
												borderRadius: 4,
												padding: "1px 5px",
											}}
										>
											Admin
										</span>
									)}
								</div>
								<div
									data-testid="contact-card-handle"
									style={{ fontSize: 13, color: "var(--fg-4)" }}
								>
									@{contactCard.handle}
								</div>
								<div
									style={{
										display: "flex",
										gap: 8,
										marginTop: 6,
										width: "100%",
									}}
								>
									{!(
										myHandle != null && contactCard.handle.toLowerCase() === myHandle.toLowerCase()
									) && (
										<button
											type="button"
											data-testid="contact-card-message-btn"
											onClick={() => {
												onOpenDm?.(contactCard.handle);
												setContactCard(null);
											}}
											style={{
												flex: 1,
												padding: "8px 0",
												background: "#FF8A3D",
												color: "#040408",
												border: "none",
												borderRadius: 8,
												fontWeight: 600,
												fontSize: 13,
												cursor: "pointer",
											}}
										>
											Message
										</button>
									)}
									<button
										type="button"
										data-testid="contact-card-close-btn"
										onClick={() => setContactCard(null)}
										style={{
											flex: 1,
											padding: "8px 0",
											background: "rgba(242,237,227,0.07)",
											color: "var(--fg-2)",
											border: "1px solid var(--border-faint)",
											borderRadius: 8,
											fontWeight: 500,
											fontSize: 13,
											cursor: "pointer",
										}}
									>
										Close
									</button>
								</div>
							</div>
						</dialog>
					)}
				</>
			) : (
				/* Safety Numbers — photon blue encryption verification card */
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
			)}

			<InfoSection title="Notifications">
				<InfoRow label="Mute" trailing={muted ? "On" : "Off"} onClick={onToggleMute} />
				<InfoRow label="Sound" trailing={sound ? "On" : "Off"} onClick={onToggleSound} />
				<InfoRow label="Vibrate" trailing={vibrate ? "On" : "Off"} onClick={onToggleVibrate} />
				<InfoRow label="Pin to top" trailing={pinnedTop ? "On" : "Off"} onClick={onTogglePinTop} />
			</InfoSection>
			<InfoSection title="Disappearing messages">
				<InfoRow label="Auto-delete after" trailing={formatTtl(disappearingTtl)} />
			</InfoSection>
			{chat.isGroup && (
				<InfoSection title="Slow mode">
					{isAdmin && onSetSlowMode ? (
						<div
							data-testid="slow-mode-admin-row"
							style={{
								display: "flex",
								alignItems: "center",
								justifyContent: "space-between",
								padding: "10px 18px",
							}}
						>
							<span style={{ fontSize: 14, color: "var(--fg-2)" }}>Send delay</span>
							<select
								data-testid="slow-mode-select"
								value={infoPanelSlowMode}
								onChange={(e) => onSetSlowMode(Number(e.target.value) as SlowModeDelay)}
								style={{
									background: "var(--bg-elevated)",
									color: "var(--fg-1)",
									border: "1px solid var(--border-soft)",
									borderRadius: 6,
									fontSize: 13,
									padding: "4px 8px",
									cursor: "pointer",
									fontFamily: "var(--font-sans)",
								}}
							>
								{SLOW_MODE_OPTIONS.map((opt) => (
									<option key={opt} value={opt}>
										{formatSlowMode(opt)}
									</option>
								))}
							</select>
						</div>
					) : (
						<div
							data-testid="slow-mode-member-row"
							style={{
								display: "flex",
								alignItems: "center",
								justifyContent: "space-between",
								padding: "10px 18px",
								fontSize: 13,
							}}
						>
							<span style={{ color: "var(--fg-1)" }}>Send delay</span>
							<span style={{ color: "var(--fg-3)" }}>{formatSlowMode(infoPanelSlowMode)}</span>
						</div>
					)}
				</InfoSection>
			)}
			<InfoSection title="Media">
				{!mediaMessages || mediaMessages.length === 0 ? (
					<div
						data-testid="media-gallery-empty"
						style={{
							padding: "12px 18px 16px",
							fontSize: 12,
							color: "var(--fg-4)",
							textAlign: "center",
						}}
					>
						No shared media
					</div>
				) : (
					<div
						data-testid="media-gallery"
						style={{
							display: "grid",
							gridTemplateColumns: "repeat(3, 1fr)",
							gap: 6,
							padding: "4px 18px 16px",
						}}
					>
						{mediaMessages.slice(0, 6).map((msg, i) => {
							const isOverflow = i === 5 && mediaMessages.length > 6;
							return (
								<button
									key={msg.id ?? i}
									type="button"
									data-testid="media-gallery-thumb"
									aria-label={isOverflow ? `View all ${mediaMessages.length} images` : "View image"}
									onClick={() => onOpenLightbox?.(msg)}
									style={{
										aspectRatio: "1/1",
										borderRadius: 8,
										overflow: "hidden",
										padding: 0,
										border: "none",
										cursor: "pointer",
										position: "relative",
										background: "rgba(168,200,255,0.06)",
									}}
								>
									{msg.media && (
										<MediaImage
											media={msg.media}
											imgStyle={{
												width: "100%",
												height: "100%",
												maxWidth: "100%",
												maxHeight: "100%",
												objectFit: "cover",
												borderRadius: 0,
											}}
										/>
									)}
									{isOverflow && (
										<div
											data-testid="media-gallery-overflow"
											style={{
												position: "absolute",
												inset: 0,
												background: "rgba(4,4,8,0.7)",
												display: "flex",
												alignItems: "center",
												justifyContent: "center",
												fontSize: 16,
												fontWeight: 700,
												color: "var(--fg-1)",
												borderRadius: 8,
											}}
										>
											+{mediaMessages.length - 5}
										</div>
									)}
								</button>
							);
						})}
					</div>
				)}
			</InfoSection>

			<div
				style={{
					padding: "8px 18px 24px",
					display: "flex",
					flexDirection: "column",
					gap: 4,
				}}
			>
				<button
					type="button"
					data-testid="archive-button"
					onClick={onToggleArchive}
					style={{
						background: "var(--bg-elevated)",
						border: "1px solid var(--border-soft)",
						borderRadius: 10,
						padding: "10px 0",
						cursor: "pointer",
						color: "var(--fg-2)",
						fontFamily: "var(--font-sans)",
						fontSize: 13,
						fontWeight: 500,
						width: "100%",
						textAlign: "center",
					}}
				>
					{archived ? "Unarchive Chat" : "Archive Chat"}
				</button>
				{exportConfirm ? (
					<div
						data-testid="export-chat-confirm"
						style={{
							background: "var(--bg-elevated)",
							border: "1px solid var(--border-soft)",
							borderRadius: 10,
							padding: "10px 14px",
							display: "flex",
							flexDirection: "column",
							gap: 6,
						}}
					>
						<span
							style={{
								color: "var(--fg-2)",
								fontFamily: "var(--font-sans)",
								fontSize: 13,
								textAlign: "center",
							}}
						>
							Save a local copy of this conversation.
						</span>
						<div style={{ display: "flex", gap: 6 }}>
							<button
								type="button"
								data-testid="export-cancel"
								onClick={() => setExportConfirm(false)}
								style={{
									flex: 1,
									background: "var(--bg-elevated)",
									border: "1px solid var(--border-soft)",
									borderRadius: 8,
									padding: "7px 0",
									cursor: "pointer",
									color: "var(--fg-2)",
									fontFamily: "var(--font-sans)",
									fontSize: 13,
									fontWeight: 500,
								}}
							>
								Cancel
							</button>
							<button
								type="button"
								data-testid="export-as-json"
								onClick={() => {
									onExportChat?.("json");
									setExportConfirm(false);
								}}
								style={{
									flex: 1,
									background: "var(--bg-elevated)",
									border: "1px solid var(--border-soft)",
									borderRadius: 8,
									padding: "7px 0",
									cursor: "pointer",
									color: "var(--fg-1)",
									fontFamily: "var(--font-sans)",
									fontSize: 13,
									fontWeight: 500,
								}}
							>
								JSON
							</button>
							<button
								type="button"
								data-testid="export-as-text"
								onClick={() => {
									onExportChat?.("text");
									setExportConfirm(false);
								}}
								style={{
									flex: 1,
									background: "var(--bg-elevated)",
									border: "1px solid var(--border-soft)",
									borderRadius: 8,
									padding: "7px 0",
									cursor: "pointer",
									color: "var(--fg-1)",
									fontFamily: "var(--font-sans)",
									fontSize: 13,
									fontWeight: 500,
								}}
							>
								Text
							</button>
						</div>
					</div>
				) : (
					<button
						type="button"
						data-testid="export-chat-button"
						onClick={() => setExportConfirm(true)}
						style={{
							background: "var(--bg-elevated)",
							border: "1px solid var(--border-soft)",
							borderRadius: 10,
							padding: "10px 0",
							cursor: "pointer",
							color: "var(--fg-2)",
							fontFamily: "var(--font-sans)",
							fontSize: 13,
							fontWeight: 500,
							width: "100%",
							textAlign: "center",
						}}
					>
						Export Chat
					</button>
				)}
				{clearConfirm ? (
					<div
						data-testid="clear-messages-confirm"
						style={{
							background: "var(--bg-elevated)",
							border: "1px solid var(--border-soft)",
							borderRadius: 10,
							padding: "10px 14px",
							display: "flex",
							flexDirection: "column",
							gap: 6,
						}}
					>
						<span
							style={{
								color: "var(--fg-2)",
								fontFamily: "var(--font-sans)",
								fontSize: 13,
								textAlign: "center",
							}}
						>
							Clear all messages? This cannot be undone.
						</span>
						<div style={{ display: "flex", gap: 6 }}>
							<button
								type="button"
								data-testid="clear-messages-cancel"
								onClick={() => setClearConfirm(false)}
								style={{
									flex: 1,
									background: "var(--bg-elevated)",
									border: "1px solid var(--border-soft)",
									borderRadius: 8,
									padding: "7px 0",
									cursor: "pointer",
									color: "var(--fg-2)",
									fontFamily: "var(--font-sans)",
									fontSize: 13,
									fontWeight: 500,
								}}
							>
								Cancel
							</button>
							<button
								type="button"
								data-testid="clear-messages-confirm-btn"
								onClick={() => {
									onClearMessages?.();
									setClearConfirm(false);
								}}
								style={{
									flex: 1,
									background: "rgba(205,48,63,0.14)",
									border: "1px solid rgba(205,48,63,0.32)",
									borderRadius: 8,
									padding: "7px 0",
									cursor: "pointer",
									color: "#E05261",
									fontFamily: "var(--font-sans)",
									fontSize: 13,
									fontWeight: 600,
								}}
							>
								Clear
							</button>
						</div>
					</div>
				) : (
					<button
						type="button"
						data-testid="clear-messages-button"
						onClick={() => setClearConfirm(true)}
						style={destructiveButton}
					>
						Clear messages
					</button>
				)}
				<button type="button" style={destructiveButton}>
					Block · Report
				</button>
			</div>
		</aside>
	);
}

// ── Call overlay ──────────────────────────────────────────────────────────────

type CallState = "idle" | "outgoing" | "active" | "incoming";
type CallType = "voice" | "video";

function formatCallDuration(s: number): string {
	const mins = Math.floor(s / 60);
	const secs = s % 60;
	return `${String(mins).padStart(2, "0")}:${String(secs).padStart(2, "0")}`;
}

interface CallOverlayProps {
	state: Exclude<CallState, "idle">;
	type: CallType;
	chatName: string;
	durationSec: number;
	muted: boolean;
	cameraOff: boolean;
	screensharing: boolean;
	onHangUp: () => void;
	onAccept: () => void;
	onDecline: () => void;
	onMuteToggle: () => void;
	onCameraToggle: () => void;
	onScreenshareToggle: () => void;
}

function CallOverlay({
	state,
	type,
	chatName,
	durationSec,
	muted,
	cameraOff,
	screensharing,
	onHangUp,
	onAccept,
	onDecline,
	onMuteToggle,
	onCameraToggle,
	onScreenshareToggle,
}: CallOverlayProps) {
	const callLabel = type === "video" ? "Video call" : "Voice call";

	const overlayStyle: CSSProperties = {
		position: "fixed",
		inset: 0,
		background: "rgba(4,4,8,0.88)",
		display: "flex",
		alignItems: "center",
		justifyContent: "center",
		zIndex: 200,
	};

	const cardStyle: CSSProperties = {
		background: "var(--bg-elevated)",
		border: "1px solid var(--border-soft)",
		borderRadius: 20,
		padding: "32px 28px 24px",
		width: 320,
		display: "flex",
		flexDirection: "column",
		alignItems: "center",
		gap: 0,
		boxShadow: "0 16px 64px rgba(0,0,0,0.6)",
	};

	const avatarStyle: CSSProperties = {
		width: 72,
		height: 72,
		borderRadius: "50%",
		background: "var(--bg-void)",
		display: "flex",
		alignItems: "center",
		justifyContent: "center",
		fontSize: 28,
		fontWeight: 700,
		color: state === "incoming" ? "#A8C8FF" : "#FF9E52",
		border: `2px solid ${state === "incoming" ? "#A8C8FF" : "#FF9E52"}`,
		marginBottom: 16,
	};

	const ctrlBtn = (active = false): CSSProperties => ({
		width: 52,
		height: 52,
		borderRadius: "50%",
		border: `1px solid ${active ? "#FF9E52" : "var(--border-soft)"}`,
		background: active ? "rgba(255,158,82,0.12)" : "var(--bg-void)",
		color: active ? "#FF9E52" : "var(--fg-2)",
		cursor: "pointer",
		display: "flex",
		alignItems: "center",
		justifyContent: "center",
	});

	const hangUpBtn: CSSProperties = {
		width: 56,
		height: 56,
		borderRadius: "50%",
		background: "#C0392B",
		border: "none",
		color: "#fff",
		cursor: "pointer",
		display: "flex",
		alignItems: "center",
		justifyContent: "center",
	};

	const acceptBtn: CSSProperties = {
		width: 56,
		height: 56,
		borderRadius: "50%",
		background: "#27AE60",
		border: "none",
		color: "#fff",
		cursor: "pointer",
		display: "flex",
		alignItems: "center",
		justifyContent: "center",
	};

	return (
		<div data-testid="call-overlay" style={overlayStyle}>
			<dialog
				open
				aria-label={callLabel}
				style={cardStyle}
				onClick={(e) => e.stopPropagation()}
				onKeyDown={(e) => e.stopPropagation()}
			>
				<div style={avatarStyle} aria-hidden="true">
					{chatName[0]}
				</div>
				<div
					style={{
						fontSize: 16,
						fontWeight: 600,
						color: "var(--fg-1)",
						marginBottom: 4,
					}}
					data-testid="call-peer-name"
				>
					{chatName}
				</div>

				{state === "outgoing" && (
					<div
						style={{ fontSize: 13, color: "var(--fg-3)", marginBottom: 28 }}
						data-testid="call-status-outgoing"
					>
						{callLabel} · Calling...
					</div>
				)}

				{state === "incoming" && (
					<div
						style={{ fontSize: 13, color: "var(--fg-3)", marginBottom: 28 }}
						data-testid="call-status-incoming"
					>
						Incoming {callLabel.toLowerCase()}
					</div>
				)}

				{state === "active" && (
					<div
						style={{
							fontSize: 13,
							color: "#4ADE80",
							fontVariantNumeric: "tabular-nums",
							marginBottom: 24,
						}}
						data-testid="call-duration"
					>
						{formatCallDuration(durationSec)}
					</div>
				)}

				{state === "active" && (
					<div style={{ display: "flex", gap: 16, alignItems: "center", marginTop: 4 }}>
						<button
							type="button"
							aria-label={muted ? "Unmute" : "Mute"}
							data-testid="call-btn-mute"
							style={ctrlBtn(muted)}
							onClick={onMuteToggle}
						>
							<Icon name={muted ? "mic-off" : "mic"} size={20} />
						</button>
						{type === "video" && (
							<button
								type="button"
								aria-label={cameraOff ? "Camera on" : "Camera off"}
								data-testid="call-btn-camera"
								style={ctrlBtn(cameraOff)}
								onClick={onCameraToggle}
							>
								<Icon name={cameraOff ? "video-off" : "video"} size={20} />
							</button>
						)}
						<button
							type="button"
							aria-label={screensharing ? "Stop sharing screen" : "Share screen"}
							data-testid="call-btn-screenshare"
							style={ctrlBtn(screensharing)}
							onClick={onScreenshareToggle}
						>
							<Icon name={screensharing ? "monitor-off" : "monitor"} size={20} />
						</button>
						<button
							type="button"
							aria-label="End call"
							data-testid="call-btn-end"
							style={hangUpBtn}
							onClick={onHangUp}
						>
							<Icon name="phone-off" size={22} />
						</button>
					</div>
				)}

				{state === "outgoing" && (
					<button
						type="button"
						aria-label="Cancel call"
						data-testid="call-btn-end"
						style={hangUpBtn}
						onClick={onHangUp}
					>
						<Icon name="phone-off" size={22} />
					</button>
				)}

				{state === "incoming" && (
					<div style={{ display: "flex", gap: 20, marginTop: 4 }}>
						<button
							type="button"
							aria-label="Decline call"
							data-testid="call-btn-decline"
							style={hangUpBtn}
							onClick={onDecline}
						>
							<Icon name="phone-off" size={22} />
						</button>
						<button
							type="button"
							aria-label="Accept call"
							data-testid="call-btn-accept"
							style={acceptBtn}
							onClick={onAccept}
						>
							<Icon name="phone" size={22} />
						</button>
					</div>
				)}
			</dialog>
		</div>
	);
}

// ── ChatLayout (root export) ──────────────────────────────────────────────────

export function ChatLayout() {
	const [chats, setChats] = useState<Chat[]>(SEED_CHATS);
	const [activeId, setActiveId] = useState("maya");
	const [search, setSearch] = useState("");
	const [infoOpen, setInfoOpen] = useState(false);
	const [inviteOpen, setInviteOpen] = useState(false);
	const [drafts, setDrafts] = useState<Record<string, string>>({});
	const handleDraftChange = useCallback((id: string, draft: string) => {
		setDrafts((prev) => {
			if (!draft) {
				const { [id]: _, ...rest } = prev;
				return rest;
			}
			return prev[id] === draft ? prev : { ...prev, [id]: draft };
		});
	}, []);
	const [createGroupOpen, setCreateGroupOpen] = useState(false);
	const [addMemberOpen, setAddMemberOpen] = useState(false);
	const [disappearingTtl, setDisappearingTtl] = useState<TtlOption>(undefined);
	const [msgSearch, setMsgSearch] = useState("");

	// ── In-chat message search bar (above composer) ───────────────────────────
	const [chatSearchOpen, setChatSearchOpen] = useState(false);
	const [chatSearchQuery, setChatSearchQuery] = useState("");
	const [chatSearchIndex, setChatSearchIndex] = useState(0);
	const chatSearchInputRef = useRef<HTMLInputElement>(null);

	const [replyingTo, setReplyingTo] = useState<ChatMessage | null>(null);
	const [editingMessage, setEditingMessage] = useState<ChatMessage | null>(null);
	const [forwardMsg, setForwardMsg] = useState<{ id: string; text: string } | null>(null);
	const [jumpToMessageId, setJumpToMessageId] = useState<string | null>(null);
	const [lightboxMsgIdx, setLightboxMsgIdx] = useState<number | null>(null);
	const handleJumpComplete = useCallback(() => setJumpToMessageId(null), []);

	// ── Custom user status ────────────────────────────────────────────────────
	const [customStatus, setCustomStatus] = useState<CustomStatus>(null);
	const [statusEditorOpen, setStatusEditorOpen] = useState(false);

	// ── Quick switcher (Cmd+K / Ctrl+K) ──────────────────────────────────────
	const [quickSwitcherOpen, setQuickSwitcherOpen] = useState(false);
	const [quickSwitcherQuery, setQuickSwitcherQuery] = useState("");
	const [quickSwitcherActive, setQuickSwitcherActive] = useState(0);
	const quickSwitcherInputRef = useRef<HTMLInputElement>(null);

	// ── Call state ────────────────────────────────────────────────────────────
	const [callState, setCallState] = useState<CallState>("idle");
	const [callType, setCallType] = useState<CallType>("voice");
	const [callDurationSec, setCallDurationSec] = useState(0);
	const [callMuted, setCallMuted] = useState(false);
	const [callCameraOff, setCallCameraOff] = useState(false);
	const [callScreensharing, setCallScreensharing] = useState(false);
	const [callChatId, setCallChatId] = useState<string | null>(null);

	const handleVoiceCall = useCallback(() => {
		setCallType("voice");
		setCallState("outgoing");
		setCallChatId(activeIdRef.current);
		setCallMuted(false);
		setCallCameraOff(false);
		setCallScreensharing(false);
		setCallDurationSec(0);
	}, []);

	const handleVideoCall = useCallback(() => {
		setCallType("video");
		setCallState("outgoing");
		setCallChatId(activeIdRef.current);
		setCallMuted(false);
		setCallCameraOff(false);
		setCallScreensharing(false);
		setCallDurationSec(0);
	}, []);

	const handleHangUp = useCallback(() => {
		setCallState("idle");
		setCallChatId(null);
		setCallDurationSec(0);
		setCallMuted(false);
		setCallCameraOff(false);
		setCallScreensharing(false);
	}, []);

	const handleScreenshareToggle = useCallback(() => {
		setCallScreensharing((prev) => !prev);
	}, []);

	const handleAcceptCall = useCallback(() => {
		setCallState("active");
		setCallDurationSec(0);
	}, []);

	const handleDeclineCall = useCallback(() => {
		setCallState("idle");
		setCallChatId(null);
		setCallDurationSec(0);
	}, []);

	// Simulate peer answering: outgoing → active after 2.5 s.
	useEffect(() => {
		if (callState !== "outgoing") return;
		const t = setTimeout(() => setCallState("active"), 2500);
		return () => clearTimeout(t);
	}, [callState]);

	// Duration timer — ticks every second while a call is active.
	useEffect(() => {
		if (callState !== "active") {
			setCallDurationSec(0);
			return;
		}
		const t = setInterval(() => setCallDurationSec((s) => s + 1), 1000);
		return () => clearInterval(t);
	}, [callState]);

	const callChat = chats.find((c) => c.id === callChatId) ?? null;

	// Stable ref so handleIncoming (useCallback) can read current activeId without
	// re-creating on every chat switch — avoids restarting the polling hook.
	const activeIdRef = useRef(activeId);
	useEffect(() => {
		activeIdRef.current = activeId;
	}, [activeId]);

	// Stable ref so handleIncoming can read per-chat vibrate/mute flags without
	// taking a dependency on chats (which would restart the polling hook on every message).
	const chatsRef = useRef(chats);
	useEffect(() => {
		chatsRef.current = chats;
	}, [chats]);

	// Tracks auto-clear timers for peer typing indicators, keyed by mlsGroupId.
	// Stored in a ref so setChats callbacks can mutate it without triggering re-renders.
	const typingTimersRef = useRef<Map<string, ReturnType<typeof setTimeout>>>(new Map());
	useEffect(() => {
		const timers = typingTimersRef.current;
		return () => {
			for (const handle of timers.values()) clearTimeout(handle);
		};
	}, []);

	// Tracks presence timeout timers, keyed by mlsGroupId.
	// If no "online" heartbeat arrives within 90 s, peer is marked offline.
	const presenceTimersRef = useRef<Map<string, ReturnType<typeof setTimeout>>>(new Map());
	useEffect(() => {
		const timers = presenceTimersRef.current;
		return () => {
			for (const handle of timers.values()) clearTimeout(handle);
		};
	}, []);

	// Throttle ref for outgoing typing indicator signals (leading-edge, 3 s window).
	const typingThrottleRef = useRef<ReturnType<typeof setTimeout> | null>(null);

	// Refs hold the latest send*Receipt and notification closures so handleIncoming
	// (stable useCallback) can call them without taking extra deps.
	const sendReadReceiptRef = useRef<
		(mlsGroupId: string, mlsIdentityId: string, ids: string[]) => void
	>(() => {});
	const sendDeliveryReceiptRef = useRef<(ids: string[]) => void>(() => {});
	const showTauriNotificationRef = useRef<() => void>(() => {});
	// mlsGroupId → envelope IDs awaiting read receipt (deferred until chat is visible + focused).
	const pendingReadReceipts = useRef<Map<string, string[]>>(new Map());

	// Reset in-conversation search when switching chats.
	// biome-ignore lint/correctness/useExhaustiveDependencies: activeId is the trigger; setMsgSearch is stable
	useEffect(() => {
		setMsgSearch("");
	}, [activeId]);

	// Close and clear the in-chat search bar when switching chats.
	// biome-ignore lint/correctness/useExhaustiveDependencies: activeId is the trigger; setters are stable
	useEffect(() => {
		setChatSearchOpen(false);
		setChatSearchQuery("");
		setChatSearchIndex(0);
	}, [activeId]);

	// Auto-focus the search input when the bar opens.
	useEffect(() => {
		if (chatSearchOpen) {
			chatSearchInputRef.current?.focus();
		}
	}, [chatSearchOpen]);

	// `active` and `chatSearchMatchIds` must be defined before the scroll useEffect
	// that depends on them — hoisted here to avoid the TDZ.
	const active = chats.find((c) => c.id === activeId);

	// Compute which message IDs match the in-chat search bar query.
	// Local-only — never sent to server, never logged (no-plaintext-logging invariant).
	const chatSearchMatchIds = useMemo<string[]>(() => {
		if (!chatSearchQuery || !active?.messages) return [];
		const q = chatSearchQuery.toLowerCase();
		return active.messages
			.filter((m) => !m.media && !m.deleted && m.text && m.text.toLowerCase().includes(q))
			.map((m) => m.id)
			.filter((id): id is string => id !== undefined);
	}, [active?.messages, chatSearchQuery]);

	// Scroll to the current match when chatSearchIndex changes.
	useEffect(() => {
		if (chatSearchMatchIds.length === 0) return;
		const currentId = chatSearchMatchIds[chatSearchIndex];
		if (!currentId) return;
		const el = document.querySelector(`[data-msg-id="${CSS.escape(currentId)}"]`);
		if (el) {
			el.scrollIntoView({ behavior: "smooth", block: "center" });
		}
	}, [chatSearchIndex, chatSearchMatchIds]);

	// Global Cmd+K / Ctrl+K opens the quick switcher.
	useEffect(() => {
		function onKey(e: globalThis.KeyboardEvent) {
			if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
				e.preventDefault();
				setQuickSwitcherOpen((v) => {
					if (!v) {
						setQuickSwitcherQuery("");
						setQuickSwitcherActive(0);
					}
					return !v;
				});
			}
		}
		window.addEventListener("keydown", onKey);
		return () => window.removeEventListener("keydown", onKey);
	}, []);

	// Global Ctrl+F / Cmd+F opens the in-chat search bar; Escape closes it.
	useEffect(() => {
		function onKey(e: globalThis.KeyboardEvent) {
			if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "f") {
				e.preventDefault();
				setChatSearchOpen(true);
			} else if (e.key === "Escape" && chatSearchOpen) {
				setChatSearchOpen(false);
				setChatSearchQuery("");
				setChatSearchIndex(0);
			}
		}
		window.addEventListener("keydown", onKey);
		return () => window.removeEventListener("keydown", onKey);
	}, [chatSearchOpen]);

	// Update browser tab title to reflect total unread count across all chats.
	const tabTotalUnread = chats.reduce((s, c) => s + c.unread, 0);
	useEffect(() => {
		document.title = tabTotalUnread > 0 ? `(${tabTotalUnread}) Powehi` : "Powehi";
		return () => {
			document.title = "Powehi";
		};
	}, [tabTotalUnread]);

	// Countdown tick — forces a re-render every second when the active chat has any
	// disappearing message so `formatTimeLeft` stays current without polling for each
	// message individually.
	const [countdownTick, setCountdownTick] = useState(0);
	const hasExpiringMessages = (active?.messages ?? []).some((m) => !!m.expiresAt);
	useEffect(() => {
		if (!hasExpiringMessages) return;
		const handle = setInterval(() => setCountdownTick((n) => n + 1), 1000);
		return () => clearInterval(handle);
	}, [hasExpiringMessages]);

	// ── Slow mode ─────────────────────────────────────────────────────────────
	const [slowModeDelay, setSlowModeDelay] = useState<Record<string, SlowModeDelay>>({});
	const [slowModeCooldownUntil, setSlowModeCooldownUntil] = useState<Record<string, number>>({});
	const [slowModeTick, setSlowModeTick] = useState(0);
	const hasCooldown = Object.values(slowModeCooldownUntil).some((v) => v > Date.now());
	useEffect(() => {
		if (!hasCooldown) return;
		const handle = setInterval(() => setSlowModeTick((n) => n + 1), 1000);
		return () => clearInterval(handle);
	}, [hasCooldown]);
	// Seconds remaining for the active chat's cooldown (re-evaluated on each tick).
	// biome-ignore lint/correctness/useExhaustiveDependencies: slowModeTick is the timer signal
	const activeCooldownSec = useMemo(() => {
		const until = slowModeCooldownUntil[activeId] ?? 0;
		return Math.max(0, Math.ceil((until - Date.now()) / 1000));
	}, [slowModeCooldownUntil, activeId, slowModeTick]);

	// Clamp chatSearchIndex whenever the match set changes.
	// biome-ignore lint/correctness/useExhaustiveDependencies: chatSearchMatchIds identity is the trigger; setChatSearchIndex is stable
	useEffect(() => {
		setChatSearchIndex(0);
	}, [chatSearchMatchIds]);

	const mediaMessages = useMemo(
		() => (active?.messages ?? []).filter((m) => !!m.media),
		[active?.messages],
	);
	const handleOpenLightbox = useCallback(
		(msg: ChatMessage) => {
			const idx = mediaMessages.findIndex((m) => m === msg);
			if (idx !== -1) setLightboxMsgIdx(idx);
		},
		[mediaMessages],
	);
	const handleLightboxClose = useCallback(() => setLightboxMsgIdx(null), []);
	const handleLightboxPrev = useCallback(
		() => setLightboxMsgIdx((i) => (i !== null && i > 0 ? i - 1 : i)),
		[],
	);
	const handleLightboxNext = useCallback(
		() => setLightboxMsgIdx((i) => (i !== null && i < mediaMessages.length - 1 ? i + 1 : i)),
		[mediaMessages.length],
	);

	const { sessionToken, identityId } = useAuthStore();
	const cryptoWorker = useCryptoWorker();
	const { persistIncoming, persistOutgoing, purgeExpired } = usePersistentMessages(
		active?.mlsGroupId,
	);
	const showTauriNotification = useTauriNotification();
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
					const dayLabel = getDayLabel(now.getTime());
					// Find the last explicitly-set day label in the history (sparse field).
					let prevDay: string | undefined;
					for (let j = msgs.length - 1; j >= 0; j--) {
						if (msgs[j].day) {
							prevDay = msgs[j].day;
							break;
						}
					}
					msgs.push({
						id: msg.id,
						from: "them",
						text: displayText,
						last: true,
						time,
						ts: now.getTime(),
						day: dayLabel !== prevDay ? dayLabel : undefined,
						continued: msgs.length > 0 && msgs[msgs.length - 1].from === "them",
						media: msg.media,
						expiresAt: msg.expiresAt,
						replyTo: msg.replyTo,
					});
					// Increment unread only when the message arrives for a background chat.
					// activeIdRef.current reflects the current selection without making this
					// callback re-create on every chat switch.
					const isActive = c.id === activeIdRef.current;
					// Track the index of the first unread message so MessageList can render
					// the "New Messages" divider at the right position.
					// Muted chats skip the divider too — no unread tracking for muted chats.
					const firstUnreadAt =
						!isActive && !c.muted && c.unread === 0 ? msgs.length - 1 : c.firstUnreadAt;
					// @mention detection for group chats: increment when text contains @all,
					// @everyone, or @<myHandle> (case-insensitive). Cleared when chat is opened.
					const rawLower = msg.text.toLowerCase();
					const mh = useAuthStore.getState().myHandle?.toLowerCase();
					const isMention =
						!isActive &&
						!!c.isGroup &&
						(rawLower.includes("@all") ||
							rawLower.includes("@everyone") ||
							(!!mh && rawLower.includes(`@${mh}`)));
					return {
						...c,
						messages: msgs,
						last: displayText,
						time,
						unread: isActive ? 0 : c.muted ? c.unread : c.unread + 1,
						firstUnreadAt: isActive ? undefined : firstUnreadAt,
						mentionCount: isActive ? 0 : isMention ? (c.mentionCount ?? 0) + 1 : c.mentionCount,
						archived: c.archived ? false : c.archived,
					};
				}),
			);
			// Encrypt and persist to IndexedDB — fails closed if encryptedDb unavailable.
			persistIncoming(msg);
			// Trigger device vibration for the matching chat unless vibration is disabled or chat is muted.
			// navigator.vibrate is absent on desktop — guard before calling (§7.5 progressive enhancement).
			const incomingChat = chatsRef.current.find((c) => c.mlsGroupId === msg.groupId);
			if (incomingChat && !incomingChat.muted && (incomingChat.vibrate ?? true)) {
				navigator.vibrate?.([100]);
			}
			// Show a native OS notification when the app window is in the background.
			// The hook internally guards on !document.hasFocus() and Tauri availability.
			// Title/body are fixed ("Powehi" / "New message") — no content or sender exposed.
			if (incomingChat && !incomingChat.muted) {
				showTauriNotificationRef.current();
			}
			// Notify sender that we received and decrypted the message (best-effort).
			sendDeliveryReceiptRef.current([msg.id]);
			// Read receipt: only dispatch immediately when this chat is active and the window is
			// focused — the user has actually seen the message. Otherwise buffer it; flushed when
			// the user opens the chat or the window regains focus.
			// Always pass the incoming message's own group IDs so the receipt is encrypted to the
			// correct MLS group regardless of which chat is currently active.
			if (incomingChat?.id === activeIdRef.current && document.hasFocus()) {
				const gId = incomingChat?.mlsGroupId;
				const iId = incomingChat?.mlsIdentityId;
				if (gId && iId) sendReadReceiptRef.current(gId, iId, [msg.id]);
			} else {
				const queue = pendingReadReceipts.current.get(msg.groupId) ?? [];
				queue.push(msg.id);
				pendingReadReceipts.current.set(msg.groupId, queue);
			}
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
						ts: now.getTime(),
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
						return {
							...m,
							reactions: { ...existing, [emoji]: [...senders, senderId] },
						};
					});
					return { ...c, messages: msgs };
				}),
			);
		},
		[],
	);

	/**
	 * Remove a sender's emoji from the target message in the matching chat.
	 * Mirror of handleIncomingReaction — used for optimistic remove and peer reaction_remove.
	 */
	const handleRemoveReaction = useCallback(
		(gId: string, targetId: string, emoji: string, senderId: string) => {
			setChats((cs) =>
				cs.map((c) => {
					if (c.mlsGroupId !== gId) return c;
					const msgs = c.messages.map((m) => {
						if (m.id !== targetId) return m;
						const existing = m.reactions ?? {};
						const senders = existing[emoji] ?? [];
						if (!senders.includes(senderId)) return m;
						const newSenders = senders.filter((s) => s !== senderId);
						if (newSenders.length === 0) {
							const { [emoji]: _removed, ...rest } = existing;
							return { ...m, reactions: rest };
						}
						return { ...m, reactions: { ...existing, [emoji]: newSenders } };
					});
					return { ...c, messages: msgs };
				}),
			);
		},
		[],
	);

	/**
	 * Send an emoji reaction (or remove it if already reacted) to the active MLS group.
	 * Toggle semantics: if myDeviceId is already in the senders list, sends reaction_remove
	 * and removes locally. Otherwise adds the reaction and sends reaction.
	 * Optimistically applies the change locally before the server echo arrives.
	 * Fire-and-forget — failure leaves the optimistic update in place (best-effort UX).
	 */
	const sendReaction = useCallback(
		(targetId: string, emoji: string) => {
			if (!(ALLOWED_REACTION_EMOJIS as readonly string[]).includes(emoji)) return;
			if (targetId.startsWith("opt_")) return;
			if (!sessionToken || !active?.mlsGroupId || !active?.mlsIdentityId || !cryptoWorker) return;
			const { mlsGroupId, mlsIdentityId } = active;
			const myDeviceId = useAuthStore.getState().deviceId;
			const targetChat = chats.find((c) => c.mlsGroupId === mlsGroupId);
			const targetMsg = targetChat?.messages.find((m) => m.id === targetId);
			const alreadyReacted =
				myDeviceId && (targetMsg?.reactions?.[emoji] ?? []).includes(myDeviceId);
			if (alreadyReacted) {
				if (myDeviceId) handleRemoveReaction(mlsGroupId, targetId, emoji, myDeviceId);
				const plaintext = new TextEncoder().encode(
					JSON.stringify({ type: "reaction_remove", emoji, targetMessageId: targetId }),
				);
				cryptoWorker
					.mlsEncrypt(mlsIdentityId, mlsGroupId, plaintext)
					.then(({ ciphertext }) => sendMessageApi(sessionToken, mlsGroupId, ciphertext, undefined))
					.catch(() => {})
					.finally(() => plaintext.fill(0));
			} else {
				if (myDeviceId) handleIncomingReaction(mlsGroupId, targetId, emoji, myDeviceId);
				const plaintext = new TextEncoder().encode(
					JSON.stringify({ type: "reaction", emoji, targetMessageId: targetId }),
				);
				cryptoWorker
					.mlsEncrypt(mlsIdentityId, mlsGroupId, plaintext)
					.then(({ ciphertext }) => sendMessageApi(sessionToken, mlsGroupId, ciphertext, undefined))
					.catch(() => {})
					.finally(() => plaintext.fill(0));
			}
		},
		[active, chats, cryptoWorker, handleIncomingReaction, handleRemoveReaction, sessionToken],
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
	 * Mark messages as delivered when a peer's delivery_receipt arrives.
	 * Sets `delivered: true` on all messages whose `id` is in `messageIds`.
	 * Read state is not affected — a subsequent read_receipt sets `read: true`.
	 */
	const handleIncomingDeliveryReceipt = useCallback((gId: string, messageIds: string[]) => {
		const idSet = new Set(messageIds);
		setChats((cs) =>
			cs.map((c) => {
				if (c.mlsGroupId !== gId) return c;
				const msgs = c.messages.map((m) =>
					m.id && idSet.has(m.id) ? { ...m, delivered: true } : m,
				);
				return { ...c, messages: msgs };
			}),
		);
	}, []);

	/**
	 * Apply an incoming edit to the target message in the matching chat.
	 * Only applies to messages from the peer (`from === "them"`) — prevents
	 * a malicious edit envelope from rewriting our own sent messages.
	 */
	const handleIncomingEdit = useCallback(
		(gId: string, targetMessageId: string, newText: string) => {
			setChats((cs) =>
				cs.map((c) => {
					if (c.mlsGroupId !== gId) return c;
					const msgs = c.messages.map((m) => {
						if (m.id !== targetMessageId || m.from !== "them") return m;
						return { ...m, text: newText, edited: true };
					});
					return { ...c, messages: msgs };
				}),
			);
		},
		[],
	);

	/**
	 * Edit a previously sent "me" message: optimistically update local state,
	 * then MLS-encrypt `{type:"edit", targetMessageId, newText}` and send to peer.
	 * Fire-and-forget — optimistic update stays on failure.
	 */
	const sendEdit = useCallback(
		(targetMessageId: string, newText: string) => {
			if (!sessionToken || !active?.mlsGroupId || !active?.mlsIdentityId || !cryptoWorker) return;
			const { mlsGroupId, mlsIdentityId } = active;
			// Optimistic local update — always applied regardless of whether the envelope has a
			// server-assigned ID yet. opt_* IDs denote messages awaiting backfill.
			setChats((cs) =>
				cs.map((c) => {
					if (c.id !== activeId) return c;
					const msgs = c.messages.map((m) => {
						if (m.id !== targetMessageId || m.from !== "me") return m;
						return { ...m, text: newText, edited: true };
					});
					return { ...c, messages: msgs };
				}),
			);
			setEditingMessage(null);
			// Skip network send for optimistic messages that haven't received a server ID yet.
			if (targetMessageId.startsWith("opt_")) return;
			const plaintext = new TextEncoder().encode(
				JSON.stringify({ type: "edit", targetMessageId, newText }),
			);
			cryptoWorker
				.mlsEncrypt(mlsIdentityId, mlsGroupId, plaintext)
				.then(({ ciphertext }) => sendMessageApi(sessionToken, mlsGroupId, ciphertext, undefined))
				.catch(() => {})
				.finally(() => plaintext.fill(0));
		},
		[active, activeId, cryptoWorker, sessionToken],
	);

	/**
	 * Apply an incoming delete signal: marks the target peer message as deleted.
	 * Only applies to messages from the peer (`from === "them"`) — prevents a
	 * malicious delete envelope from erasing our own sent messages.
	 */
	const handleIncomingDelete = useCallback((gId: string, targetMessageId: string) => {
		setChats((cs) =>
			cs.map((c) => {
				if (c.mlsGroupId !== gId) return c;
				const msgs = c.messages.map((m) => {
					if (m.id !== targetMessageId || m.from !== "them") return m;
					return { ...m, deleted: true };
				});
				return { ...c, messages: msgs };
			}),
		);
	}, []);

	/**
	 * Delete a previously sent "me" message: optimistically mark it deleted locally,
	 * then MLS-encrypt `{type:"delete", targetMessageId}` and broadcast to peers.
	 * Fire-and-forget — optimistic deleted state stays on failure.
	 */
	const sendDelete = useCallback(
		(targetMessageId: string) => {
			if (!sessionToken || !active?.mlsGroupId || !active?.mlsIdentityId || !cryptoWorker) return;
			const { mlsGroupId, mlsIdentityId } = active;
			// Optimistic local update: mark own message deleted immediately.
			setChats((cs) =>
				cs.map((c) => {
					if (c.id !== activeId) return c;
					const msgs = c.messages.map((m) => {
						if (m.id !== targetMessageId || m.from !== "me") return m;
						return { ...m, deleted: true };
					});
					return { ...c, messages: msgs };
				}),
			);
			// opt_* ids are pending server acknowledgement — skip network send.
			if (targetMessageId.startsWith("opt_")) return;
			const plaintext = new TextEncoder().encode(
				JSON.stringify({ type: "delete", targetMessageId }),
			);
			cryptoWorker
				.mlsEncrypt(mlsIdentityId, mlsGroupId, plaintext)
				.then(({ ciphertext }) => sendMessageApi(sessionToken, mlsGroupId, ciphertext, undefined))
				.catch(() => {})
				.finally(() => plaintext.fill(0));
		},
		[active, activeId, cryptoWorker, sessionToken],
	);

	/**
	 * Apply an incoming pin/unpin signal to the matching chat.
	 * Sets or clears `pinnedMessageId` and marks the target message `pinned`.
	 */
	const handleIncomingPin = useCallback(
		(gId: string, targetMessageId: string, action: "pin" | "unpin") => {
			setChats((cs) =>
				cs.map((c) => {
					if (c.mlsGroupId !== gId) return c;
					const msgs = c.messages.map((m) => {
						if (m.id !== targetMessageId) return m;
						return { ...m, pinned: action === "pin" };
					});
					return {
						...c,
						messages: msgs,
						pinnedMessageId:
							action === "pin"
								? targetMessageId
								: c.pinnedMessageId === targetMessageId
									? undefined
									: c.pinnedMessageId,
					};
				}),
			);
		},
		[],
	);

	/**
	 * Handle an incoming presence heartbeat from a peer.
	 * "online" resets the 90s offline timeout; "offline" marks them offline immediately.
	 * lastSeen is recorded when transitioning from online→offline.
	 */
	const handleIncomingPresence = useCallback((gId: string, status: "online" | "offline") => {
		const existing = presenceTimersRef.current.get(gId);
		if (existing) clearTimeout(existing);

		if (status === "offline") {
			presenceTimersRef.current.delete(gId);
			const now = new Date();
			const lastSeen = `${String(now.getHours()).padStart(2, "0")}:${String(now.getMinutes()).padStart(2, "0")}`;
			setChats((cs) =>
				cs.map((c) => (c.mlsGroupId === gId ? { ...c, online: false, lastSeen } : c)),
			);
		} else {
			// "online": mark online and schedule auto-offline after 90 s.
			setChats((cs) => cs.map((c) => (c.mlsGroupId === gId ? { ...c, online: true } : c)));
			const handle = setTimeout(() => {
				presenceTimersRef.current.delete(gId);
				const now = new Date();
				const lastSeen = `${String(now.getHours()).padStart(2, "0")}:${String(now.getMinutes()).padStart(2, "0")}`;
				setChats((cs) =>
					cs.map((c) => (c.mlsGroupId === gId ? { ...c, online: false, lastSeen } : c)),
				);
			}, 90_000);
			presenceTimersRef.current.set(gId, handle);
		}
	}, []);

	/**
	 * Pin or unpin a message in the active MLS group.
	 * Optimistically updates local state, then MLS-encrypts and sends to peer.
	 * Fire-and-forget — optimistic state stays on failure.
	 */
	const sendPin = useCallback(
		(targetMessageId: string) => {
			if (targetMessageId.startsWith("opt_")) return;
			if (!sessionToken || !active?.mlsGroupId || !active?.mlsIdentityId || !cryptoWorker) return;
			const { mlsGroupId, mlsIdentityId } = active;
			const currentlyPinned = active.pinnedMessageId === targetMessageId;
			const action = currentlyPinned ? "unpin" : "pin";
			// Optimistic local update.
			setChats((cs) =>
				cs.map((c) => {
					if (c.id !== activeId) return c;
					const msgs = c.messages.map((m) => {
						if (m.id !== targetMessageId) return m;
						return { ...m, pinned: !currentlyPinned };
					});
					return {
						...c,
						messages: msgs,
						pinnedMessageId: action === "pin" ? targetMessageId : undefined,
					};
				}),
			);
			const plaintext = new TextEncoder().encode(JSON.stringify({ type: action, targetMessageId }));
			cryptoWorker
				.mlsEncrypt(mlsIdentityId, mlsGroupId, plaintext)
				.then(({ ciphertext }) => sendMessageApi(sessionToken, mlsGroupId, ciphertext, undefined))
				.catch(() => {})
				.finally(() => plaintext.fill(0));
		},
		[active, activeId, cryptoWorker, sessionToken],
	);

	/**
	 * Toggle the star/bookmark flag on a message. Local-only — no MLS message sent,
	 * no server contact. Falls back to text match for optimistic messages without a stable ID.
	 */
	const handleStarMessage = useCallback(
		(chatId: string, msgId: string | undefined, msgText: string) => {
			setChats((prev) =>
				prev.map((c) => {
					if (c.id !== chatId) return c;
					const msgs = c.messages.map((m) => {
						const matches = msgId ? m.id === msgId : m.text === msgText;
						if (!matches) return m;
						return { ...m, starred: !m.starred };
					});
					return { ...c, messages: msgs };
				}),
			);
		},
		[],
	);

	/** Share a message via the Web Share API / Tauri native share sheet.
	 * Purely client-side — no MLS message sent, no server contact. */
	const handleShareMessage = useCallback((msg: ChatMessage) => {
		if (!msg.text || msg.text === "[image]") return;
		if (typeof navigator === "undefined" || !navigator.share) return;
		navigator.share({ text: msg.text }).catch(() => {});
	}, []);

	const handleCopyMessage = useCallback((msg: ChatMessage) => {
		if (!msg.text || msg.text === "[image]") return;
		navigator.clipboard.writeText(msg.text).catch(() => {});
	}, []);

	/** Toggle the muted flag on a chat. Local-only — no MLS message sent, no server contact. */
	const handleToggleMute = useCallback((chatId: string) => {
		setChats((cs) => cs.map((c) => (c.id === chatId ? { ...c, muted: !c.muted } : c)));
	}, []);

	/** Toggle the sound flag on a chat. Local-only — no MLS message sent, no server contact. */
	const handleToggleSound = useCallback((chatId: string) => {
		setChats((cs) => cs.map((c) => (c.id === chatId ? { ...c, sound: !(c.sound ?? true) } : c)));
	}, []);

	/** Toggle the vibrate flag on a chat. Local-only — no MLS message sent, no server contact. */
	const handleToggleVibrate = useCallback((chatId: string) => {
		setChats((cs) =>
			cs.map((c) => (c.id === chatId ? { ...c, vibrate: !(c.vibrate ?? true) } : c)),
		);
	}, []);

	/** Toggle the archived flag on a chat. Local-only — no MLS message sent, no server contact. */
	const handleToggleArchive = useCallback((chatId: string) => {
		setChats((cs) => cs.map((c) => (c.id === chatId ? { ...c, archived: !c.archived } : c)));
		// When archiving the active chat, stay in the chat but it's now archived.
		// When un-archiving while on the archived tab, switch to "all" tab — done via Sidebar state.
	}, []);

	/** Toggle the pinnedTop flag on a chat. Local-only — no MLS message sent, no server contact. */
	const handleTogglePinTop = useCallback((chatId: string) => {
		setChats((cs) => cs.map((c) => (c.id === chatId ? { ...c, pinnedTop: !c.pinnedTop } : c)));
	}, []);

	const handleUpdateGroupDescription = useCallback((chatId: string, desc: string) => {
		setChats((cs) => cs.map((c) => (c.id === chatId ? { ...c, description: desc } : c)));
	}, []);

	/** Set (or clear) a custom display nickname for a DM contact. Local-only — never sent to server. */
	const handleUpdateNickname = useCallback((chatId: string, nickname: string) => {
		setChats((cs) =>
			cs.map((c) => (c.id === chatId ? { ...c, nickname: nickname || undefined } : c)),
		);
	}, []);

	/** Erase all messages in a chat. Local-only — no MLS op, no server contact.
	 * Resets unread count, mention count, pinned message, and last-message preview. */
	const handleClearMessages = useCallback((chatId: string) => {
		setChats((cs) =>
			cs.map((c) =>
				c.id !== chatId
					? c
					: {
							...c,
							messages: [],
							unread: 0,
							mentionCount: 0,
							firstUnreadAt: undefined,
							pinnedMessageId: undefined,
							last: "",
							time: "",
						},
			),
		);
	}, []);

	/** Export a chat's messages to a downloadable file (JSON or plain text).
	 * Local-only — triggers a browser download, never sends data to the server.
	 * Only message content fields are exported; crypto keys and envelope IDs are omitted. */
	const handleExportChat = useCallback(
		(chatId: string, format: "json" | "text") => {
			const chat = chats.find((c) => c.id === chatId);
			if (!chat) return;

			// Sanitize the handle to safe filename characters (no path separators, control
			// chars, or RTL-override codepoints that could spoof the download filename).
			const safeHandle =
				chat.handle
					.replace(/[^A-Za-z0-9._-]/g, "_")
					.slice(0, 64)
					.replace(/^[._]+/, "") || "chat";

			const myHandle = useAuthStore.getState().myHandle ?? "You";

			if (format === "json") {
				const payload = {
					chat: { name: chat.name, handle: chat.handle, isGroup: chat.isGroup ?? false },
					messages: chat.messages.map((m) => ({
						from: m.from === "me" ? myHandle : chat.name,
						text: m.deleted ? "(deleted)" : m.text,
						time: m.time ?? null,
						ts: m.ts ?? null,
						edited: m.edited ?? false,
					})),
				};
				const blob = new Blob([JSON.stringify(payload, null, 2)], {
					type: "application/json",
				});
				const url = URL.createObjectURL(blob);
				const a = document.createElement("a");
				a.href = url;
				a.download = `${safeHandle}-export.json`;
				a.click();
				URL.revokeObjectURL(url);
			} else {
				const lines = chat.messages
					.filter((m) => !m.day)
					.map((m) => {
						const sender = m.from === "me" ? myHandle : chat.name;
						const label = m.time ? `${sender} (${m.time})` : sender;
						const body = m.deleted ? "(deleted)" : m.edited ? `${m.text} (edited)` : m.text;
						return `${label}: ${body}`;
					});
				const blob = new Blob([lines.join("\n")], { type: "text/plain" });
				const url = URL.createObjectURL(blob);
				const a = document.createElement("a");
				a.href = url;
				a.download = `${safeHandle}-export.txt`;
				a.click();
				URL.revokeObjectURL(url);
			}
		},
		[chats],
	);

	/** Clear unread badge, mention badge, and unread divider for every chat in one operation.
	 * Local-only — no server call, no MLS op, no logging. */
	const handleMarkAllRead = useCallback(() => {
		setChats((cs) =>
			cs.map((c) => ({ ...c, unread: 0, firstUnreadAt: undefined, mentionCount: 0 })),
		);
	}, []);

	/**
	 * Send a read_receipt to the specified MLS group for the given envelope IDs.
	 * Takes explicit mlsGroupId/mlsIdentityId so buffered receipts from background chats
	 * are always encrypted to the correct group, not to whatever `active` happens to be.
	 * Fire-and-forget — a failed receipt is non-fatal (the UI shows "sent" vs "read" state).
	 * Not a useCallback: re-created each render so it always closes over current session state.
	 * Exposed via sendReadReceiptRef so stable callbacks (handleIncoming) can call it.
	 */
	const sendReadReceipt = (mlsGroupId: string, mlsIdentityId: string, messageIds: string[]) => {
		if (!sessionToken || !mlsGroupId || !mlsIdentityId || !cryptoWorker) return;
		const plaintext = new TextEncoder().encode(
			JSON.stringify({ type: "read_receipt", messageIds, readAt: Date.now() }),
		);
		cryptoWorker
			.mlsEncrypt(mlsIdentityId, mlsGroupId, plaintext)
			.then(({ ciphertext }) => sendMessageApi(sessionToken, mlsGroupId, ciphertext, undefined))
			.catch(() => {})
			.finally(() => plaintext.fill(0));
	};

	/**
	 * Send a delivery_receipt to the active MLS group for the given envelope IDs.
	 * Fire-and-forget — acknowledges to the sender that their message was received and decrypted.
	 * Not a useCallback: re-created each render so it always closes over current state.
	 * Exposed via sendDeliveryReceiptRef so stable callbacks (handleIncoming) can call it.
	 */
	const sendDeliveryReceipt = (messageIds: string[]) => {
		if (!sessionToken || !active?.mlsGroupId || !active?.mlsIdentityId || !cryptoWorker) return;
		const { mlsGroupId, mlsIdentityId } = active;
		const plaintext = new TextEncoder().encode(
			JSON.stringify({ type: "delivery_receipt", messageIds }),
		);
		cryptoWorker
			.mlsEncrypt(mlsIdentityId, mlsGroupId, plaintext)
			.then(({ ciphertext }) => sendMessageApi(sessionToken, mlsGroupId, ciphertext, undefined))
			.catch(() => {})
			.finally(() => plaintext.fill(0));
	};

	// Keep the refs fresh every render so handleIncoming always invokes the latest closures.
	useEffect(() => {
		sendReadReceiptRef.current = sendReadReceipt;
		sendDeliveryReceiptRef.current = sendDeliveryReceipt;
		showTauriNotificationRef.current = showTauriNotification;
	});

	// When the window regains focus, flush pending read receipts for the active chat.
	useEffect(() => {
		const handleWindowFocus = () => {
			const activeChat = chatsRef.current.find((c) => c.id === activeIdRef.current);
			if (!activeChat?.mlsGroupId || !activeChat?.mlsIdentityId) return;
			const pending = pendingReadReceipts.current.get(activeChat.mlsGroupId);
			if (pending?.length) {
				sendReadReceiptRef.current(activeChat.mlsGroupId, activeChat.mlsIdentityId, pending);
				pendingReadReceipts.current.delete(activeChat.mlsGroupId);
			}
		};
		window.addEventListener("focus", handleWindowFocus);
		return () => window.removeEventListener("focus", handleWindowFocus);
	}, []);

	/**
	 * Forward `forwardMsg.text` to the target chat as a new MLS-encrypted message.
	 * Optimistically appends to the target chat's message list, then sends via API.
	 * Fire-and-forget — failure leaves the optimistic bubble in place (same as sendMessage).
	 */
	const sendForward = (targetId: string) => {
		if (!forwardMsg || !sessionToken || !cryptoWorker) return;
		const targetChat = chats.find((c) => c.id === targetId);
		if (!targetChat?.mlsGroupId || !targetChat?.mlsIdentityId) return;
		const { mlsGroupId, mlsIdentityId } = targetChat;
		const text = forwardMsg.text;
		const now = new Date();
		const time = `${String(now.getHours()).padStart(2, "0")}:${String(now.getMinutes()).padStart(2, "0")}`;
		setForwardMsg(null);
		// Optimistic update on the target chat.
		setChats((cs) =>
			cs.map((c) => {
				if (c.id !== targetId) return c;
				const msgs = [...c.messages];
				for (let i = msgs.length - 1; i >= 0; i--) {
					if (msgs[i].from === "me" && msgs[i].last) {
						msgs[i] = { ...msgs[i], last: false, continued: true };
						break;
					}
				}
				msgs.push({ from: "me", text, last: true, time, continued: false });
				return { ...c, messages: msgs, last: text, time };
			}),
		);
		const plaintext = new TextEncoder().encode(text);
		cryptoWorker
			.mlsEncrypt(mlsIdentityId, mlsGroupId, plaintext)
			.then(({ ciphertext }) => sendMessageApi(sessionToken, mlsGroupId, ciphertext, undefined))
			.catch(() => {})
			.finally(() => plaintext.fill(0));
	};

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

	// Send presence heartbeat to the active MLS group every 30 s.
	// Sends "offline" on cleanup (chat switch or unmount) so the peer knows immediately.
	// biome-ignore lint/correctness/useExhaustiveDependencies: active?.mlsGroupId + mlsIdentityId are the semantic triggers; full active object changes on every message
	useEffect(() => {
		if (!sessionToken || !cryptoWorker || !active?.mlsGroupId || !active?.mlsIdentityId) return;
		const { mlsGroupId, mlsIdentityId } = active;

		const sendPresence = (status: "online" | "offline") => {
			const plaintext = new TextEncoder().encode(JSON.stringify({ type: "presence", status }));
			cryptoWorker
				.mlsEncrypt(mlsIdentityId, mlsGroupId, plaintext)
				.then(({ ciphertext }) => sendMessageApi(sessionToken, mlsGroupId, ciphertext, undefined))
				.catch(() => {})
				.finally(() => plaintext.fill(0));
		};

		// Announce online immediately, then refresh every 30 s.
		sendPresence("online");
		const handle = setInterval(() => sendPresence("online"), 30_000);

		return () => {
			clearInterval(handle);
			sendPresence("offline");
		};
	}, [sessionToken, cryptoWorker, active?.mlsGroupId, active?.mlsIdentityId]);

	// Poll for incoming messages whenever there's an active MLS group + session.
	useMessages(
		active?.mlsIdentityId,
		active?.mlsGroupId,
		handleIncoming,
		handlePqBinding,
		handleIncomingTyping,
		handleIncomingReaction,
		handleRemoveReaction,
		handleIncomingReadReceipt,
		handleIncomingDeliveryReceipt,
		handleIncomingEdit,
		handleIncomingDelete,
		handleIncomingPin,
		handleIncomingPresence,
	);

	/** Select a chat and clear its unread and mention badges.
	 * First visit (unread > 0): clears badge, keeps divider visible.
	 * Subsequent visit (unread === 0): clears divider too. */
	const handleSelectChat = useCallback((id: string) => {
		setActiveId(id);
		setReplyingTo(null);
		setEditingMessage(null);
		setChats((cs) =>
			cs.map((c) => {
				if (c.id !== id) return c;
				const base = c.unread > 0 ? { ...c, unread: 0 } : { ...c, firstUnreadAt: undefined };
				return { ...base, mentionCount: 0 };
			}),
		);
		// Flush buffered read receipts for this chat when the user opens it.
		// Use the chat's own mlsGroupId/mlsIdentityId — never `active` — to avoid
		// encrypting receipts into the wrong MLS group (security-auditor finding #1).
		const chat = chatsRef.current.find((c) => c.id === id);
		if (chat?.mlsGroupId && chat?.mlsIdentityId) {
			const pending = pendingReadReceipts.current.get(chat.mlsGroupId);
			if (pending?.length) {
				sendReadReceiptRef.current(chat.mlsGroupId, chat.mlsIdentityId, pending);
				pendingReadReceipts.current.delete(chat.mlsGroupId);
			}
		}
	}, []);

	/**
	 * Jump to a chat from a sidebar message-search result.
	 * Switches to the target chat, seeds in-conversation search with the sidebar query
	 * so matching messages are highlighted immediately, then clears the sidebar search.
	 */
	const handleJumpToMessage = useCallback(
		(chatId: string, messageId?: string) => {
			handleSelectChat(chatId);
			setMsgSearch(search);
			setSearch("");
			if (messageId) setJumpToMessageId(messageId);
		},
		[handleSelectChat, search],
	);

	// Open a DM with a group member by handle (triggered from contact card).
	// Switches to the existing DM if found; closes InfoPanel in both cases.
	const handleOpenDmFromMember = useCallback(
		(handle: string) => {
			const dm = chatsRef.current.find((c) => !c.isGroup && c.handle === handle);
			if (dm) handleSelectChat(dm.id);
			setInfoOpen(false);
		},
		[handleSelectChat],
	);

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
	const handleGroupCreated = useCallback(
		(groupId: string, groupName: string) => {
			setCreateGroupOpen(false);
			setChats((prev) => {
				if (prev.some((c) => c.mlsGroupId === groupId)) return prev;
				const now = new Date();
				const time = `${String(now.getHours()).padStart(2, "0")}:${String(now.getMinutes()).padStart(2, "0")}`;
				return [
					{
						id: groupId,
						name: groupName,
						handle: groupId.slice(0, 8),
						online: false,
						last: "",
						time,
						unread: 0,
						messages: [],
						mlsGroupId: groupId,
						mlsIdentityId: identityId ?? undefined,
						isGroup: true,
						memberCount: 1,
					},
					...prev,
				];
			});
		},
		[identityId],
	);
	const handleMemberAdded = useCallback(
		(_contactId: string, _contactName: string) => {
			setChats((prev) =>
				prev.map((c) => (c.id === activeId ? { ...c, memberCount: (c.memberCount ?? 1) + 1 } : c)),
			);
		},
		[activeId],
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

	// Sweep scheduled messages: when scheduledFor <= now, fire them as regular sends.
	useEffect(() => {
		const fireScheduled = () => {
			const now = Date.now();
			setChats((cs) =>
				cs.map((c) => ({
					...c,
					messages: c.messages.map((m) =>
						m.scheduledFor && m.scheduledFor <= now ? { ...m, scheduledFor: undefined } : m,
					),
				})),
			);
		};
		const handle = setInterval(fireScheduled, 10_000);
		return () => clearInterval(handle);
	}, []);

	const sendScheduled = (text: string, at: number) => {
		const now = new Date();
		const time = `${String(now.getHours()).padStart(2, "0")}:${String(now.getMinutes()).padStart(2, "0")}`;
		const optId = `sched_${crypto.randomUUID()}`;
		setChats((cs) =>
			cs.map((c) => {
				if (c.id !== activeId) return c;
				const msgs = [...c.messages];
				for (let i = msgs.length - 1; i >= 0; i--) {
					if (msgs[i].from === "me" && msgs[i].last && !msgs[i].scheduledFor) {
						msgs[i] = { ...msgs[i], last: false, continued: true };
						break;
					}
				}
				msgs.push({
					id: optId,
					from: "me",
					text,
					last: true,
					time,
					read: false,
					continued: msgs.length > 0 && msgs[msgs.length - 1].from === "me",
					scheduledFor: at,
				});
				return { ...c, messages: msgs };
			}),
		);
	};

	const cancelScheduled = (msgId: string) => {
		setChats((cs) =>
			cs.map((c) => ({
				...c,
				messages: c.messages.filter((m) => m.id !== msgId),
			})),
		);
	};

	const handleCreatePoll = (question: string, options: string[]) => {
		if (!activeId) return;
		const now = new Date();
		const time = `${String(now.getHours()).padStart(2, "0")}:${String(now.getMinutes()).padStart(2, "0")}`;
		const pollId = `poll_${now.getTime()}`;
		const newMsg: ChatMessage = {
			id: pollId,
			from: "me",
			text: "",
			time,
			last: true,
			poll: { question, options: options.map((text) => ({ text, voters: [] })) },
		};
		setChats((cs) =>
			cs.map((c) => (c.id === activeId ? { ...c, messages: [...c.messages, newMsg] } : c)),
		);
	};

	const handleVotePoll = (msgId: string | undefined, optionIdx: number) => {
		if (!activeId || !msgId) return;
		setChats((cs) =>
			cs.map((c) => {
				if (c.id !== activeId) return c;
				return {
					...c,
					messages: c.messages.map((m) => {
						if (m.id !== msgId || !m.poll) return m;
						const opts = m.poll.options.map((opt, i) => {
							if (i !== optionIdx) return opt;
							const already = opt.voters.includes("me");
							return {
								...opt,
								voters: already ? opt.voters.filter((v) => v !== "me") : [...opt.voters, "me"],
							};
						});
						return { ...m, poll: { ...m.poll, options: opts } };
					}),
				};
			}),
		);
	};

	const sendMessage = async (text: string) => {
		const now = new Date();
		const time = `${String(now.getHours()).padStart(2, "0")}:${String(now.getMinutes()).padStart(2, "0")}`;
		const expiresAt = disappearingTtl ? Date.now() + disappearingTtl * 1000 : undefined;

		// Capture reply context before clearing state.
		const currentReply = replyingTo;
		const replyContext: ReplyContext | undefined = currentReply?.id
			? { messageId: currentReply.id, excerpt: currentReply.text.slice(0, 100) }
			: undefined;
		setReplyingTo(null);

		// Apply slow-mode cooldown for the sending chat before dispatching.
		const activeSlowDelay = slowModeDelay[activeId] ?? 0;
		if (activeSlowDelay > 0) {
			setSlowModeCooldownUntil((prev) => ({
				...prev,
				[activeId]: Date.now() + activeSlowDelay * 1000,
			}));
		}

		// Optimistic local update — always runs synchronously so UI is responsive.
		// Assign a temp local ID (opt_ prefix) so ↑-to-edit can target this message before
		// the server-assigned envelope ID is backfilled.
		const optId = `opt_${crypto.randomUUID()}`;
		const sendDayLabel = getDayLabel(now.getTime());
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
				// Set day label only when the day has changed from the last separator.
				let prevDay: string | undefined;
				for (let j = msgs.length - 1; j >= 0; j--) {
					if (msgs[j].day) {
						prevDay = msgs[j].day;
						break;
					}
				}
				msgs.push({
					id: optId,
					from: "me",
					text,
					last: true,
					time,
					ts: now.getTime(),
					day: sendDayLabel !== prevDay ? sendDayLabel : undefined,
					read: false,
					continued: msgs.length > 0 && msgs[msgs.length - 1].from === "me",
					expiresAt,
					replyTo: replyContext,
				});
				return { ...c, messages: msgs, last: text, time };
			}),
		);

		// Real MLS encryption + REST API call when all context is available.
		if (sessionToken && active?.mlsGroupId && active?.mlsIdentityId && cryptoWorker) {
			// Use structured JSON when replying or when a disappearing TTL is active so the
			// receiver can derive its own expiry without the server seeing the duration.
			const payload =
				replyContext || disappearingTtl
					? JSON.stringify({
							type: "text",
							text,
							...(replyContext ? { replyTo: replyContext } : {}),
							...(disappearingTtl ? { ttl: disappearingTtl } : {}),
						})
					: text;
			const encoder = new TextEncoder();
			const plaintext = encoder.encode(payload);
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
							if (msgs[i].from === "me" && msgs[i].id?.startsWith("opt_")) {
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
				drafts={drafts}
				onSelect={handleSelectChat}
				onNewChat={() => setInviteOpen(true)}
				onNewGroup={() => setCreateGroupOpen(true)}
				onSettings={() => undefined}
				searchQuery={search}
				onSearch={setSearch}
				onJumpToMessage={handleJumpToMessage}
				onMarkAllRead={handleMarkAllRead}
				customStatus={customStatus}
				onEditStatus={() => setStatusEditorOpen(true)}
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
						onCall={handleVoiceCall}
						onVideo={handleVideoCall}
						onInfo={() => setInfoOpen((v) => !v)}
						infoOpen={infoOpen}
						pqBindingHex={active.pqBindingHex}
						msgSearch={msgSearch}
						onMsgSearch={setMsgSearch}
						onAddMember={active.isGroup ? () => setAddMemberOpen(true) : undefined}
					/>
					{active.pinnedMessageId && (
						<PinnedBanner
							pinnedMessageId={active.pinnedMessageId}
							messages={active.messages}
							onUnpin={() => sendPin(active.pinnedMessageId ?? "")}
							onJumpToPin={() => setJumpToMessageId(active.pinnedMessageId ?? null)}
						/>
					)}
					<MessageList
						chatId={activeId}
						messages={active.messages}
						partner={active.name}
						searchQuery={msgSearch}
						searchMatchIds={chatSearchMatchIds}
						searchMatchIndex={chatSearchIndex}
						searchMatchQuery={chatSearchQuery || undefined}
						myDeviceId={useAuthStore.getState().deviceId ?? undefined}
						isGroup={active.isGroup}
						isTyping={active.typing}
						members={active.members}
						onReact={sendReaction}
						onReply={setReplyingTo}
						onEdit={setEditingMessage}
						onDelete={sendDelete}
						onPin={sendPin}
						onForward={(msg) => {
							if (msg.id && !msg.deleted) setForwardMsg({ id: msg.id, text: msg.text });
						}}
						onStar={(msgId, msgText) => handleStarMessage(activeId, msgId, msgText)}
						onShare={handleShareMessage}
						onCopy={handleCopyMessage}
						onCancelScheduled={cancelScheduled}
						onVote={handleVotePoll}
						onOpenLightbox={handleOpenLightbox}
						onJumpToReply={(id) => setJumpToMessageId(id)}
						firstUnreadIndex={active.firstUnreadAt}
						jumpToMessageId={jumpToMessageId ?? undefined}
						onJumpComplete={handleJumpComplete}
						countdownTick={countdownTick}
					/>
					{chatSearchOpen && (
						<div
							data-testid="chat-search-bar"
							style={{
								flex: "none",
								display: "flex",
								alignItems: "center",
								gap: 8,
								padding: "8px 16px",
								background: "var(--bg-surface)",
								borderTop: "1px solid var(--border-soft)",
								borderBottom: "1px solid var(--border-soft)",
							}}
						>
							<Icon name="search" size={14} color="var(--fg-3)" />
							<input
								ref={chatSearchInputRef}
								type="text"
								data-testid="chat-search-input"
								placeholder="Search messages…"
								value={chatSearchQuery}
								onChange={(e) => setChatSearchQuery(e.target.value)}
								onKeyDown={(e) => {
									if (e.key === "Escape") {
										setChatSearchOpen(false);
										setChatSearchQuery("");
										setChatSearchIndex(0);
									} else if (e.key === "Enter") {
										if (chatSearchMatchIds.length > 0) {
											setChatSearchIndex((i) => (i + 1) % chatSearchMatchIds.length);
										}
									}
								}}
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
							<span
								data-testid="chat-search-count"
								style={{
									fontSize: 11,
									color: "var(--fg-3)",
									fontFamily: "var(--font-mono)",
									whiteSpace: "nowrap",
									minWidth: 40,
									textAlign: "right",
								}}
							>
								{chatSearchQuery && chatSearchMatchIds.length > 0
									? `${chatSearchIndex + 1} / ${chatSearchMatchIds.length}`
									: chatSearchQuery
										? "0 / 0"
										: ""}
							</span>
							<button
								type="button"
								data-testid="chat-search-prev"
								aria-label="Previous match"
								onClick={() => {
									if (chatSearchMatchIds.length === 0) return;
									setChatSearchIndex(
										(i) => (i - 1 + chatSearchMatchIds.length) % chatSearchMatchIds.length,
									);
								}}
								style={{
									background: "none",
									border: "none",
									color: "var(--fg-3)",
									cursor: "pointer",
									display: "flex",
									alignItems: "center",
									padding: 4,
									borderRadius: 6,
								}}
							>
								<Icon name="chevron-up" size={14} />
							</button>
							<button
								type="button"
								data-testid="chat-search-next"
								aria-label="Next match"
								onClick={() => {
									if (chatSearchMatchIds.length === 0) return;
									setChatSearchIndex((i) => (i + 1) % chatSearchMatchIds.length);
								}}
								style={{
									background: "none",
									border: "none",
									color: "var(--fg-3)",
									cursor: "pointer",
									display: "flex",
									alignItems: "center",
									padding: 4,
									borderRadius: 6,
								}}
							>
								<Icon name="chevron-down" size={14} />
							</button>
							<button
								type="button"
								data-testid="chat-search-close"
								aria-label="Close search"
								onClick={() => {
									setChatSearchOpen(false);
									setChatSearchQuery("");
									setChatSearchIndex(0);
								}}
								style={{
									background: "none",
									border: "none",
									color: "var(--fg-3)",
									cursor: "pointer",
									display: "flex",
									alignItems: "center",
									padding: 4,
									borderRadius: 6,
								}}
							>
								<Icon name="x" size={14} />
							</button>
						</div>
					)}
					<Composer
						onSend={sendMessage}
						partner={active.name}
						ttl={disappearingTtl}
						onToggleTtl={handleToggleTtl}
						onPhoto={() => fileInputRef.current?.click()}
						onTyping={sendTypingIndicator}
						replyTo={replyingTo ? { text: replyingTo.text, from: replyingTo.from } : null}
						onCancelReply={() => setReplyingTo(null)}
						editingMessage={editingMessage}
						onEdit={(newText) => {
							if (editingMessage?.id) sendEdit(editingMessage.id, newText);
						}}
						onCancelEdit={() => setEditingMessage(null)}
						onEditLast={() => {
							const last = [...(active?.messages ?? [])]
								.reverse()
								.find((m) => m.from === "me" && !m.deleted);
							if (last) setEditingMessage(last);
						}}
						chatId={activeId}
						initialDraft={drafts[activeId] ?? ""}
						onDraftChange={handleDraftChange}
						onScheduleSend={sendScheduled}
						onCreatePoll={active.isGroup ? handleCreatePoll : undefined}
						isGroupChat={active.isGroup}
						slowModeCooldownSec={activeCooldownSec}
						slowModeDelay={active.isGroup ? (slowModeDelay[activeId] ?? 0) : 0}
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
					muted={active.muted ?? false}
					onToggleMute={() => handleToggleMute(active.id)}
					sound={active.sound ?? true}
					onToggleSound={() => handleToggleSound(active.id)}
					vibrate={active.vibrate ?? true}
					onToggleVibrate={() => handleToggleVibrate(active.id)}
					archived={active.archived ?? false}
					onToggleArchive={() => handleToggleArchive(active.id)}
					pinnedTop={active.pinnedTop ?? false}
					onTogglePinTop={() => handleTogglePinTop(active.id)}
					myHandle={useAuthStore.getState().myHandle ?? undefined}
					onUpdateDescription={(desc) => handleUpdateGroupDescription(active.id, desc)}
					onUpdateNickname={(nickname) => handleUpdateNickname(active.id, nickname)}
					onClearMessages={() => handleClearMessages(active.id)}
					onExportChat={(fmt) => handleExportChat(active.id, fmt)}
					mediaMessages={mediaMessages}
					onOpenLightbox={handleOpenLightbox}
					onOpenDm={handleOpenDmFromMember}
					slowModeDelay={slowModeDelay[active.id] ?? 0}
					onSetSlowMode={(d) => setSlowModeDelay((prev) => ({ ...prev, [active.id]: d }))}
					isAdmin={
						active.members?.some(
							(m) =>
								m.role === "admin" &&
								m.handle.toLowerCase() === (useAuthStore.getState().myHandle ?? "").toLowerCase(),
						) ?? false
					}
				/>
			)}

			<InviteModal open={inviteOpen} onClose={() => setInviteOpen(false)} />

			{lightboxMsgIdx !== null && (
				<Lightbox
					mediaMsgs={mediaMessages}
					idx={lightboxMsgIdx}
					onClose={handleLightboxClose}
					onPrev={handleLightboxPrev}
					onNext={handleLightboxNext}
				/>
			)}

			{/* Voice / video call overlay — pure UI stub (no WebRTC) */}
			{callState !== "idle" && callChat && (
				<CallOverlay
					state={callState}
					type={callType}
					chatName={callChat.name}
					durationSec={callDurationSec}
					muted={callMuted}
					cameraOff={callCameraOff}
					screensharing={callScreensharing}
					onHangUp={handleHangUp}
					onAccept={handleAcceptCall}
					onDecline={handleDeclineCall}
					onMuteToggle={() => setCallMuted((m) => !m)}
					onCameraToggle={() => setCallCameraOff((o) => !o)}
					onScreenshareToggle={handleScreenshareToggle}
				/>
			)}

			{/* Hidden dev button — lets tests trigger an incoming call without WebRTC signalling. */}
			<button
				type="button"
				data-testid="dev-simulate-incoming-call"
				style={{ display: "none" }}
				onClick={() => {
					setCallType("voice");
					setCallState("incoming");
					setCallChatId(activeIdRef.current);
				}}
			>
				simulate
			</button>

			<CreateGroupModal
				open={createGroupOpen}
				onClose={() => setCreateGroupOpen(false)}
				onGroupCreated={handleGroupCreated}
			/>

			{active?.isGroup && (
				<AddMemberModal
					open={addMemberOpen}
					onClose={() => setAddMemberOpen(false)}
					groupId={active.mlsGroupId ?? active.id}
					groupName={active.name}
					contacts={chats
						.filter((c) => !c.isGroup && c.id !== active.id)
						.map((c) => ({ id: c.id, name: c.name }))}
					onMemberAdded={handleMemberAdded}
				/>
			)}

			{forwardMsg && (
				<div
					data-testid="forward-modal-backdrop"
					style={{
						position: "fixed",
						inset: 0,
						background: "rgba(4,4,8,0.72)",
						display: "flex",
						alignItems: "center",
						justifyContent: "center",
						zIndex: 100,
					}}
					onClick={() => setForwardMsg(null)}
					onKeyDown={(e) => {
						if (e.key === "Escape") setForwardMsg(null);
					}}
				>
					<div
						data-testid="forward-modal"
						style={{
							background: "var(--bg-elevated)",
							border: "1px solid var(--border-faint)",
							borderRadius: 16,
							padding: "20px 0 8px",
							width: 320,
							maxHeight: 440,
							display: "flex",
							flexDirection: "column",
							boxShadow: "0 8px 32px rgba(0,0,0,0.5)",
						}}
						onClick={(e) => e.stopPropagation()}
						onKeyDown={(e) => e.stopPropagation()}
					>
						<div
							style={{
								display: "flex",
								alignItems: "center",
								justifyContent: "space-between",
								padding: "0 20px 14px",
								borderBottom: "1px solid var(--border-faint)",
							}}
						>
							<span
								style={{
									fontSize: 11,
									fontWeight: 600,
									letterSpacing: "0.12em",
									color: "var(--fg-3)",
									textTransform: "uppercase",
								}}
							>
								Forward to
							</span>
							<button
								type="button"
								aria-label="Cancel forward"
								data-testid="forward-modal-close"
								onClick={() => setForwardMsg(null)}
								style={{
									background: "none",
									border: "none",
									color: "var(--fg-3)",
									cursor: "pointer",
									padding: 4,
									display: "flex",
									alignItems: "center",
									justifyContent: "center",
								}}
							>
								<Icon name="x" size={14} />
							</button>
						</div>
						<div style={{ overflowY: "auto", padding: "8px 0" }}>
							{chats
								.filter((c) => c.id !== activeId && c.mlsGroupId && c.mlsIdentityId)
								.map((c) => (
									<button
										key={c.id}
										type="button"
										data-testid={`forward-target-${c.id}`}
										onClick={() => sendForward(c.id)}
										style={{
											width: "100%",
											display: "flex",
											alignItems: "center",
											gap: 12,
											padding: "10px 20px",
											background: "none",
											border: "none",
											color: "var(--fg-1)",
											cursor: "pointer",
											textAlign: "left",
										}}
									>
										<div
											style={{
												width: 36,
												height: 36,
												borderRadius: "50%",
												background: "var(--bg-void)",
												display: "flex",
												alignItems: "center",
												justifyContent: "center",
												fontSize: 14,
												fontWeight: 600,
												color: "#A8C8FF",
												flexShrink: 0,
											}}
										>
											{c.name[0]}
										</div>
										<div>
											<div style={{ fontSize: 13, fontWeight: 500 }}>{c.name}</div>
											<div
												style={{
													fontSize: 11,
													color: "var(--fg-3)",
													marginTop: 1,
												}}
											>
												{c.last
													? c.last.length > 30
														? `${c.last.slice(0, 30)}…`
														: c.last
													: "No messages yet"}
											</div>
										</div>
									</button>
								))}
							{chats.filter((c) => c.id !== activeId && c.mlsGroupId && c.mlsIdentityId).length ===
								0 && (
								<div
									style={{
										padding: "20px",
										textAlign: "center",
										fontSize: 13,
										color: "var(--fg-4)",
									}}
								>
									No other conversations
								</div>
							)}
						</div>
					</div>
				</div>
			)}

			{/* ── Quick switcher (Cmd+K / Ctrl+K) ─────────────────────────────── */}
			{quickSwitcherOpen && (
				<QuickSwitcher
					chats={chats}
					query={quickSwitcherQuery}
					activeIdx={quickSwitcherActive}
					inputRef={quickSwitcherInputRef}
					onQueryChange={(q) => {
						setQuickSwitcherQuery(q);
						setQuickSwitcherActive(0);
					}}
					onActiveChange={setQuickSwitcherActive}
					onSelect={(id) => {
						setActiveId(id);
						setQuickSwitcherOpen(false);
					}}
					onClose={() => setQuickSwitcherOpen(false)}
				/>
			)}

			{/* ── Custom user status editor ─────────────────────────────────────── */}
			{statusEditorOpen && (
				<StatusEditor
					current={customStatus}
					onSave={setCustomStatus}
					onClose={() => setStatusEditorOpen(false)}
				/>
			)}
		</div>
	);
}
