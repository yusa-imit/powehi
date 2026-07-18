import { type CSSProperties, useState } from "react";
import { useMediaReceive } from "../hooks/useMediaReceive";
import type { MediaPayload } from "../hooks/useMessages";
import { useThumbnail } from "../hooks/useThumbnail";

/**
 * MediaImage — displays an §9.2 encrypted image, (§9.4.2) chunked video, or audio
 * (voice message) attachment.
 *
 * §9.4.1: If the media payload includes an inline `thumbnail`, decrypts and
 * shows it immediately as a blurred placeholder while the full R2 image loads.
 * Once the full image is ready, replaces the thumbnail with the full image.
 *
 * Routing to the encrypted blob (chunked vs single-shot) is still purely
 * size-based (see mediaTransfer.ts) and the legacy wire `type` field only ever
 * says "image" or "video" per that same size bucket — but since cycle 296 the
 * envelope also carries the sender's real `mimeType` when available, which is
 * what decides image-vs-video display here. `media.chunked === true` (no
 * `mimeType`, e.g. from an older client build) is still trusted as "this is a
 * video" fallback. Failing that, a small video wire-tagged "image" with no
 * `mimeType` would fail to decode as an `<img>`: the `onError` handler below
 * falls back to `<video>` in that case rather than showing a permanent
 * "unavailable" state.
 *
 * Object URLs are revoked on unmount to prevent memory leaks.
 *
 * Pass `interactive={false}` (default `true`) when embedding inside another
 * clickable element (e.g. a gallery-grid `<button>`) — a `<video controls>`
 * nested inside a `<button>` is invalid HTML and its controls would be
 * unreachable anyway (clicks bubble to the outer button). In that mode video
 * attachments render without the `controls` attribute plus a small play-badge
 * so the tile still reads as "this is a video".
 */
export function MediaImage({
	media,
	imgStyle,
	interactive = true,
}: {
	media: MediaPayload;
	imgStyle?: CSSProperties;
	interactive?: boolean;
}) {
	const { objectUrl, loading, error } = useMediaReceive(media);
	const { objectUrl: thumbUrl } = useThumbnail(loading ? media.thumbnail : undefined);
	const [imgFailed, setImgFailed] = useState(false);
	// Real mimeType (cycle-296) is authoritative when present; otherwise fall back to
	// the legacy chunked-implies-video heuristic (older client build, or the not-yet-
	// decoded default before an `onError` has had a chance to fire).
	const looksLikeVideo =
		media.mimeType != null ? media.mimeType.startsWith("video/") : media.chunked === true;
	// Voice messages always carry a real audio/* mimeType (useVoiceRecorder sets file.type) —
	// there is no legacy chunked-implies-audio heuristic to fall back to, unlike video above.
	const looksLikeAudio = media.mimeType?.startsWith("audio/");
	const isVideo = looksLikeVideo || imgFailed;

	if (error || (!loading && !objectUrl)) {
		return (
			<div
				style={{
					display: "flex",
					alignItems: "center",
					gap: 6,
					fontSize: 13,
					opacity: 0.7,
				}}
			>
				{looksLikeAudio
					? "Voice message unavailable"
					: looksLikeVideo
						? "Video unavailable"
						: "Image unavailable"}
			</div>
		);
	}

	if (loading) {
		if (looksLikeAudio) {
			return (
				<div
					style={{
						width: 200,
						height: 40,
						borderRadius: 10,
						background: "rgba(168,200,255,0.08)",
						display: "flex",
						alignItems: "center",
						justifyContent: "center",
						fontSize: 12,
						color: "var(--fg-3)",
					}}
					aria-label="Loading voice message"
				>
					Loading voice message…
				</div>
			);
		}
		if (thumbUrl) {
			return (
				<img
					src={thumbUrl}
					alt="Loading encrypted attachment"
					aria-label="Loading image"
					style={{
						maxWidth: "100%",
						maxHeight: 320,
						borderRadius: 10,
						display: "block",
						filter: "blur(4px)",
						transition: "filter 0.3s",
						...imgStyle,
					}}
				/>
			);
		}
		return (
			<div
				style={{
					width: 200,
					height: 120,
					borderRadius: 10,
					background: "rgba(168,200,255,0.08)",
					display: "flex",
					alignItems: "center",
					justifyContent: "center",
					fontSize: 12,
					color: "var(--fg-3)",
				}}
				aria-label={looksLikeVideo ? "Loading video" : "Loading image"}
			>
				Loading…
			</div>
		);
	}

	if (looksLikeAudio) {
		return (
			// biome-ignore lint/a11y/useMediaCaption: live voice messages have no caption track to attach.
			<audio
				controls
				src={objectUrl ?? ""}
				aria-label="Encrypted voice message"
				style={{ width: "100%", ...imgStyle }}
			/>
		);
	}

	if (isVideo) {
		return (
			<div style={{ position: "relative", display: "block", ...imgStyle }}>
				<video
					src={objectUrl ?? ""}
					controls={interactive}
					muted={!interactive}
					aria-label="Encrypted video attachment"
					style={{
						maxWidth: "100%",
						maxHeight: interactive ? 320 : "100%",
						width: interactive ? undefined : "100%",
						height: interactive ? undefined : "100%",
						objectFit: interactive ? undefined : "cover",
						borderRadius: 10,
						display: "block",
					}}
				/>
				{!interactive && (
					<div
						aria-hidden="true"
						style={{
							position: "absolute",
							inset: 0,
							display: "flex",
							alignItems: "center",
							justifyContent: "center",
							pointerEvents: "none",
						}}
					>
						<div
							style={{
								width: 28,
								height: 28,
								borderRadius: "50%",
								background: "rgba(4,4,8,0.55)",
								display: "flex",
								alignItems: "center",
								justifyContent: "center",
							}}
						>
							<div
								style={{
									width: 0,
									height: 0,
									marginLeft: 2,
									borderTop: "6px solid transparent",
									borderBottom: "6px solid transparent",
									borderLeft: "9px solid var(--fg-1, #F2EDE3)",
								}}
							/>
						</div>
					</div>
				)}
			</div>
		);
	}

	return (
		<img
			src={objectUrl ?? ""}
			alt="Encrypted attachment"
			onError={() => setImgFailed(true)}
			style={{
				maxWidth: "100%",
				maxHeight: 320,
				borderRadius: 10,
				display: "block",
				...imgStyle,
			}}
		/>
	);
}
