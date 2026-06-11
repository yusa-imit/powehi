import { useMediaReceive } from "../hooks/useMediaReceive";
import type { MediaPayload } from "../hooks/useMessages";
import { useThumbnail } from "../hooks/useThumbnail";

/**
 * MediaImage — displays an §9.2 encrypted image attachment.
 *
 * §9.4.1: If the media payload includes an inline `thumbnail`, decrypts and
 * shows it immediately as a blurred placeholder while the full R2 image loads.
 * Once the full image is ready, replaces the thumbnail with the full image.
 *
 * Object URLs are revoked on unmount to prevent memory leaks.
 */
export function MediaImage({ media }: { media: MediaPayload }) {
	const { objectUrl, loading, error } = useMediaReceive(media);
	const { objectUrl: thumbUrl } = useThumbnail(loading ? media.thumbnail : undefined);

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
				Image unavailable
			</div>
		);
	}

	if (loading) {
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
				aria-label="Loading image"
			>
				Loading…
			</div>
		);
	}

	return (
		<img
			src={objectUrl ?? ""}
			alt="Encrypted attachment"
			style={{
				maxWidth: "100%",
				maxHeight: 320,
				borderRadius: 10,
				display: "block",
			}}
		/>
	);
}
