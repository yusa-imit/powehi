import { useMediaReceive } from "../hooks/useMediaReceive";
import type { MediaPayload } from "../hooks/useMessages";

/**
 * MediaImage — displays an §9.2 encrypted image attachment.
 *
 * Downloads and decrypts the R2 blob via useMediaReceive; shows a loading
 * placeholder until the image is ready, or an "unavailable" label on error.
 * The object URL is revoked on unmount to prevent memory leaks.
 */
export function MediaImage({ media }: { media: MediaPayload }) {
	const { objectUrl, loading, error } = useMediaReceive(media);

	if (loading) {
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

	if (error || !objectUrl) {
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

	return (
		<img
			src={objectUrl}
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
