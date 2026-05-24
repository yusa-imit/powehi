export function App() {
	return (
		<div
			style={{
				minHeight: "100vh",
				display: "flex",
				alignItems: "center",
				justifyContent: "center",
				flexDirection: "column",
				gap: "0.5rem",
			}}
		>
			<h1
				style={{
					fontSize: "2rem",
					fontWeight: 500,
					letterSpacing: "-0.02em",
					color: "var(--fg-1)",
					margin: 0,
				}}
			>
				Pōwehi
			</h1>
			<p
				style={{
					fontSize: "0.875rem",
					color: "var(--fg-3)",
					margin: 0,
				}}
			>
				End-to-end encrypted messaging
			</p>
		</div>
	);
}
