import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { App } from "./App";
import { useServiceWorker } from "./hooks/useServiceWorker";
import { useAuthStore } from "./store/auth";
import "./index.css";

function Root() {
	const sessionToken = useAuthStore((s) => s.sessionToken);
	// VITE_VAPID_PUBLIC_KEY is injected at build time for the target deployment.
	// Missing in dev/CI — push subscription registration is silently skipped.
	const vapidPublicKey = import.meta.env.VITE_VAPID_PUBLIC_KEY;
	useServiceWorker(vapidPublicKey, sessionToken ?? undefined);
	return <App />;
}

const root = document.getElementById("root");
if (!root) throw new Error("Root element not found");

createRoot(root).render(
	<StrictMode>
		<Root />
	</StrictMode>,
);
