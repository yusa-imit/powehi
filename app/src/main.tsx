import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { App } from "./App";
import { useServiceWorker } from "./hooks/useServiceWorker";
import "./index.css";

function Root() {
	useServiceWorker();
	return <App />;
}

const root = document.getElementById("root");
if (!root) throw new Error("Root element not found");

createRoot(root).render(
	<StrictMode>
		<Root />
	</StrictMode>,
);
