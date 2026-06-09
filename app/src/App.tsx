import { useEffect, useState } from "react";
import { extractInviteCode } from "./api/invites";
import { AcceptInviteModal } from "./components/AcceptInviteModal";
import { ChatLayout } from "./components/ChatLayout";
import { Login } from "./components/Login";
import { useAuthStore } from "./store/auth";

export function App() {
	const phase = useAuthStore((s) => s.phase);
	const [inviteCode, setInviteCode] = useState<string | null>(null);

	// Detect invite code in URL fragment when authenticated.
	// The fragment is never transmitted to the server (RFC 3986 §3.5).
	useEffect(() => {
		if (phase !== "app") return;
		const code = extractInviteCode(window.location.hash);
		if (code) {
			setInviteCode(code);
			// Clear the hash so navigating away and back doesn't re-trigger the modal.
			history.replaceState(null, "", window.location.pathname + window.location.search);
		}
	}, [phase]);

	const handleAccepted = (_groupId: string) => {
		setInviteCode(null);
	};

	return (
		<>
			{phase === "login" ? <Login /> : <ChatLayout />}
			{inviteCode !== null && phase === "app" && (
				<AcceptInviteModal
					inviteCode={inviteCode}
					onClose={() => setInviteCode(null)}
					onAccepted={handleAccepted}
				/>
			)}
		</>
	);
}
