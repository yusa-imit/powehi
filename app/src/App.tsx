import { ChatLayout } from "./components/ChatLayout";
import { Login } from "./components/Login";
import { useAuthStore } from "./store/auth";

export function App() {
	const phase = useAuthStore((s) => s.phase);
	return phase === "login" ? <Login /> : <ChatLayout />;
}
