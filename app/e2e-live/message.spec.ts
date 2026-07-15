import { randomUUID } from "node:crypto";
import { expect, test } from "@playwright/test";
import {
	forwardBrowserErrors,
	registerAndReachChat,
	signIn,
	simulateDistinctClientIp,
	uniqueHandle,
} from "./helpers";

// Live-backend E2E, Phase 2 (testing-conventions.md: "E2E: Playwright for
// ... message send/receive"). Builds on auth.spec.ts's real OPAQUE
// register/sign-in by driving TWO independent real devices (separate
// BrowserContexts, so each has its own IndexedDB-persisted device_id/MLS
// identity) through the real invite-link contact flow
// (InviteModal -> AcceptInviteModal, see those components' doc comments for
// the exact KeyPackage-fetch / MLS-group-create / Welcome-send sequence)
// and then a real bidirectional MLS-encrypted message exchange over the
// wire — the two devices only ever share ciphertext with the server.
test.describe("Live backend: contact invite + message exchange", () => {
	test("two real devices connect via an invite link and exchange encrypted messages", async ({
		page,
		browser,
	}) => {
		// Real WASM crypto (OPAQUE + MLS) for two full register flows plus a
		// full invite/accept/KeyPackage/Welcome handshake and two message
		// round trips comfortably exceeds the config default of 60s.
		test.setTimeout(150_000);

		const password = "CorrectHorseBattery9!";
		const handleA = uniqueHandle();
		const handleB = uniqueHandle();

		// Separate BrowserContext for B so it gets its own origin storage
		// (IndexedDB device_id/MLS identity) — sharing A's context would
		// collide both "devices" onto the same local identity.
		const contextB = await browser.newContext();
		const pageB = await contextB.newPage();

		// Surface WASM panics / uncaught exceptions (e.g. inside the
		// mlsCreateGroup/mlsAddMember crypto-worker calls) in CI logs instead of
		// only observing a downstream `open-chat-btn` timeout with no clue which
		// step failed.
		forwardBrowserErrors(page, "device-A");
		forwardBrowserErrors(pageB, "device-B");

		try {
			// Distinct simulated client IPs so A's and B's auth calls (and
			// auth.spec.ts's, which ran earlier in this same worker) land in
			// separate auth_governor buckets instead of exhausting one shared
			// fallback bucket — see simulateDistinctClientIp's doc comment.
			await simulateDistinctClientIp(page.context());
			await simulateDistinctClientIp(contextB);

			await registerAndReachChat(page, handleA, password);
			await registerAndReachChat(pageB, handleB, password);

			// A creates a one-time invite link.
			await page.getByRole("button", { name: "New chat" }).click();
			const inviteDialog = page.getByRole("dialog", { name: /new contact invite/i });
			await expect(inviteDialog).toBeVisible();
			await inviteDialog.getByRole("button", { name: "Create invite link" }).click();
			const inviteUrlLocator = inviteDialog.getByTestId("invite-url");
			await expect(inviteUrlLocator).toBeVisible({ timeout: 15_000 });
			const inviteUrl = (await inviteUrlLocator.textContent())?.trim();
			expect(inviteUrl).toBeTruthy();
			// biome-ignore lint/style/noNonNullAssertion: asserted truthy above
			const url = inviteUrl!;

			// Close the invite dialog the way a real user would (it never
			// auto-closes — InviteModal.tsx stays mounted until the "Close"
			// button, backdrop click, or Escape fires onClose). Left open, its
			// full-viewport `<dialog>` (zIndex 100) intercepts pointer events on
			// everything behind it, including the sidebar row asserted below.
			await inviteDialog.getByRole("button", { name: "Close" }).click();
			await expect(inviteDialog).not.toBeVisible();

			// B opens the invite link. This is a full navigation, so B lands back
			// on the login screen (in-memory session token cleared, same as a
			// reload) but the code survives in the URL fragment; ChatLayout only
			// reads it once mounted post-login (see ChatLayout.tsx's invite-code
			// detection effect).
			await pageB.goto(url);
			await signIn(pageB, handleB, password);

			// B redeems the code: real redeemInvite -> fetchKeyPackage ->
			// mlsCreateGroup -> mlsAddMember -> createGroup -> addMember ->
			// sendWelcome (AcceptInviteModal.tsx).
			const acceptDialog = pageB.getByRole("dialog", { name: /accept contact invite/i });
			await expect(acceptDialog).toBeVisible({ timeout: 10_000 });
			await acceptDialog.getByRole("button", { name: "Connect" }).click();
			const openChatBtn = acceptDialog.getByTestId("open-chat-btn");
			await expect(openChatBtn).toBeVisible({ timeout: 30_000 });
			await openChatBtn.click();

			// B is now inside the freshly created 1:1 chat — send the first message.
			const messageFromB = `hello from B ${randomUUID().slice(0, 8)}`;
			await pageB.getByTestId("composer-textarea").fill(messageFromB);
			await pageB.getByTestId("composer-textarea").press("Enter");

			// A's global Welcome poller (useWelcomePoller, 3s interval) picks up
			// B's Welcome and adds a new sidebar entry named "Contact <deviceId
			// prefix>" (ChatLayout.tsx's handleNewGroup) — select it to make it
			// the active chat, which is what starts A's per-group message poller.
			const newChatRow = page.getByRole("button", { name: /^Contact / });
			await expect(newChatRow).toBeVisible({ timeout: 30_000 });
			await newChatRow.click();

			// A's per-group message poller (useMessages, 3s interval) decrypts
			// and renders B's real MLS-encrypted message.
			await expect(page.getByTestId("message-list-scroll").getByText(messageFromB)).toBeVisible({
				timeout: 30_000,
			});

			// Reply from A, proving the channel works both ways.
			const messageFromA = `hello from A ${randomUUID().slice(0, 8)}`;
			await page.getByTestId("composer-textarea").fill(messageFromA);
			await page.getByTestId("composer-textarea").press("Enter");

			// B is still on the same (already-active) chat, so its message poller
			// is already running.
			await expect(pageB.getByTestId("message-list-scroll").getByText(messageFromA)).toBeVisible({
				timeout: 30_000,
			});
		} finally {
			await contextB.close();
		}
	});
});
