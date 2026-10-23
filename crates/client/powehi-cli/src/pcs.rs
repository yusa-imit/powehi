//! Post-compromise-security rotation policy (prd.md §5, Phase 8 item 8.15): when `send`/`chat`
//! must first rotate this device's leaf key with a self-Update Commit.
//!
//! Pure decisions only; the staging, the server call and the merge live elsewhere. An idle
//! conversation never rotates (there is nothing new to protect), so age counts only once the
//! device has sent under the current epoch secrets.

use crate::conversation::Conversation;

/// Rotate after this many Application messages sent under one leaf key.
pub const MAX_MESSAGES_PER_UPDATE: u32 = 50;
/// Rotate when the leaf key is this old (7 days) and at least one message is about to go out.
pub const MAX_UPDATE_AGE_SECS: u64 = 7 * 24 * 60 * 60;

/// True when a self-Update Commit should precede the next Application message at `now`.
///
/// `last_update_at` unknown (`None`) means no message was sent yet: not due. A clock that went
/// backwards (`now` before the recorded time) is not due either; the counter still applies.
pub fn update_due(conv: &Conversation, now: u64) -> bool {
    let count = conv.sent_since_update();
    if count >= MAX_MESSAGES_PER_UPDATE {
        return true;
    }
    match conv.last_update_at() {
        Some(at) if count > 0 => now.saturating_sub(at) >= MAX_UPDATE_AGE_SECS,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conversation::Role;
    use uuid::Uuid;

    fn conv() -> Conversation {
        Conversation::new(Uuid::new_v4(), Uuid::new_v4(), Role::Creator, None)
    }

    #[test]
    fn a_fresh_conversation_is_not_due() {
        assert!(!update_due(&conv(), 1_000_000));
    }

    #[test]
    fn the_message_count_triggers_exactly_at_the_limit() {
        let mut c = conv();
        for _ in 0..MAX_MESSAGES_PER_UPDATE - 1 {
            c.note_sent(100);
        }
        assert!(!update_due(&c, 100));
        c.note_sent(100);
        assert!(update_due(&c, 100));
    }

    #[test]
    fn age_triggers_only_after_a_send_and_exactly_at_the_limit() {
        let mut c = conv();
        c.note_sent(1_000);
        assert!(!update_due(&c, 1_000 + MAX_UPDATE_AGE_SECS - 1));
        assert!(update_due(&c, 1_000 + MAX_UPDATE_AGE_SECS));
    }

    #[test]
    fn a_confirmed_update_resets_both_triggers() {
        let mut c = conv();
        for _ in 0..MAX_MESSAGES_PER_UPDATE {
            c.note_sent(10);
        }
        assert!(update_due(&c, 10));
        c.note_self_update(20);
        assert_eq!(c.sent_since_update(), 0);
        assert!(!update_due(&c, 20 + MAX_UPDATE_AGE_SECS));
        c.note_sent(30);
        assert!(!update_due(&c, 30));
    }

    #[test]
    fn a_clock_before_the_record_is_not_due_by_age() {
        let mut c = conv();
        c.note_sent(5_000);
        assert!(!update_due(&c, 1));
    }

    #[test]
    fn the_counter_saturates_instead_of_wrapping() {
        let mut c = conv();
        c.set_sent_for_test(u32::MAX);
        c.note_sent(1);
        assert_eq!(c.sent_since_update(), u32::MAX);
        assert!(update_due(&c, 1));
    }
}
