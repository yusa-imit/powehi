//! Moves stored messages into the TUI (8.20 slice b2b): rows reloaded from the store, each
//! pending message of the selected conversation removed from the store and then shown.

use zeroize::Zeroizing;

use super::{rows, App};
use crate::message;
use crate::store::ProfileStore;

/// Reloads the conversation list and moves the SELECTED conversation's stored messages into
/// `app`. Other conversations keep their messages in the store (and their unread count): a
/// message leaves the store only once its conversation is on screen. Unreadable records are
/// skipped; nothing here is logged.
pub fn drain(store: &ProfileStore, app: &mut App) {
    let Ok(list) = rows::load(store) else {
        app.set_notice("could not read conversations");
        return;
    };
    app.set_rows(list);
    let Some(id) = app.selected_id() else {
        return;
    };
    let Ok(msgs) = message::pending(store, id) else {
        return;
    };
    for m in &msgs {
        // Remove first: a message that cannot be removed stays in the store, unshown, and is
        // retried on the next refresh. Showing first would repeat it on every refresh.
        if message::discard(store, m).is_err() {
            app.set_notice("could not remove a message from the store");
            return;
        }
        let who = message::sender_label(m);
        app.push_message(id, who, Zeroizing::new(m.text.to_string()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conversation::{self, Conversation, Role};
    use crate::inbox::{Received, RX_PREFIX};
    use crate::profile::ProfilePaths;
    use uuid::Uuid;

    #[test]
    fn stored_messages_move_into_the_app_and_leave_the_store() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = ProfilePaths::resolve(tmp.path(), "work").unwrap();
        let store = ProfileStore::open(&paths, &[7u8; 32]).unwrap();
        let gid = Uuid::new_v4();
        conversation::save(
            &store,
            &Conversation::new(gid, Uuid::new_v4(), Role::Creator, None),
        )
        .unwrap();
        let rec = Received {
            group_id: gid,
            sender: Uuid::new_v4(),
            body: b"hello".to_vec(),
            received_at: 1,
            sender_key: None,
        };
        let name = format!("{RX_PREFIX}{}", Uuid::new_v4().hyphenated());
        store
            .put(&name, &serde_json::to_vec(&rec).unwrap())
            .unwrap();
        let mut app = App::new(Vec::new());
        drain(&store, &mut app);
        assert_eq!(app.selected_id(), Some(gid));
        // A second, unselected conversation keeps its message in the store.
        let other = Uuid::new_v4();
        conversation::save(
            &store,
            &Conversation::new(other, Uuid::new_v4(), Role::Creator, None),
        )
        .unwrap();
        let rec2 = Received {
            group_id: other,
            sender: Uuid::new_v4(),
            body: b"x".to_vec(),
            received_at: 2,
            sender_key: None,
        };
        let name2 = format!("{RX_PREFIX}{}", Uuid::new_v4().hyphenated());
        store
            .put(&name2, &serde_json::to_vec(&rec2).unwrap())
            .unwrap();
        drain(&store, &mut app);
        assert!(store.get(&name2).unwrap().is_some());
        assert!(store.get(&name).unwrap().is_none());
        assert!(message::pending(&store, gid).unwrap().is_empty());
    }
}
