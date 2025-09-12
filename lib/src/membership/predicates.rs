/// PODLang predicates for membership management system
///
/// This module defines predicates for managing membership in a system with:
/// - Admin-controlled invitations
/// - Member acceptance flow
/// - State updates with membership changes

/// Initialize a new membership state with empty member set
///
/// init_membership(state) = AND(
///     Equals(state["members"], EMPTY_SET)
/// )
pub const INIT_MEMBERSHIP: &str = r#"
init_membership(state) = AND(
    DictContains(?state, "members", 0)
)
"#;

/// An invite pod represents an invitation to join the membership list.
/// It must be "signed" by a public key in the admin set.
///
/// invite(state, invite_pk, private: admin_pk, admin_sk) = AND(
///     PkOf(admin_pk, admin_sk) // NOTE: could use signature here
///     Contains(state["admins"], ?admin_pk)
/// )
/// TODO: PublicKeyOf is broken ...
pub const INVITE: &str = r#"
invite(state, invite, private: admin_arr, admin_sk, admin_pk) = AND(
    DictContains(?state, "admins", ?admin_arr)
    SetContains(?admin_arr, ?admin_pk)
    SignedBy(?invite, ?admin_pk)
    PublicKeyOf(?admin_pk, ?admin_sk)
)
"#;

/// To accept the invitation, the invited user creates an accept_invite pod which they sign.
///
/// accept_invite(state, invite_pk, private: invite_sk) = AND(
///     invite(state, invite_pk)
///     PkOf(invite_pk, invite_sk)
/// )
/// TODO: PublicKeyOf is broken ...
/// I made "invite" private here since it is signed by an admin, which could reveal
/// the public key
pub const ACCEPT_INVITE: &str = r#"
accept_invite(state, invite_pk, private: invite) = AND(
    invite(?state, ?invite)
    DictContains(?invite, "invite", ?invite_pk)
)
"#;

/// Update the membership state to include a new member.
/// Given an accept_invite pod, it ensures the new_state was updated to include the new member.
///
/// update_state(old_state, new_state, private: old_member_list, new_member_list) = AND(
///     accept_invite(?old_state, ?invite_pk)
///     SetInsert(?new_member_set, ?old_member_set, ?invite_pk)
///     DictUpdate(?new_state, ?old_state, "members", ?new_member_set, ?old_member_set)
/// )
/// TODO: container updates are not handled by the solver yet
pub const UPDATE_STATE: &str = r#"
update_state(old_state, new_state, old_member_set, new_member_set, private: invite_pk) = AND(
    accept_invite(?old_state, ?invite_pk)
    SetInsert(?new_member_set, ?old_member_set, ?invite_pk)
    DictContains(?old_state, "members", ?old_member_set)
    //DictUpdate(?new_state, ?old_state, "members", ?new_member_set)
)
"#;

/// Complete membership predicate set combining all individual predicates
pub fn membership_predicates() -> String {
    format!(
        "{}\n{}\n{}\n{}",
        INIT_MEMBERSHIP, INVITE, ACCEPT_INVITE, UPDATE_STATE
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_predicates_are_valid_strings() {
        assert!(!INIT_MEMBERSHIP.is_empty());
        assert!(!INVITE.is_empty());
        assert!(!ACCEPT_INVITE.is_empty());
        assert!(!UPDATE_STATE.is_empty());
        assert!(!membership_predicates().is_empty());
    }

    #[test]
    fn test_predicates_contain_expected_keywords() {
        assert!(INIT_MEMBERSHIP.contains("init_membership"));

        assert!(INVITE.contains("invite"));
        assert!(INVITE.contains("Contains"));

        assert!(ACCEPT_INVITE.contains("accept_invite"));

        assert!(UPDATE_STATE.contains("update_state"));
        assert!(UPDATE_STATE.contains("SetInsert"));
        assert!(UPDATE_STATE.contains("DictUpdate"));
    }

    #[test]
    fn test_membership_predicates_function() {
        let all_predicates = membership_predicates();
        assert!(all_predicates.contains("init_membership"));
        assert!(all_predicates.contains("invite"));
        assert!(all_predicates.contains("accept_invite"));
        assert!(all_predicates.contains("update_state"));
    }
}
