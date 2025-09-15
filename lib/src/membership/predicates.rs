//! PODLang predicates for membership management system
//!
//! This module defines predicates for managing membership in a system with:
//! - Admin-controlled invitations
//! - Member acceptance flow
//! - State updates with membership changes

use hex::ToHex;
use pod2::middleware::CustomPredicateBatch;
use std::sync::Arc;

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

pub const IS_ADMIN: &str = r#"
is_admin(state, admin_pk, private: admin_arr) = AND(
    DictContains(?state, "admins", ?admin_arr)
    SetContains(?admin_arr, ?admin_pk)
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
invite(state, invite, private: admin_sk, admin_pk) = AND(
    is_admin(?state, ?admin_pk)
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
update_state(old_state, new_state, private: invite_pk, old_member_set, new_member_set) = AND(
    accept_invite(?old_state, ?invite_pk)
    SetInsert(?new_member_set, ?old_member_set, ?invite_pk)
    DictContains(?old_state, "members", ?old_member_set)
    DictUpdate(?new_state, ?old_state, "members", ?new_member_set)
)
"#;

pub const QUERY_PREDICATES: &str = r#"
is_admin(state, admin_pk, private: admin_set) = AND(
    DictContains(?state, "admins", ?admin_set)
    SetContains(?admin_set, ?admin_pk)
)
"#;

/// Complete membership predicate set combining all individual predicates
pub fn membership_predicates(query_batch: Arc<CustomPredicateBatch>) -> String {
    format!(
        r#"
use is_admin from 0x{}

init_membership(state) = AND(
    DictContains(?state, "members", 0)
)

invite(state, invite_pk, private: admin_sk, admin_pk) = AND(
    is_admin(?state, ?admin_pk)
    PublicKeyOf(?admin_pk, ?admin_sk)
    // annoying - need this to bind invite_pk arg to correct value
    Equal(?invite_pk, ?invite_pk) 
)

accept_invite(state, invite_pk, private: admin_pk, invite_sk) = AND(
    invite(?state, ?invite_pk)
    PublicKeyOf(?invite_pk, ?invite_sk)
)

update_state(old_state, new_state, private: invite_pk, old_member_set, new_member_set) = AND(
    accept_invite(?old_state, ?invite_pk)
    SetInsert(?new_member_set, ?old_member_set, ?invite_pk)
    DictContains(?old_state, "members", ?old_member_set)
    DictUpdate(?new_state, ?old_state, "members", ?new_member_set)
)
"#,
        query_batch.id().encode_hex::<String>()
    )
}

/// Query predicates for membership system
pub fn query_predicates() -> &'static str {
    QUERY_PREDICATES
}
