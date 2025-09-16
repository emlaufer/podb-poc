//! PODLang predicates for membership management system
//!
//! This module defines predicates for managing membership in a system with:
//! - Admin-controlled invitations
//! - Member acceptance flow
//! - State updates with membership changes

use hex::ToHex;
use pod2::middleware::CustomPredicateBatch;
use std::sync::Arc;
pub const QUERY_PREDICATES: &str = r#"
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
    r#"
is_admin(state, admin_pk, private: admin_set) = AND(
    DictContains(?state, "admins", ?admin_set)
    SetContains(?admin_set, ?admin_pk)
)"#
}
