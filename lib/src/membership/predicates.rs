//! PODLang predicates for membership management system
//!
//! This module defines predicates for managing membership in a system with:
//! - Admin-controlled invitations
//! - Member acceptance flow
//! - State updates with membership changes

use hex::ToHex;
use pod2::lang::parse;
use pod2::middleware::{CustomPredicateBatch, Params};
use std::sync::Arc;

#[derive(Debug)]
pub struct Predicates {
    pub state: Arc<CustomPredicateBatch>,
    pub membership: Arc<CustomPredicateBatch>,
    pub post: Arc<CustomPredicateBatch>,
    pub query: Arc<CustomPredicateBatch>,
    pub index: Arc<CustomPredicateBatch>,
}

impl Predicates {
    pub fn new(params: &Params) -> Predicates {
        let query_batch_content = query_predicates();
        let query_batch = parse(&query_batch_content, params, &[])
            .unwrap()
            .custom_batch;

        let membership_batch_content = membership_predicates(query_batch.clone());
        let membership_batch = parse(&membership_batch_content, params, &[query_batch.clone()])
            .unwrap()
            .custom_batch;

        let post_batch_content = post_predicates(query_batch.clone());
        let post_batch = parse(&post_batch_content, params, &[query_batch.clone()])
            .unwrap()
            .custom_batch;

        let state_batch_content = state_predicates(membership_batch.clone(), post_batch.clone());
        let state_batch = parse(
            &state_batch_content,
            params,
            &[membership_batch.clone(), post_batch.clone()],
        )
        .unwrap()
        .custom_batch;

        let index_batch_content = index_predicates(membership_batch.clone(), post_batch.clone());
        let index_batch = parse(
            &index_batch_content,
            params,
            &[membership_batch.clone(), post_batch.clone()],
        )
        .unwrap()
        .custom_batch;

        Self {
            state: state_batch,
            membership: membership_batch,
            post: post_batch,
            query: query_batch,
            index: index_batch,
        }
    }
}

pub fn state_predicates(
    membership_batch: Arc<CustomPredicateBatch>,
    post_batch: Arc<CustomPredicateBatch>,
) -> String {
    format!(
        r#"
use _, _, _, add_member from 0x{}
use _, add_post from 0x{}

init_state(state) = AND(
    DictContains(state, "members", 0)
    DictContains(state, "posts", 0)
)

update_state(old_state, new_state, private: post) = OR(
    add_member(old_state, new_state)
    add_post(old_state, new_state, post)
)"#,
        membership_batch.id().encode_hex::<String>(),
        post_batch.id().encode_hex::<String>(),
    )
}

/// Complete membership predicate set combining all individual predicates
pub fn membership_predicates(query_batch: Arc<CustomPredicateBatch>) -> String {
    format!(
        r#"
use is_admin, _, _ from 0x{}

init_membership(state) = AND(
    DictContains(state, "members", 0)
    DictContains(state, "posts", 0)
)

invite(state, invite_pk, private: admin_sk, admin_pk) = AND(
    is_admin(state, admin_pk)
    PublicKeyOf(admin_pk, admin_sk)
    // annoying - need this to bind invite_pk arg to correct value
    Equal(invite_pk, invite_pk) 
)

accept_invite(state, invite_pk, private: admin_pk, invite_sk) = AND(
    invite(state, invite_pk)
    PublicKeyOf(invite_pk, invite_sk)
)

add_member(old_state, new_state, private: invite_pk, old_member_set, new_member_set) = AND(
    accept_invite(old_state, invite_pk)
    SetInsert(new_member_set, old_member_set, invite_pk)
    DictContains(old_state, "members", old_member_set)
    DictUpdate(new_state, old_state, "members", new_member_set)
)
"#,
        query_batch.id().encode_hex::<String>()
    )
}

/// Complete membership predicate set combining all individual predicates
pub fn post_predicates(query_batch: Arc<CustomPredicateBatch>) -> String {
    format!(
        r#"
use _, is_member, _ from 0x{}

// I split this from add_post to avoid going over the custom statement arity limit
valid_post(state, post, private: author_pk) = AND(
    DictContains(post, "author", author_pk)
    SignedBy(post, author_pk)
    is_member(state, author_pk) 
)

add_post(old_state, new_state, post, private: old_posts, new_posts) = AND(
    valid_post(old_state, post)
    SetInsert(new_posts, old_posts, post)
    DictContains(old_state, "posts", old_posts)
    DictUpdate(new_state, old_state, "posts", new_posts)
)
"#,
        query_batch.id().encode_hex::<String>()
    )
}

/// Query predicates for membership system
pub fn query_predicates() -> &'static str {
    r#"
is_admin(state, admin_pk, private: admin_set) = AND(
    DictContains(state, "admins", admin_set)
    SetContains(admin_set, admin_pk)
)

is_member(state, member_pk, private: member_set) = AND(
    DictContains(state, "members", member_set)
    SetContains(member_set, member_pk)
)

is_not_member(state, member_pk, private: member_set) = AND(
    DictContains(state, "members", member_set)
    SetNotContains(member_set, member_pk)
)
"#
}

pub fn index_predicates(
    member_batch: Arc<CustomPredicateBatch>,
    post_batch: Arc<CustomPredicateBatch>,
) -> String {
    format!(
        r#"
use _, _, _, add_member from 0x{}
use _, add_post from 0x{}

update_posts_index(old_index, new_index, new_state, old_state) = OR(
    index_add_post(old_index, new_index, old_state, new_state)
    index_add_member(old_index, new_index, old_state, new_state)
)

index_add_post(old_index, new_index, old_state, new_state, private: post, new_user_set, old_user_set) = AND(
    SetInsert(new_user_set, old_user_set, post)
    DictContains(old_index, post["author_name"], old_user_set)
    DictUpdate(new_index, old_index, post["author_name"], post)
    add_post(old_state, new_state, post)
)

index_add_member(old_index, new_index, new_state, old_state) = AND(
    Equal(new_index, old_index)
    add_member(old_state, new_state)
)
"#,
        member_batch.id().encode_hex::<String>(),
        post_batch.id().encode_hex::<String>()
    )
}
