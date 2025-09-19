use crate::membership::Post;
use pod2::frontend::MainPod;
use pod2::middleware::{Hash, PublicKey, Signature};
use serde::{Deserialize, Serialize};

/// Request to accept an invite
#[derive(Debug, Deserialize, Serialize)]
pub struct AcceptInviteRequest {
    pub accept_invite_pod: MainPod,
    pub new_member_public_key: PublicKey,
}

/// Response from accepting an invite
#[derive(Debug, Deserialize, Serialize)]
pub struct AcceptInviteResponse {
    pub update_proof: MainPod,
    pub old_state_commitment: Hash,
    pub new_state_commitment: Hash,
    pub new_member_count: usize,
    pub success: bool,
}

/// Response containing just state commitment (for privacy)
#[derive(Debug, Deserialize, Serialize)]
pub struct StateCommitmentResponse {
    pub state_commitment: Hash,
    pub member_count: usize,
}

/// Request to generate an is_admin proof
#[derive(Debug, Deserialize, Serialize)]
pub struct IsAdminProofRequest {
    pub public_key: PublicKey,
}

/// Response containing is_admin proof
#[derive(Debug, Deserialize, Serialize)]
pub struct IsAdminProofResponse {
    pub is_admin_proof: MainPod,
    pub success: bool,
}

/// Request to add a new post
#[derive(Debug, Deserialize, Serialize)]
pub struct AddPostRequest {
    pub post: Post,
    pub author_public_key: PublicKey,
    pub signature: Signature,
}

/// Response from adding a post
#[derive(Debug, Deserialize, Serialize)]
pub struct AddPostResponse {
    pub update_proof: MainPod,
    pub old_state_commitment: Hash,
    pub new_state_commitment: Hash,
    pub total_posts: usize,
    pub success: bool,
}

/// Public log entry for membership events
#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "type")]
pub enum PublicLogEntry {
    #[serde(rename = "init_membership")]
    InitMembership {
        state_commitment: Hash,
        proof: MainPod,
        timestamp: u64,
    },
    #[serde(rename = "update_state")]
    UpdateState {
        old_state_commitment: Hash,
        new_state_commitment: Hash,
        proof: MainPod,
        timestamp: u64,
    },
}
