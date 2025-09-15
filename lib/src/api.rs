use pod2::frontend::MainPod;
use pod2::middleware::{PublicKey, Hash};
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