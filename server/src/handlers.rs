use axum::{extract::State, response::Json};
use lib::api::{
    AcceptInviteRequest, AcceptInviteResponse, IsAdminProofRequest, IsAdminProofResponse,
    StateCommitmentResponse,
};
use lib::membership::{MembershipError, MembershipProver, MembershipState, MembershipVerifier};
use pod2::frontend::MainPod;
use pod2::middleware::PublicKey;
use serde::Serialize;
use serde_json::{Value, json};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{error, info, instrument};

#[derive(Debug)]
pub struct MembershipService {
    current_state: MembershipState,
    prover: MembershipProver,
    verifier: MembershipVerifier,
}

impl MembershipService {
    pub fn new() -> Self {
        Self {
            current_state: MembershipState::default(),
            prover: MembershipProver::new(),
            verifier: MembershipVerifier::new(),
        }
    }

    pub fn new_with_initial_admins(initial_admins: Vec<PublicKey>) -> Self {
        let mut initial_state = MembershipState::default();
        for admin in initial_admins {
            initial_state.add_admin(admin);
        }

        Self {
            current_state: initial_state,
            prover: MembershipProver::new(),
            verifier: MembershipVerifier::new(),
        }
    }

    pub fn accept_invite(
        &mut self,
        accept_invite_pod: &MainPod,
        new_member: PublicKey,
    ) -> Result<(MainPod, pod2::middleware::Hash, pod2::middleware::Hash), MembershipError> {
        // First verify the accept_invite proof
        match self.verifier.verify_accept_invite(
            accept_invite_pod,
            &self.current_state.commitment(),
            new_member,
        ) {
            Ok(true) => info!("Successfully verified accept_invite proof"),
            Ok(false) => {
                return Err(MembershipError::ProofError(
                    "Accept invite verification failed".to_string(),
                ));
            }
            Err(e) => {
                return Err(MembershipError::ProofError(format!(
                    "Accept invite verification error: {:?}",
                    e
                )));
            }
        }

        // Get old state commitment
        let old_state_commitment = self.current_state.commitment();

        // Create new state with added member
        let mut new_state = self.current_state.clone();
        new_state.add_member(new_member);
        let new_state_commitment = new_state.commitment();

        // Generate update proof
        let update_proof =
            self.prover
                .prove_update_state(&self.current_state, &new_state, accept_invite_pod)?;

        // Update current state
        self.current_state = new_state;

        Ok((update_proof, old_state_commitment, new_state_commitment))
    }

    pub fn prove_is_admin(&self, public_key: PublicKey) -> Result<MainPod, MembershipError> {
        self.prover.prove_is_admin(&self.current_state, public_key)
    }

    pub fn current_state(&self) -> &MembershipState {
        &self.current_state
    }
}

pub type SharedState = Arc<RwLock<MembershipService>>;

#[derive(Debug, Serialize)]
pub enum MembershipServerError {
    InvalidPod(String),
    ProofGenerationFailed(String),
}

impl From<MembershipError> for MembershipServerError {
    fn from(error: MembershipError) -> Self {
        match error {
            MembershipError::ParseError(msg) => MembershipServerError::InvalidPod(msg),
            MembershipError::SolverError(msg) => MembershipServerError::ProofGenerationFailed(msg),
            MembershipError::ProofError(msg) => MembershipServerError::ProofGenerationFailed(msg),
        }
    }
}

#[instrument]
pub async fn accept_invite(
    State(state): State<SharedState>,
    Json(request): Json<AcceptInviteRequest>,
) -> Result<Json<AcceptInviteResponse>, Json<MembershipServerError>> {
    info!("Accept invite request received");

    let mut service = state.write().await;
    match service.accept_invite(&request.accept_invite_pod, request.new_member_public_key) {
        Ok((update_proof, old_state_commitment, new_state_commitment)) => {
            let member_count = service.current_state().members.len();
            info!(
                "Successfully processed invite, new member count: {}",
                member_count
            );

            Ok(Json(AcceptInviteResponse {
                update_proof,
                old_state_commitment,
                new_state_commitment,
                new_member_count: member_count,
                success: true,
            }))
        }
        Err(err) => {
            error!("Failed to process invite: {:?}", err);
            Err(Json(MembershipServerError::from(err)))
        }
    }
}

#[instrument]
pub async fn prove_is_admin(
    State(state): State<SharedState>,
    Json(request): Json<IsAdminProofRequest>,
) -> Result<Json<IsAdminProofResponse>, Json<MembershipServerError>> {
    info!("Is admin proof request received");

    let service = state.read().await;
    match service.prove_is_admin(request.public_key) {
        Ok(is_admin_proof) => {
            info!("Successfully generated is_admin proof");
            Ok(Json(IsAdminProofResponse {
                is_admin_proof,
                success: true,
            }))
        }
        Err(err) => {
            error!("Failed to generate is_admin proof: {:?}", err);
            Err(Json(MembershipServerError::from(err)))
        }
    }
}

#[instrument]
pub async fn get_membership_state_commitment(
    State(state): State<SharedState>,
) -> Json<StateCommitmentResponse> {
    info!("Membership state commitment request received");

    let service = state.read().await;
    let current_state = service.current_state();

    let response = StateCommitmentResponse {
        state_commitment: current_state.commitment(),
        member_count: current_state.members.len(),
    };

    info!(
        "Returning state commitment with {} members",
        response.member_count
    );

    Json(response)
}

#[instrument]
pub async fn hello() -> Json<Value> {
    info!("Health check endpoint accessed");
    Json(json!({ "message": "Hello from PODB server!" }))
}
