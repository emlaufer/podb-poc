use axum::{extract::State, response::Json};
use lib::membership::{MembershipError, MembershipProver, MembershipState};
use pod2::frontend::MainPod;
use pod2::middleware::PublicKey;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{error, info, instrument};

#[derive(Debug)]
pub struct MembershipService {
    current_state: MembershipState,
    prover: MembershipProver,
}

impl MembershipService {
    pub fn new() -> Self {
        Self {
            current_state: MembershipState::default(),
            prover: MembershipProver::new(),
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
        }
    }

    pub fn accept_invite(
        &mut self,
        accept_invite_pod: &MainPod,
        new_member: PublicKey,
    ) -> Result<MainPod, MembershipError> {
        // Create new state with added member
        let mut new_state = self.current_state.clone();
        new_state.add_member(new_member);

        // Generate update proof
        let update_proof =
            self.prover
                .prove_update_state(&self.current_state, &new_state, accept_invite_pod)?;

        // Update current state
        self.current_state = new_state;

        Ok(update_proof)
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
    StateUpdateFailed(String),
    InternalError(String),
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

#[derive(Debug, Deserialize)]
pub struct AcceptInviteRequest {
    pub accept_invite_pod: MainPod,
    pub new_member_public_key: PublicKey,
}

#[derive(Serialize)]
pub struct AcceptInviteResponse {
    pub update_proof: MainPod,
    pub new_member_count: usize,
    pub success: bool,
}

#[derive(Serialize)]
pub struct MembershipStateResponse {
    pub admins: Vec<PublicKey>,
    pub members: Vec<PublicKey>,
    pub admin_count: usize,
    pub member_count: usize,
}

#[instrument]
pub async fn accept_invite(
    State(state): State<SharedState>,
    Json(request): Json<AcceptInviteRequest>,
) -> Result<Json<AcceptInviteResponse>, Json<MembershipServerError>> {
    info!("Accept invite request received");

    let mut service = state.write().await;
    match service.accept_invite(&request.accept_invite_pod, request.new_member_public_key) {
        Ok(update_proof) => {
            let member_count = service.current_state().members.len();
            info!(
                "Successfully processed invite, new member count: {}",
                member_count
            );

            Ok(Json(AcceptInviteResponse {
                update_proof,
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
pub async fn get_membership_state(
    State(state): State<SharedState>,
) -> Json<MembershipStateResponse> {
    info!("Membership state request received");
    
    let service = state.read().await;
    let current_state = service.current_state();
    
    let response = MembershipStateResponse {
        admins: current_state.admins.clone(),
        members: current_state.members.clone(),
        admin_count: current_state.admins.len(),
        member_count: current_state.members.len(),
    };
    
    info!(
        "Returning membership state: {} admins, {} members",
        response.admin_count, response.member_count
    );
    
    Json(response)
}

#[instrument]
pub async fn hello() -> Json<Value> {
    info!("Health check endpoint accessed");
    Json(json!({ "message": "Hello from PODB server!" }))
}
