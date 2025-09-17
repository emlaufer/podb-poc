use axum::{extract::State, response::Json};
use lib::api::{
    AcceptInviteRequest, AcceptInviteResponse, IsAdminProofRequest, IsAdminProofResponse,
    PublicLogEntry, StateCommitmentResponse,
};
use lib::membership::{MembershipError, MembershipProver, MembershipState, MembershipVerifier};
use lib::public_log::PublicLog;
use pod2::frontend::MainPod;
use pod2::middleware::PublicKey;
use serde::Serialize;
use serde_json::{Value, json};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use tracing::{error, info, instrument};

#[derive(Debug)]
pub struct MembershipService {
    current_state: MembershipState,
    prover: MembershipProver,
    verifier: MembershipVerifier,
    public_log: PublicLog,
}

impl MembershipService {
    pub fn new() -> Self {
        Self {
            current_state: MembershipState::default(),
            prover: MembershipProver::new(),
            verifier: MembershipVerifier::new(),
            public_log: PublicLog::new(),
        }
    }

    pub fn new_with_initial_admins(
        initial_admins: Vec<PublicKey>,
    ) -> Result<Self, MembershipError> {
        let mut initial_state = MembershipState::default();
        for admin in initial_admins {
            initial_state.add_admin(admin);
        }

        let mut service = Self {
            current_state: initial_state,
            prover: MembershipProver::new(),
            verifier: MembershipVerifier::new(),
            public_log: PublicLog::new(),
        };

        // Generate and publish init_membership proof
        service.init_membership()?;

        Ok(service)
    }

    fn init_membership(&mut self) -> Result<(), MembershipError> {
        // Generate init_membership proof
        let init_proof = self.prover.prove_init_membership(&self.current_state)?;
        let state_commitment = self.current_state.commitment();

        // Publish to public log
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let log_entry = PublicLogEntry::InitMembership {
            state_commitment,
            proof: init_proof,
            timestamp,
        };

        if let Err(e) = self.public_log.post(&log_entry) {
            error!("Failed to publish init_membership to public log: {}", e);
        } else {
            info!("Published init_membership to public log");
        }

        Ok(())
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
        update_proof.pod.verify();

        // Update current state
        self.current_state = new_state;

        // Publish to public log
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let log_entry = PublicLogEntry::UpdateState {
            old_state_commitment,
            new_state_commitment,
            proof: update_proof.clone(),
            timestamp,
        };

        if let Err(e) = self.public_log.post(&log_entry) {
            error!("Failed to publish update_state to public log: {}", e);
        } else {
            info!("Published update_state to public log");
        }

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
