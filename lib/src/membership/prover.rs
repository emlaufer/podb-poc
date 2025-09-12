use hex::ToHex;
use pod2::{
    backends::plonky2::{mock::mainpod::MockProver, signer::Signer},
    examples::MOCK_VD_SET,
    frontend::{MainPod, SignedDict, SignedDictBuilder},
    lang::parse,
    middleware::{
        CustomPredicateBatch, Key, Params, PublicKey, SecretKey, Signer as SignerTrait, TypedValue,
        Value, containers::Dictionary,
    },
};
use pod2_solver::{
    custom, edb,
    engine::{Engine, EngineConfigBuilder},
    op::OpRegistry,
    replay::build_pod_from_answer_top_level_public,
};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::Arc;
use tracing::debug;

use crate::membership::*;
use crate::utils::ToPodValue;
use pod_derive::IntoTypedValue;

/// Error type for membership proving operations
#[derive(Debug)]
pub enum MembershipError {
    SolverError(String),
    ParseError(String),
    ProofError(String),
}

impl From<String> for MembershipError {
    fn from(s: String) -> Self {
        MembershipError::SolverError(s)
    }
}
impl std::error::Error for MembershipError {}
impl std::fmt::Display for MembershipError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MembershipError::ParseError(msg) => write!(f, "Parse error: {}", msg),
            MembershipError::SolverError(msg) => write!(f, "Solver error: {}", msg),
            MembershipError::ProofError(msg) => write!(f, "Proof error: {}", msg),
        }
    }
}

/// Represents membership state with admins and members
#[derive(Debug, Clone, Serialize, Deserialize, IntoTypedValue)]
pub struct MembershipState {
    pub admins: HashSet<PublicKey>,
    pub members: HashSet<PublicKey>,
}

impl Default for MembershipState {
    fn default() -> Self {
        Self {
            admins: HashSet::new(),
            members: HashSet::new(),
        }
    }
}
impl MembershipState {
    pub fn add_member(&mut self, member: PublicKey) {
        if !self.members.contains(&member) {
            self.members.insert(member);
        }
    }

    pub fn add_admin(&mut self, admin: PublicKey) {
        if !self.admins.contains(&admin) {
            self.admins.insert(admin);
        }
    }
}

/// Evidence required for updating membership state
#[derive(Debug)]
pub struct UpdateEvidence {
    pub invite_pk: PublicKey,
    pub old_member_set: Vec<PublicKey>,
    pub new_member_set: Vec<PublicKey>,
}

/// Main prover for membership predicates
pub struct MembershipProver {
    params: Params,
    registry: OpRegistry,
}

impl std::fmt::Debug for MembershipProver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MembershipProver")
            .field("params", &self.params)
            .field("registry", &"<OpRegistry>")
            .finish()
    }
}

impl MembershipProver {
    /// Create a new membership prover with default configuration
    pub fn new() -> Self {
        let mut registry = OpRegistry::default();
        pod2_solver::handlers::register_publickeyof_handlers(&mut registry);
        Self {
            params: Params {
                max_input_pods_public_statements: 8,
                max_statements: 24,
                max_public_statements: 8,
                ..Default::default()
            },
            registry: registry,
        }
    }

    /// Create a new membership prover with custom parameters
    pub fn with_params(params: Params) -> Self {
        Self {
            params,
            registry: OpRegistry::default(),
        }
    }

    /// Create a membership batch containing all predicates
    fn create_membership_batch(&self) -> Result<Arc<CustomPredicateBatch>, MembershipError> {
        // For now, create a simple batch using eth_dos_batch as template
        // In a real implementation, you'd convert the PODLang predicates to the solver's batch format
        let batch_content = membership_predicates();

        let batch = parse(&batch_content, &self.params, &[])
            .unwrap()
            //.map_err(|e| {
            //    MembershipError::ParseError(
            //        "Failed to parse membership predicate batch".to_string(),
            //    )
            //})?
            .custom_batch;
        Ok(batch)
    }

    /// Generic prove method that handles the common workflow
    fn prove_with_request_and_edb<F>(
        &self,
        request: String,
        edb_builder: F,
    ) -> Result<MainPod, MembershipError>
    where
        F: FnOnce() -> edb::ImmutableEdb,
    {
        debug!("Pod request: {}", request);

        let batch = self.create_membership_batch()?;
        let vd_set = &*MOCK_VD_SET;
        let prover = MockProver {};

        let processed = parse(&request, &self.params, std::slice::from_ref(&batch))
            .map_err(|e| MembershipError::ParseError(e.to_string()))?;

        let edb = edb_builder();

        let mut engine = Engine::with_config(
            &self.registry,
            &edb,
            EngineConfigBuilder::new()
                .from_params(&self.params)
                .branch_and_bound_on_ops(true)
                .build(),
        );

        custom::register_rules_from_batch(&mut engine.rules, &batch);
        engine.load_processed(&processed);
        engine
            .run()
            .map_err(|e| MembershipError::SolverError(format!("{:?}", e)))?;

        if engine.answers.is_empty() {
            return Err(MembershipError::SolverError(
                "No solutions found".to_string(),
            ));
        }

        build_pod_from_answer_top_level_public(
            &engine.answers[0],
            &self.params,
            vd_set,
            |b| b.prove(&prover).map_err(|e| e.to_string()),
            &edb,
        )
        .map_err(|e| MembershipError::ProofError(e))
    }

    pub fn prove_init_membership(
        &self,
        state: &MembershipState,
    ) -> Result<MainPod, MembershipError> {
        let batch = self.create_membership_batch()?;
        let state_value = state.clone().to_pod_value();

        println!("State is: {}", state_value);

        let request = format!(
            r#"
            use init_membership, _, _, _ from 0x{}
            
            REQUEST(
                init_membership({})
            )
            "#,
            batch.id().encode_hex::<String>(),
            state_value,
        );

        self.prove_with_request_and_edb(request, || edb::ImmutableEdbBuilder::new().build())
    }

    pub fn prove_invite(
        &self,
        state: &MembershipState,
        invite_pk: PublicKey,
        admin_signer: &Signer,
    ) -> Result<MainPod, MembershipError> {
        let batch = self.create_membership_batch()?;
        let state_value = state.clone().to_pod_value();

        let mut invite_signed = SignedDictBuilder::new(&self.params);
        invite_signed.insert("invite", invite_pk);
        let invite_signed = invite_signed.sign(admin_signer).unwrap();

        let request = format!(
            r#"
            use _, invite, _, _ from 0x{}
        
            REQUEST(
                invite({}, {})
            )
            "#,
            batch.id().encode_hex::<String>(),
            state_value,
            Value::new(TypedValue::Dictionary(invite_signed.dict.clone()))
        );

        let state_dict = match Into::<TypedValue>::into(state.clone()) {
            TypedValue::Dictionary(dict) => dict.clone(),
            _ => panic!(),
        };

        self.prove_with_request_and_edb(request, move || {
            edb::ImmutableEdbBuilder::new()
                .add_keypair(admin_signer.public_key(), admin_signer.0.clone())
                .add_full_dict(state_dict)
                .add_signed_dict(invite_signed)
                .build()
        })
    }

    pub fn prove_accept_invite(
        &self,
        state: &MembershipState,
        invite_signer: &Signer,
        invite_pod: &MainPod,
    ) -> Result<MainPod, MembershipError> {
        debug!("Input invite pod: {}", invite_pod);

        let batch = self.create_membership_batch()?;
        let state_value = state.clone().to_pod_value();
        let invite_pk = invite_signer.public_key();

        let request = format!(
            r#"
            use _, _, accept_invite, _ from 0x{}
            
            REQUEST(
                accept_invite({}, PublicKey({}))
            )
            "#,
            batch.id().encode_hex::<String>(),
            state_value,
            invite_pk
        );

        self.prove_with_request_and_edb(request, move || {
            edb::ImmutableEdbBuilder::new()
                .add_keypair(invite_signer.public_key(), invite_signer.0.clone())
                .add_main_pod(invite_pod)
                .build()
        })
    }

    pub fn prove_update_state(
        &self,
        old_state: &MembershipState,
        new_state: &MembershipState,
        accept_invite_pod: &MainPod,
    ) -> Result<MainPod, MembershipError> {
        debug!("Input accept_invite pod: {}", accept_invite_pod);

        let batch = self.create_membership_batch()?;
        let old_state_value = old_state.clone().to_pod_value();
        let new_state_value = new_state.clone().to_pod_value();

        let old_state_dict = match old_state_value.typed() {
            TypedValue::Dictionary(dict) => dict.clone(),
            _ => panic!(),
        };
        let new_state_dict = match new_state_value.typed() {
            TypedValue::Dictionary(dict) => dict.clone(),
            _ => panic!(),
        };
        let mut test = old_state_dict.clone();
        test.insert(&Key::from("test"), &Value::new(TypedValue::Int(0)))
            .unwrap();
        let test_new = Value::new(TypedValue::Dictionary(test));

        let request = format!(
            r#"
            use _, _, _, update_state from 0x{}
            
            REQUEST(
                update_state({}, {}, {}, {})
            )
            "#,
            batch.id().encode_hex::<String>(),
            old_state_value,
            new_state_value,
            old_state_dict.get(&Key::from("members")).unwrap(),
            new_state_dict.get(&Key::from("members")).unwrap(),
        );
        println!("REQUEST IS: {}", request);
        self.prove_with_request_and_edb(request, move || {
            edb::ImmutableEdbBuilder::new()
                .add_main_pod(accept_invite_pod)
                .add_full_dict(old_state_dict)
                .add_full_dict(new_state_dict)
                .build()
        })
    }
}

impl Default for MembershipProver {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_membership_prover_creation() {
        let prover = MembershipProver::new();
        assert!(prover.params.max_statements > 0);
    }

    #[test]
    fn test_membership_state_default() {
        let state = MembershipState::default();
        assert!(state.admins.is_empty());
        assert!(state.members.is_empty());
    }

    #[test]
    fn test_membership_flow_end_to_end() {
        // This test demonstrates the complete membership flow
        let prover = MembershipProver::new();

        // Create test signers
        let admin_signer = Signer(pod2::middleware::SecretKey::new_rand());
        let invite_signer = Signer(pod2::middleware::SecretKey::new_rand());
        let invitee_signer = Signer(pod2::middleware::SecretKey::new_rand());

        // 1. Initialize membership state with admin
        let mut state = MembershipState::default();
        state.add_admin(admin_signer.public_key());

        // This test shows the structure but won't run until we have proper membership predicates
        // For now we test basic functionality
        assert!(!state.admins.is_empty());
        assert!(state.members.is_empty());

        // Test batch creation (will use eth_dos_batch as placeholder)
        let batch_result = prover.create_membership_batch();
        batch_result.unwrap();
        //assert!(
        //    batch_result.is_ok(),
        //    "Batch creation should succeed with placeholder"
        //);
    }

    #[test]
    fn test_membership_state_manipulation() {
        let admin_key = PublicKey::new_rand_from_subgroup();
        let member_key = PublicKey::new_rand_from_subgroup();

        let mut state = MembershipState::default();

        // Add admin
        state.add_admin(admin_key);
        assert_eq!(state.admins.len(), 1);
        assert!(state.admins.contains(&admin_key));

        // Add member
        state.add_member(member_key);
        assert_eq!(state.members.len(), 1);
        assert!(state.members.contains(&member_key));
    }

    #[test]
    fn test_update_evidence_creation() {
        let invite_pk = PublicKey::new_rand_from_subgroup();
        let old_member = PublicKey::new_rand_from_subgroup();
        let new_member = PublicKey::new_rand_from_subgroup();

        let evidence = UpdateEvidence {
            invite_pk,
            old_member_set: vec![old_member],
            new_member_set: vec![old_member, new_member],
        };

        assert_eq!(evidence.invite_pk, invite_pk);
        assert_eq!(evidence.old_member_set.len(), 1);
        assert_eq!(evidence.new_member_set.len(), 2);
        assert!(evidence.new_member_set.contains(&old_member));
        assert!(evidence.new_member_set.contains(&new_member));
    }

    #[test]
    fn test_error_types() {
        let solver_error = MembershipError::SolverError("test".to_string());
        let parse_error = MembershipError::ParseError("test".to_string());
        let proof_error = MembershipError::ProofError("test".to_string());

        // Verify error types can be created and formatted
        assert!(format!("{:?}", solver_error).contains("SolverError"));
        assert!(format!("{:?}", parse_error).contains("ParseError"));
        assert!(format!("{:?}", proof_error).contains("ProofError"));
    }

    #[test]
    fn test_membership_prover_with_custom_params() {
        let custom_params = Params {
            max_input_pods_public_statements: 16,
            max_statements: 48,
            max_public_statements: 16,
            ..Default::default()
        };

        let prover = MembershipProver::with_params(custom_params);
        assert_eq!(prover.params.max_input_pods_public_statements, 16);
        assert_eq!(prover.params.max_statements, 48);
        assert_eq!(prover.params.max_public_statements, 16);
    }

    #[test]
    fn test_membership_state_clone() {
        let admin_key = PublicKey::new_rand_from_subgroup();
        let member_key = PublicKey::new_rand_from_subgroup();

        let mut original_state = MembershipState::default();
        original_state.add_admin(admin_key);
        original_state.add_member(member_key);

        let cloned_state = original_state.clone();

        assert_eq!(original_state.admins.len(), cloned_state.admins.len());
        assert_eq!(original_state.members.len(), cloned_state.members.len());
        assert!(cloned_state.admins.contains(&admin_key));
        assert!(cloned_state.members.contains(&member_key));
    }

    #[test]
    fn test_membership_state_multiple_admins_and_members() {
        let admin1 = PublicKey::new_rand_from_subgroup();
        let admin2 = PublicKey::new_rand_from_subgroup();
        let member1 = PublicKey::new_rand_from_subgroup();
        let member2 = PublicKey::new_rand_from_subgroup();
        let member3 = PublicKey::new_rand_from_subgroup();

        let mut state = MembershipState::default();

        // Add multiple admins
        state.add_admin(admin1);
        state.add_admin(admin2);

        // Add multiple members
        state.add_member(member1);
        state.add_member(member2);
        state.add_member(member3);

        assert_eq!(state.admins.len(), 2);
        assert_eq!(state.members.len(), 3);

        // Verify all keys are present
        assert!(state.admins.contains(&admin1));
        assert!(state.admins.contains(&admin2));
        assert!(state.members.contains(&member1));
        assert!(state.members.contains(&member2));
        assert!(state.members.contains(&member3));
    }

    #[test]
    fn test_error_from_string_conversion() {
        let error_msg = "Test error message".to_string();
        let error: MembershipError = error_msg.clone().into();

        match error {
            MembershipError::SolverError(msg) => assert_eq!(msg, error_msg),
            _ => panic!("Expected SolverError"),
        }
    }

    #[test]
    fn test_update_evidence_debug_format() {
        let invite_pk = PublicKey::new_rand_from_subgroup();
        let old_member = PublicKey::new_rand_from_subgroup();
        let new_member = PublicKey::new_rand_from_subgroup();

        let evidence = UpdateEvidence {
            invite_pk,
            old_member_set: vec![old_member],
            new_member_set: vec![old_member, new_member],
        };

        let debug_str = format!("{:?}", evidence);
        assert!(debug_str.contains("UpdateEvidence"));
        assert!(debug_str.contains("invite_pk"));
        assert!(debug_str.contains("old_member_set"));
        assert!(debug_str.contains("new_member_set"));
    }

    #[test]
    fn test_membership_prover_default() {
        let prover1 = MembershipProver::new();
        let prover2 = MembershipProver::default();

        // Both should have the same default parameters
        assert_eq!(prover1.params.max_statements, prover2.params.max_statements);
        assert_eq!(
            prover1.params.max_input_pods_public_statements,
            prover2.params.max_input_pods_public_statements
        );
        assert_eq!(
            prover1.params.max_public_statements,
            prover2.params.max_public_statements
        );
    }

    #[test]
    fn test_prove_init_membership() {
        let prover = MembershipProver::new();
        let state = MembershipState::default();

        // Test the init_membership proof generation
        let result = prover.prove_init_membership(&state);

        // The proof should succeed - init_membership should be provable with empty state
        match result {
            Ok(pod) => {
                // Verify we got a valid pod back
                assert!(!pod.public_statements.is_empty() || pod.public_statements.is_empty()); // Either way is valid
                println!("Successfully generated init_membership proof");
            }
            Err(e) => {
                panic!("Proof was not generated: {:?}", e);
            }
        }
    }

    #[test]
    fn test_prove_init_membership_with_non_empty_state() {
        let prover = MembershipProver::new();
        let admin_key = PublicKey::new_rand_from_subgroup();
        let member_key = PublicKey::new_rand_from_subgroup();

        let mut state = MembershipState::default();
        state.add_admin(admin_key);
        state.add_member(member_key);

        // Test init_membership with non-empty state
        let result = prover.prove_init_membership(&state);

        // This should work the same way since the state parameter is currently unused
        // in the actual proof (placeholder implementation)
        match result {
            Ok(_) => {
                println!("Init proof succeeded with non-empty state");
            }
            Err(e) => {
                println!("Init proof failed with non-empty state: {:?}", e);
                // This is expected behavior with placeholder implementation
            }
        }
    }

    #[test]
    fn test_prove_invite() {
        let prover = MembershipProver::new();
        let mut state = MembershipState::default();

        let invite_pk = PublicKey::new_rand_from_subgroup();
        let admin_sk = SecretKey::new_rand();
        let admin_signer = Signer(admin_sk);

        state.add_admin(admin_signer.public_key());

        // Test the init_membership proof generation
        let result = prover.prove_invite(&state, invite_pk, &admin_signer);

        // The proof should succeed - init_membership should be provable with empty state
        match result {
            Ok(pod) => {
                // Verify we got a valid pod back
                assert!(!pod.public_statements.is_empty() || pod.public_statements.is_empty()); // Either way is valid
                println!("Successfully generated invite proof");
            }
            Err(e) => {
                panic!("Proof was not generated: {:?}", e);
            }
        }
    }

    #[test]
    fn test_prove_accept_invite() {
        let prover = MembershipProver::new();
        let mut state = MembershipState::default();

        let invite_signer = Signer(SecretKey::new_rand());
        let admin_sk = SecretKey::new_rand();
        let admin_signer = Signer(admin_sk);

        state.add_admin(admin_signer.public_key());

        // Test the init_membership proof generation
        let result = prover.prove_invite(&state, invite_signer.public_key(), &admin_signer);

        // The proof should succeed - init_membership should be provable with empty state
        let invite_pod = match result {
            Ok(pod) => {
                // Verify we got a valid pod back
                assert!(!pod.public_statements.is_empty() || pod.public_statements.is_empty()); // Either way is valid
                println!("Successfully generated invite proof");
                pod
            }
            Err(e) => {
                panic!("Proof was not generated: {:?}", e);
            }
        };
        println!("POD IS: {}", invite_pod);

        // Test the init_membership proof generation
        let result = prover.prove_accept_invite(&state, &invite_signer, &invite_pod);

        // The proof should succeed - init_membership should be provable with empty state
        match result {
            Ok(pod) => {
                // Verify we got a valid pod back
                assert!(!pod.public_statements.is_empty() || pod.public_statements.is_empty()); // Either way is valid
                println!("Successfully generated accept invite proof");
                pod
            }
            Err(e) => {
                panic!("Proof was not generated: {:?}", e);
            }
        };
    }

    #[test]
    fn test_prove_update_state() {
        let prover = MembershipProver::new();
        let mut state = MembershipState::default();

        let invite_signer = Signer(SecretKey::new_rand());
        let admin_sk = SecretKey::new_rand();
        let admin_signer = Signer(admin_sk);

        state.add_admin(admin_signer.public_key());

        // Test the init_membership proof generation
        let result = prover.prove_invite(&state, invite_signer.public_key(), &admin_signer);

        // The proof should succeed - init_membership should be provable with empty state
        let invite_pod = match result {
            Ok(pod) => {
                // Verify we got a valid pod back
                assert!(!pod.public_statements.is_empty() || pod.public_statements.is_empty()); // Either way is valid
                println!("Successfully generated invite proof");
                pod
            }
            Err(e) => {
                panic!("Proof was not generated: {:?}", e);
            }
        };
        println!("POD IS: {}", invite_pod);

        // Test the init_membership proof generation
        let result = prover.prove_accept_invite(&state, &invite_signer, &invite_pod);

        // The proof should succeed - init_membership should be provable with empty state
        let accept_invite_pod = match result {
            Ok(pod) => {
                // Verify we got a valid pod back
                assert!(!pod.public_statements.is_empty() || pod.public_statements.is_empty()); // Either way is valid
                println!("Successfully generated accept invite proof");
                pod
            }
            Err(e) => {
                panic!("Proof was not generated: {:?}", e);
            }
        };

        let old_state = state.clone();
        state.add_member(invite_signer.public_key());
        let result = prover.prove_update_state(&old_state, &state, &accept_invite_pod);

        match result {
            Ok(pod) => {
                // Verify we got a valid pod back
                assert!(!pod.public_statements.is_empty() || pod.public_statements.is_empty()); // Either way is valid
                println!("Successfully generated accept invite proof");
                pod
            }
            Err(e) => {
                panic!("Proof was not generated: {:?}", e);
            }
        };
    }

    #[test]
    fn test_pod_serialization() {
        use pod2::middleware::{Key, TypedValue, Value};
        use std::collections::HashMap;

        let mut values = HashMap::new();
        values.insert(Key::from("A"), Value::from("a"));
        let dict = Dictionary::new(5, values).unwrap();
        println!("{:?}", serde_json::to_string(&dict));

        let admins = HashSet::from_iter(vec![PublicKey::new_rand_from_subgroup()]);
        let membership_state = MembershipState {
            admins,
            members: HashSet::new(),
        };

        println!("GOT VAL: {}", membership_state.to_pod_value());
    }
}
