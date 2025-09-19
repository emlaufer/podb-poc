use hex::ToHex;
use pod2::{
    frontend::MainPod,
    lang::parse,
    middleware::{CustomPredicateBatch, Hash, Params, PublicKey, TypedValue, Value},
};
use std::sync::Arc;
use tracing::debug;

use crate::membership::predicates::Predicates;
use crate::membership::*;
use crate::utils::ToPodValue;

/// Error type for membership verification operations
#[derive(Debug)]
pub enum VerificationError {
    InvalidProof(String),
    InvalidState(String),
    VerificationFailed(String),
}

impl From<String> for VerificationError {
    fn from(s: String) -> Self {
        VerificationError::VerificationFailed(s)
    }
}

impl std::error::Error for VerificationError {}

impl std::fmt::Display for VerificationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VerificationError::InvalidProof(msg) => write!(f, "Invalid proof: {}", msg),
            VerificationError::InvalidState(msg) => write!(f, "Invalid state: {}", msg),
            VerificationError::VerificationFailed(msg) => write!(f, "Verification failed: {}", msg),
        }
    }
}

/// Main verifier for membership predicates
#[derive(Debug)]
pub struct MembershipVerifier {
    params: Params,
    predicates: Predicates,
}

impl MembershipVerifier {
    /// Create a new membership verifier
    pub fn new() -> Self {
        let params = Params::default();
        let predicates = Predicates::new(&params);
        Self { params, predicates }
    }

    /// Create a membership batch containing all predicates
    fn create_query_batch(&self) -> Result<Arc<CustomPredicateBatch>, VerificationError> {
        Ok(self.predicates.query.clone())
    }

    /// Create a membership batch containing all predicates
    fn create_membership_batch(&self) -> Result<Arc<CustomPredicateBatch>, VerificationError> {
        Ok(self.predicates.membership.clone())
    }

    /// Verify an init membership proof
    pub fn verify_init_membership(
        &self,
        proof: &MainPod,
        expected_state: &Hash,
    ) -> Result<bool, VerificationError> {
        let batch = self.create_membership_batch()?;
        let state_value = expected_state.clone().to_pod_value();

        let query = format!(
            r#"
            use init_membership, _, _, _ from 0x{}

            REQUEST(
                init_membership({})
            )
            "#,
            batch.id().encode_hex::<String>(),
            state_value,
        );

        debug!("Verification query: {}", query);

        let query_batch = &self.predicates.query;
        let request = parse(&query, &self.params, &[batch.clone(), query_batch.clone()])
            .map_err(|e| VerificationError::InvalidProof(format!("Parse error: {:?}", e)))?
            .request;

        proof.pod.verify().map_err(|e| {
            VerificationError::VerificationFailed(format!("Verification error: {:?}", e))
        })?;
        request.exact_match_pod(&*proof.pod).map_err(|e| {
            VerificationError::VerificationFailed(format!("Exact match error: {:?}", e))
        })?;

        Ok(true)
    }

    /// Verify an invite proof
    pub fn verify_invite(
        &self,
        proof: &MainPod,
        expected_state: &Hash,
        expected_invite_pk: PublicKey,
    ) -> Result<bool, VerificationError> {
        let batch = self.create_membership_batch()?;
        let state_value = expected_state.clone().to_pod_value();

        // Create signed invite dictionary value as expected
        let invite_dict_value = Value::new(TypedValue::Dictionary(
            pod2::middleware::containers::Dictionary::new(
                1,
                std::iter::once((
                    pod2::middleware::Key::from("invite"),
                    Value::new(TypedValue::PublicKey(expected_invite_pk)),
                ))
                .collect(),
            )
            .unwrap(),
        ));

        let query = format!(
            r#"
            use _, invite, _, _ from 0x{}

            REQUEST(
                invite({}, {})
            )
            "#,
            batch.id().encode_hex::<String>(),
            state_value,
            invite_dict_value
        );

        debug!("Verification query: {}", query);

        let query_batch = &self.predicates.query;
        let request = parse(&query, &self.params, &[batch.clone(), query_batch.clone()])
            .map_err(|e| VerificationError::InvalidProof(format!("Parse error: {:?}", e)))?
            .request;

        proof.pod.verify().map_err(|e| {
            VerificationError::VerificationFailed(format!("Verification error: {:?}", e))
        })?;
        request.exact_match_pod(&*proof.pod).map_err(|e| {
            VerificationError::VerificationFailed(format!("Exact match error: {:?}", e))
        })?;

        Ok(true)
    }

    /// Verify an accept invite proof
    pub fn verify_accept_invite(
        &self,
        proof: &MainPod,
        expected_state: &Hash,
        expected_invite_pk: PublicKey,
    ) -> Result<bool, VerificationError> {
        let batch = self.create_membership_batch()?;
        let state_value = expected_state.clone().to_pod_value();

        let query = format!(
            r#"
            use _, _, accept_invite, _ from 0x{}

            REQUEST(
                accept_invite({}, PublicKey({}))
            )
            "#,
            batch.id().encode_hex::<String>(),
            state_value,
            expected_invite_pk
        );

        debug!("Verification query: {}", query);

        let query_batch = &self.predicates.query;
        let request = parse(&query, &self.params, &[batch.clone(), query_batch.clone()])
            .map_err(|e| VerificationError::InvalidProof(format!("Parse error: {:?}", e)))?
            .request;

        proof.pod.verify().map_err(|e| {
            VerificationError::VerificationFailed(format!("Verification error: {:?}", e))
        })?;
        request.exact_match_pod(&*proof.pod).map_err(|e| {
            VerificationError::VerificationFailed(format!("Exact match error: {:?}", e))
        })?;

        Ok(true)
    }

    /// Verify an update state proof
    pub fn verify_update_state(
        &self,
        proof: &MainPod,
        expected_old_state: &Hash,
        expected_new_state: &Hash,
    ) -> Result<bool, VerificationError> {
        let state_batch = self.predicates.state.clone();
        let old_state_value = expected_old_state.clone().to_pod_value();
        let new_state_value = expected_new_state.clone().to_pod_value();

        let query = format!(
            r#"
            use _, update_state from 0x{}

            REQUEST(
                update_state({}, {})
            )
            "#,
            state_batch.id().encode_hex::<String>(),
            old_state_value,
            new_state_value
        );

        debug!("Verification query: {}", query);

        let query_batch = &self.predicates.query;
        let request = parse(
            &query,
            &self.params,
            &[state_batch.clone(), query_batch.clone()],
        )
        .map_err(|e| VerificationError::InvalidProof(format!("Parse error: {:?}", e)))?
        .request;

        proof.pod.verify().map_err(|e| {
            VerificationError::VerificationFailed(format!("Verification error: {:?}", e))
        })?;
        request.exact_match_pod(&*proof.pod).map_err(|e| {
            VerificationError::VerificationFailed(format!("Exact match error: {:?}", e))
        })?;

        Ok(true)
    }
}

impl Default for MembershipVerifier {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verification_errors() {
        let error = VerificationError::InvalidProof("test".to_string());
        assert!(format!("{}", error).contains("Invalid proof"));

        let error = VerificationError::InvalidState("test".to_string());
        assert!(format!("{}", error).contains("Invalid state"));

        let error = VerificationError::VerificationFailed("test".to_string());
        assert!(format!("{}", error).contains("Verification failed"));
    }
}
