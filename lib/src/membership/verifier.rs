use hex::ToHex;
use pod2::{
    frontend::MainPod,
    lang::parse,
    middleware::{CustomPredicateBatch, Hash, Params, PublicKey, TypedValue, Value},
};
use std::sync::Arc;
use tracing::debug;

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
}

impl MembershipVerifier {
    /// Create a new membership verifier
    pub fn new() -> Self {
        Self {
            params: Params::default(),
        }
    }

    /// Create a membership batch containing all predicates
    fn create_query_batch(&self) -> Result<Arc<CustomPredicateBatch>, VerificationError> {
        let query_batch_content = query_predicates();
        let query_batch = parse(&query_batch_content, &self.params, &[])
            .map_err(|e| VerificationError::InvalidProof(format!("Parse error: {:?}", e)))?
            .custom_batch;
        Ok(query_batch)
    }

    /// Create a membership batch containing all predicates
    fn create_membership_batch(&self) -> Result<Arc<CustomPredicateBatch>, VerificationError> {
        let query_batch = self.create_query_batch()?;
        let batch_content = membership_predicates(query_batch.clone());
        let batch = parse(&batch_content, &self.params, &[query_batch])
            .map_err(|e| VerificationError::InvalidProof(format!("Parse error: {:?}", e)))?
            .custom_batch;
        Ok(batch)
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

        let request = parse(&query, &self.params, std::slice::from_ref(&batch))
            .map_err(|e| VerificationError::InvalidProof(format!("Parse error: {:?}", e)))?
            .request;

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

        let request = parse(&query, &self.params, std::slice::from_ref(&batch))
            .map_err(|e| VerificationError::InvalidProof(format!("Parse error: {:?}", e)))?
            .request;

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

        let request = parse(&query, &self.params, std::slice::from_ref(&batch))
            .map_err(|e| VerificationError::InvalidProof(format!("Parse error: {:?}", e)))?
            .request;

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
        let batch = self.create_membership_batch()?;
        let old_state_value = expected_old_state.clone().to_pod_value();
        let new_state_value = expected_new_state.clone().to_pod_value();

        let query = format!(
            r#"
            use _, _, _, update_state from 0x{}

            REQUEST(
                update_state({}, {})
            )
            "#,
            batch.id().encode_hex::<String>(),
            old_state_value,
            new_state_value
        );

        debug!("Verification query: {}", query);

        let request = parse(&query, &self.params, std::slice::from_ref(&batch))
            .map_err(|e| VerificationError::InvalidProof(format!("Parse error: {:?}", e)))?
            .request;

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
