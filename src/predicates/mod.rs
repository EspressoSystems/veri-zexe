//! This module defines interfaces for a Predicate module.

use crate::{errors::DPCApiError, types::InnerUniversalParam};

/// Predicate trait
pub trait PredicateTrait<'a>
where
    Self: Sized,
{
    /// the actual, unwrapped predicate.
    type PlonkPredicate;

    /// the circuit corresponding to this predicate
    type PredicateCircuit;

    /// Proving key
    type ProvingKey;

    /// Verification key
    type VerificationKey;

    /// Proof for predicate satisfaction
    type Proof;

    /// Blinding factor
    type BlindFactor;

    /// Get the actual, unwrapped predicate.
    fn predicate(&self) -> Self::PlonkPredicate;

    /// Return a pointer to the verification key
    fn verifying_key(&self) -> &Self::VerificationKey;

    /// Generate a new predicate given the following inputs:
    /// - the SRS
    /// - a dummy description of the circuit
    /// - an indicator whether this is a birth or death predicate
    /// Output the predicate or an error
    fn new(
        srs: &'a InnerUniversalParam,
        circuit: &Self::PredicateCircuit,
        is_birth_predicate: bool,
    ) -> Result<Self, DPCApiError>;

    /// Update the witness of the predicate and finalize it.
    /// Used when the public input of the predicate changes.
    fn update_witness(&mut self, circuit: Self::PredicateCircuit) -> Result<(), DPCApiError>;
}
