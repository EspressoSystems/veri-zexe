//! APIs for proof generations and verifications

use crate::{
    errors::DPCApiError,
    types::{InnerPairingEngine, InnerUniversalParam, OuterPairingEngine, OuterUniversalParam},
};
use ark_std::rand::{CryptoRng, RngCore};
use jf_plonk::proof_system::PlonkKzgSnark;

pub(crate) mod policies_vfy;
pub(crate) mod predicates;
pub(crate) mod transaction;
pub(crate) mod utxo;

/// One-time universal setup for parameters to be used in proving utxo relation
/// and inner predicate proofs
#[allow(dead_code)] // TODO make it public or create upper layer api
pub fn universal_setup_inner<R: RngCore + CryptoRng>(
    max_degree: usize,
    rng: &mut R,
) -> Result<InnerUniversalParam, DPCApiError> {
    // either pass degree upperbound as an input parameter
    // or directly access a fixed constant
    PlonkKzgSnark::<InnerPairingEngine>::universal_setup(max_degree, rng)
        .map_err(DPCApiError::FailedSnark)
}

/// One-time universal setup for parameters to be used in the outer circuit that
/// recursively verifies inner policy proofs.
#[allow(dead_code)] // TODO make it public or create upper layer api
pub fn universal_setup_outer<R: RngCore + CryptoRng>(
    max_degree: usize,
    rng: &mut R,
) -> Result<OuterUniversalParam, DPCApiError> {
    // either pass degree upperbound as an input parameter
    // or directly access a fixed constant
    PlonkKzgSnark::<OuterPairingEngine>::universal_setup(max_degree, rng)
        .map_err(DPCApiError::FailedSnark)
}
