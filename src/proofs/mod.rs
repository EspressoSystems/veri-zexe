// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the VeriZexe library.

// This program is free software: you can redistribute it and/or modify it under
// the terms of the GNU General Public License as published by the Free Software
// Foundation, either version 3 of the License, or (at your option) any later
// version. This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
// details. You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>.

//! APIs for proof generations and verifications

use crate::{
    errors::DPCApiError,
    types::{InnerPairingEngine, InnerUniversalParam, OuterPairingEngine, OuterUniversalParam},
};
use ark_std::rand::{CryptoRng, RngCore};
use jf_plonk::proof_system::PlonkKzgSnark;

pub(crate) mod policies_vfy;
pub(crate) mod predicates;
pub mod transaction;
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
