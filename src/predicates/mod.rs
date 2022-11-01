// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the VeriZexe library.

// This program is free software: you can redistribute it and/or modify it under
// the terms of the GNU General Public License as published by the Free Software
// Foundation, either version 3 of the License, or (at your option) any later
// version. This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
// details. You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>.

//! This module defines interfaces for a Predicate module.

use crate::{errors::DPCApiError, types::InnerUniversalParam};

/// Predicate trait
pub trait PredicateTrait
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

    // TODO: (alex) make this trait generic over field and PredicateCircuit:
    // Circuit<F> in order to have generic default implementation.

    /// Get the number of constraints in the underlying `PredicateCircuit`
    fn num_constraints(&self) -> usize;

    /// Return a pointer to the verification key
    fn verifying_key(&self) -> &Self::VerificationKey;

    /// Generate a new predicate given the following inputs:
    /// - the SRS
    /// - a dummy description of the circuit
    /// - an indicator whether this is a birth or death predicate
    /// Output the predicate or an error
    fn new(
        srs: &InnerUniversalParam,
        circuit: &Self::PredicateCircuit,
        is_birth_predicate: bool,
    ) -> Result<Self, DPCApiError>;

    /// Update the witness of the predicate and finalize it.
    /// Used when the public input of the predicate changes.
    fn update_witness(&mut self, circuit: Self::PredicateCircuit) -> Result<(), DPCApiError>;
}
