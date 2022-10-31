// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the VeriZexe library.

// This program is free software: you can redistribute it and/or modify it under
// the terms of the GNU General Public License as published by the Free Software
// Foundation, either version 3 of the License, or (at your option) any later
// version. This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
// details. You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>.

//! This module implements a variant of AltZcash style private transaction
//! protocol, where one may transfer  tokens through a private transaction, for
//! a transaction less than 2^13 value.
//!
//! In this example, we first properly define our customized Application which
//! is a combination of predicates and circuits
//! (which are simple wrappers of `Predicate` and `PredicateCircuit`).
//! This requires implementation of the following traits
//! - TypeACircuit
//! - TypeBCircuit
//! - PredicateOps
//!
//! Once the application is built, we take the following steps to generate a
//! proof:
//! * Sample inner and outer circuit SRS
//!
//! * PredicateOps::preprocess(): upon receiving the SRSs and number of
//! inputs, it generates
//!     - dpc proving key
//!     - dpc verification key
//!     - birth predicate
//!     - policy id for birth predicate
//!     - death predicate
//!     - policy id for death predicate
//!
//! * build the notes and records for transaction
//!     - a valid fee note (valid = exist in merkle tree)
//!     - a list of valid input notes (valid = exist in merkle tree)
//!     - a fee change record
//!     - a list of output records
//! and build corresponding witnesses for this transaction
//!
//! * generate a dpc proof that consists of three components
//!     - an UTXO proof proves that both fee note and input notes are valid
//!       w.r.t. the given merkle root
//!     - a birth/death predicates proof that proves both predicates are
//!       satisfied w.r.t. the public/private inputs
//!     - a policies verification proof that proves the knowledge of predicates
//!       satisfaction.
//!
//! The first and third proofs are common in all DPC applications.
//! Application may vary in the second proof, which, in our case,
//! argues for the following knowledge
//!
//! - a death predicate that checks:
//!     - the values are correctly committed via the `common_local_data`
//!     - the sum of input values is less than 2^13
//!
//! - a birth predicate that checks:
//!     - the values are correctly committed via the `common_local_data`
//!     - the sum of input records' value matches the sum of output records'
//!       value
//!     - all input/output records shares a same asset id
//!     - the associated death pid is permitted (not implemented)
//!
//! Note that the birth predicate is identical for all three examples; and is
//! implemented via the default implementation.
//! So here we only need to write the logic for the death predicate.

use super::{PredicateOps, TypeACircuit, TypeBCircuit};
use crate::{
    circuit::{
        local_data::local_data_commitment_circuit,
        structs::{NoteInputVar, RecordOpeningVar},
    },
    constants::MEMO_LEN,
    errors::DPCApiError,
    predicates::PredicateTrait,
    proofs::{
        predicates::{Predicate, PredicateCircuit},
        transaction::{DPCProvingKey, DPCVerifyingKey},
    },
    structs::{NoteInput, PolicyIdentifier, RecordOpening},
    types::{InnerScalarField, InnerUniversalParam, OuterUniversalParam},
};
use ark_std::vec::Vec;
use jf_relation::{Arithmetization, Circuit, MergeableCircuitType, PlonkCircuit};

// A simple wrapper of predicate circuit
struct AltZcashPredicateCircuit(PredicateCircuit);

impl From<PredicateCircuit> for AltZcashPredicateCircuit {
    fn from(circuit: PredicateCircuit) -> Self {
        Self(circuit)
    }
}

// A simple wrapper of predicate
struct AltZcashPredicate(Predicate);

impl From<Predicate> for AltZcashPredicate {
    fn from(predicate: Predicate) -> Self {
        Self(predicate)
    }
}

// Using the default birth predicate circuit to argue
// 1. all asset_ids match
// 2. sum inputs = sum outputs
// 3. all the inputs are correctly w.r.t. commitment
impl TypeACircuit for AltZcashPredicateCircuit {
    // Our code requires that #gates in a birth circuit to be greater
    // than that of a death circuit. If birth circuit has smaller size,
    // we need to pad the birth circuit to make it larger.
    //
    // Our death circuit performs an extra range check which will
    // not exceed 1024 constraints
    const PAD_GATES: usize = 1024;
}

// Extra, application dependent logics are defined in this circuit.
impl TypeBCircuit for AltZcashPredicateCircuit {
    // we want to check:
    //  - it uses a same local data commitment as the birth predicate
    //  - the sum of input values is less than 2^13
    fn gen_death_circuit_core(
        entire_input_notes: &[NoteInput],
        entire_output_records: &[RecordOpening],
        memo: &[InnerScalarField; MEMO_LEN],
        blinding_local_data: InnerScalarField,
        comm_local_data: InnerScalarField,
    ) -> Result<Self, DPCApiError> {
        let mut death_circuit = PlonkCircuit::new_turbo_plonk();

        // build all the variables
        let comm_local_data_var = death_circuit.create_public_variable(comm_local_data)?;
        let blinding_local_data_var = death_circuit.create_variable(blinding_local_data)?;

        let entire_input_notes_vars = entire_input_notes
            .iter()
            .map(|x| NoteInputVar::new(&mut death_circuit, x))
            .collect::<Result<Vec<_>, _>>()?;
        let entire_outputs_vars = entire_output_records
            .iter()
            .map(|x| RecordOpeningVar::new(&mut death_circuit, x))
            .collect::<Result<Vec<_>, _>>()?;
        let memo_vars = memo
            .iter()
            .map(|x| death_circuit.create_variable(*x))
            .collect::<Result<Vec<_>, _>>()?;

        // argue that the local data is correct w.r.t. to the commitment of local data
        local_data_commitment_circuit(
            &mut death_circuit,
            &entire_input_notes_vars,
            &entire_outputs_vars,
            &memo_vars,
            &blinding_local_data_var,
            &comm_local_data_var,
        )?;

        // argue that the sum is less than 2^13
        let mut sum_input_var = entire_input_notes_vars[1].record_opening_var.payload.data[1];
        for note in entire_input_notes_vars.iter().skip(2) {
            sum_input_var =
                death_circuit.add(sum_input_var, note.record_opening_var.payload.data[1])?;
        }
        death_circuit.is_in_range(sum_input_var, 13)?;

        // pad the death circuit with dummy gates
        let current_gate_count = death_circuit.num_gates();
        let target_gate_count = Self::preprocessed_birth_circuit(entire_input_notes.len())?
            .0
             .0
            .num_gates();

        death_circuit.pad_gates(target_gate_count - current_gate_count);

        Ok(AltZcashPredicateCircuit(PredicateCircuit(death_circuit)))
    }
}

impl<'a> PredicateOps<'a> for AltZcashPredicate {
    /// Setup the circuit and related parameters
    ///
    /// Inputs:
    /// - rng
    /// - inner SRS
    /// - outer SRS
    /// - total number of inputs (including fee record)
    ///
    /// Outputs:
    /// - DPC proving key
    /// - DPC verification key
    /// - Birth predicate (with dummy local commitment)
    /// - Birth predicate PIDs
    /// - Death predicate (with dummy local commitment)
    /// - Death predicate PIDs
    fn preprocess(
        inner_srs: &'a InnerUniversalParam,
        outer_srs: &'a OuterUniversalParam,
        entire_input_size: usize,
    ) -> Result<
        (
            DPCProvingKey,
            DPCVerifyingKey,
            Self,
            PolicyIdentifier,
            Self,
            PolicyIdentifier,
        ),
        DPCApiError,
    > {
        // setup the dummy circuit/predicate/pid
        let mut birth_predicate_circuit =
            AltZcashPredicateCircuit::preprocessed_birth_circuit(entire_input_size)?;
        let death_predicate_circuit =
            AltZcashPredicateCircuit::preprocessed_death_circuit(entire_input_size)?;
        let birth_predicate = Predicate::new(inner_srs, &birth_predicate_circuit.0, true)?;
        let death_predicate = Predicate::new(inner_srs, &death_predicate_circuit.0, false)?;
        let birth_pid = PolicyIdentifier::from_verifying_key(birth_predicate.verifying_key());
        let death_pid = PolicyIdentifier::from_verifying_key(death_predicate.verifying_key());

        birth_predicate_circuit
            .0
             .0
            .finalize_for_mergeable_circuit(MergeableCircuitType::TypeA)?;

        // the inner domain size is the birth (or death) circuit's domain size
        let inner_domain_size = birth_predicate_circuit.0 .0.eval_domain_size()?;

        let (dpc_pk, dpc_vk, (..)) = crate::proofs::transaction::preprocess(
            outer_srs,
            inner_srs,
            entire_input_size - 1,
            inner_domain_size,
        )?;
        Ok((
            dpc_pk,
            dpc_vk,
            Self::from(birth_predicate),
            birth_pid,
            Self::from(death_predicate),
            death_pid,
        ))
    }

    /// Finalize a predicate circuit.
    ///
    /// This function will need to be called to prepare
    /// the circuit for proof generation.
    /// When a predicate circuit was initialized, it does not have the
    /// correct commitment to the local data (and thus cannot generate)
    /// a correct proof.
    fn finalize_for_proving(
        &mut self,
        entire_input_notes: &[NoteInput],
        entire_output_records: &[RecordOpening],
        memo: &[InnerScalarField; MEMO_LEN],
        blinding_local_data: InnerScalarField,
        comm_local_data: InnerScalarField,
        is_birth_predicate: bool,
    ) -> Result<(), DPCApiError> {
        let mut final_circuit = if is_birth_predicate {
            AltZcashPredicateCircuit::gen_birth_circuit(
                entire_input_notes,
                entire_output_records,
                memo,
                blinding_local_data,
                comm_local_data,
            )?
        } else {
            AltZcashPredicateCircuit::gen_death_circuit(
                entire_input_notes,
                entire_output_records,
                memo,
                blinding_local_data,
                comm_local_data,
            )?
        };

        // sanity check: circuit is satisfied
        final_circuit
            .0
             .0
            .check_circuit_satisfiability(&[comm_local_data])?;

        // finalize the circuit, and update the witness accordingly

        let circuit_type = if is_birth_predicate {
            MergeableCircuitType::TypeA
        } else {
            MergeableCircuitType::TypeB
        };

        final_circuit
            .0
             .0
            .finalize_for_mergeable_circuit(circuit_type)?;
        self.0.update_witness(final_circuit.0)?;
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        constants::MEMO_LEN,
        errors::DPCApiError,
        examples::tests::{build_notes, build_notes_and_records},
        keys::KeyChainMasterKey,
        proofs::{transaction::*, universal_setup_inner, universal_setup_outer},
        structs::compress_local_data,
        types::InnerScalarField,
    };
    use ark_ff::{UniformRand, Zero};
    use ark_std::{rand::Rng, test_rng, vec};

    const NON_NATIVE_ASSET_ID: u64 = 2u64;

    #[test]
    #[ignore]
    fn test_alt_zcash_example_transaction() -> Result<(), DPCApiError> {
        // universal setup
        let rng = &mut test_rng();
        let max_inner_degree = (1 << 17) + 4;
        let inner_srs = universal_setup_inner(max_inner_degree, rng)?;
        let max_outer_degree = (1 << 18) + 4;
        let outer_srs = universal_setup_outer(max_outer_degree, rng)?;

        // good path: 2 inputs
        let fee_in = 300;
        let fee = 5;
        let fee_out = 295;
        let input_note_values = [10, 30];
        let output_note_values = [22, 18];

        assert!(test_example_transaction_helper(
            &inner_srs,
            &outer_srs,
            fee_in,
            fee,
            fee_out,
            input_note_values.as_ref(),
            output_note_values.as_ref(),
        )
        .is_ok());

        // good path: 4 inputs
        let fee_in = 300;
        let fee = 5;
        let fee_out = 295;
        let input_note_values = [10, 30, 60, 0];
        let output_note_values = [22, 33, 44, 1];

        assert!(test_example_transaction_helper(
            &inner_srs,
            &outer_srs,
            fee_in,
            fee,
            fee_out,
            input_note_values.as_ref(),
            output_note_values.as_ref(),
        )
        .is_ok());

        // bad path: transaction exceed 2^13

        let fee_in = 300;
        let fee = 5;
        let fee_out = 295;
        let input_note_values = [10, 30, 60, 8192];
        let output_note_values = [22, 33, 44, 8193];

        assert!(test_example_transaction_helper(
            &inner_srs,
            &outer_srs,
            fee_in,
            fee,
            fee_out,
            input_note_values.as_ref(),
            output_note_values.as_ref(),
        )
        .is_err());

        // bad path: input sum != output sum
        let fee_in = 300;
        let fee = 5;
        let fee_out = 295;
        let input_note_values = [10, 30, 60, 0];
        let output_note_values = [22, 33, 44, 81093];

        assert!(test_example_transaction_helper(
            &inner_srs,
            &outer_srs,
            fee_in,
            fee,
            fee_out,
            input_note_values.as_ref(),
            output_note_values.as_ref(),
        )
        .is_err());
        Ok(())
    }

    // TODO: use the consolidated API for testing
    fn test_example_transaction_helper(
        inner_srs: &InnerUniversalParam,
        outer_srs: &OuterUniversalParam,
        fee_in: u64,
        fee: u64,
        fee_out: u64,
        input_note_values: &[u64],
        output_note_values: &[u64],
    ) -> Result<(), DPCApiError> {
        let num_non_fee_inputs = input_note_values.len();
        assert_eq!(num_non_fee_inputs, output_note_values.len());

        let rng = &mut test_rng();

        let (dpc_pk, dpc_vk, mut birth_predicate, birth_pid, mut death_predicate, death_pid) =
            AltZcashPredicate::preprocess(&inner_srs, &outer_srs, num_non_fee_inputs + 1)?;

        // generate proof generation key and addresses
        let mut wsk = [0u8; 32];
        rng.fill(&mut wsk[..]);
        let msk = KeyChainMasterKey::generate(wsk, &[]);
        let (_, pgk, ivk) = msk.derive_key_chain_single_consumer();
        let (addr, rd) = msk.derive_diversified_address(&pgk, &ivk, 0)?;

        // =================================
        // setup transaction parameters
        // we have four types of records:
        // - native token transaction fee note
        // - native token transaction fee change note
        // - AltZcash input notes
        // - AltZcash output notes
        // =================================
        let (entire_input_records, entire_output_records) = build_notes_and_records(
            rng,
            &addr,
            &pgk,
            fee_in,
            fee_out,
            NON_NATIVE_ASSET_ID,
            &input_note_values,
            &output_note_values,
            birth_pid,
            death_pid,
        )?;

        let entire_input_notes = build_notes(&entire_input_records, &pgk, &rd)?;

        // prepare memo
        let dummy_memo = [InnerScalarField::zero(); MEMO_LEN];

        // update the predicates to use the correct witness circuit that matches the
        // correct local data commitment
        let compressed_local_data = compress_local_data(
            &entire_input_notes,
            &entire_output_records,
            dummy_memo.to_vec(),
        )?;

        // =================================
        // proof generation
        // =================================
        let blinding_local_data = InnerScalarField::rand(rng);
        let comm_local_data = compressed_local_data.commit(blinding_local_data)?;

        birth_predicate.finalize_for_proving(
            &entire_input_notes,
            &entire_output_records,
            &dummy_memo,
            blinding_local_data,
            comm_local_data,
            true,
        )?;
        death_predicate.finalize_for_proving(
            &entire_input_notes,
            &entire_output_records,
            &dummy_memo,
            blinding_local_data,
            comm_local_data,
            false,
        )?;

        let input_death_predicates = vec![death_predicate.0; num_non_fee_inputs];
        let output_birth_predicates = vec![birth_predicate.0; num_non_fee_inputs];

        let witness = DPCWitness::new_unchecked(
            rng,
            entire_input_notes,
            entire_output_records,
            &input_death_predicates,
            &output_birth_predicates,
            blinding_local_data,
        )?;

        let pub_input = DPCPublicInput::from_witness(
            &witness,
            fee as u64,
            dummy_memo.to_vec(),
            inner_srs.powers_of_g[1],
        )?;

        // generate the proof and verify it
        let dpc_proof = prove(rng, &dpc_pk, &witness, &pub_input)?;
        verify(&dpc_proof, &dpc_vk, &pub_input)
    }
}
