// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the VeriZexe library.

// This program is free software: you can redistribute it and/or modify it under
// the terms of the GNU General Public License as published by the Free Software
// Foundation, either version 3 of the License, or (at your option) any later
// version. This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
// details. You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>.

//! This module implements a few examples with predicates.

mod restricted_zcash_example;
mod tornado_cash_example;
pub(crate) mod zcash_example;

use crate::{
    circuit::{
        local_data::local_data_commitment_circuit,
        structs::{NoteInputVar, RecordOpeningVar},
    },
    constants::MEMO_LEN,
    errors::DPCApiError,
    keys::ProofGenerationKey,
    proofs::{
        predicates::{Predicate, PredicateCircuit},
        transaction::{DPCProvingKey, DPCVerifyingKey},
    },
    structs::{NoteInput, PolicyIdentifier, RecordOpening},
    types::{InnerScalarField, InnerUniversalParam, OuterUniversalParam},
};
use ark_std::{format, vec, vec::Vec, Zero};
use jf_relation::{Circuit, PlonkCircuit};

/// A birth predicate that is shared among all example applications.
pub(crate) trait TypeACircuit
where
    Self: Sized + From<PredicateCircuit>,
{
    // Our code requires that #gates in a birth circuit to be greater
    // than that of a death circuit. If birth circuit has a smaller size,
    // we need to pad the birth circuit to make it larger.
    const PAD_GATES: usize;

    /// This internal logic will prove that
    /// 1. all the inputs are correctly w.r.t. commitment
    /// 2. all asset_ids match
    /// 3. sum inputs = sum outputs
    fn gen_birth_circuit_core(
        entire_input_notes: &[NoteInput],
        entire_output_records: &[RecordOpening],
        memo: &[InnerScalarField; MEMO_LEN],
        blinding_local_data: InnerScalarField,
        comm_local_data: InnerScalarField,
    ) -> Result<Self, DPCApiError> {
        let mut birth_circuit = PlonkCircuit::new_turbo_plonk();

        // build all the variables
        let comm_local_data_var = birth_circuit.create_public_variable(comm_local_data)?;
        let blinding_local_data_var = birth_circuit.create_variable(blinding_local_data)?;

        let entire_input_notes_vars = entire_input_notes
            .iter()
            .map(|x| NoteInputVar::new(&mut birth_circuit, x))
            .collect::<Result<Vec<_>, _>>()?;
        let entire_outputs_vars = entire_output_records
            .iter()
            .map(|x| RecordOpeningVar::new(&mut birth_circuit, x))
            .collect::<Result<Vec<_>, _>>()?;
        let memo_vars = memo
            .iter()
            .map(|x| birth_circuit.create_variable(*x))
            .collect::<Result<Vec<_>, _>>()?;

        // 1. argue that the local data is correct w.r.t. to the commitment of local
        // data
        local_data_commitment_circuit(
            &mut birth_circuit,
            &entire_input_notes_vars,
            &entire_outputs_vars,
            &memo_vars,
            &blinding_local_data_var,
            &comm_local_data_var,
        )?;

        // 2. all asset_ids match; asset_id is encoded in the first byte of payload
        let asset_id = entire_input_notes_vars[1].record_opening_var.payload.data[0];
        for note in entire_input_notes_vars.iter().skip(2) {
            birth_circuit.enforce_equal(asset_id, note.record_opening_var.payload.data[0])?;
        }
        for record in entire_outputs_vars.iter().skip(1) {
            birth_circuit.enforce_equal(asset_id, record.payload.data[0])?;
        }

        // 3. sum inputs = sum outputs
        let mut sum_input_var = entire_input_notes_vars[0].record_opening_var.payload.data[1];
        for note in entire_input_notes_vars.iter().skip(1) {
            sum_input_var =
                birth_circuit.add(sum_input_var, note.record_opening_var.payload.data[1])?;
        }
        let mut sum_output_var = entire_outputs_vars[0].payload.data[1];
        for record in entire_outputs_vars.iter().skip(1) {
            sum_output_var = birth_circuit.add(sum_output_var, record.payload.data[1])?;
        }
        birth_circuit.enforce_equal(sum_input_var, sum_output_var)?;

        // pad the birth circuit with dummy gates so that it will always be greater
        // than the supported death ones
        birth_circuit.pad_gates(Self::PAD_GATES);

        Ok(Self::from(PredicateCircuit(birth_circuit)))
    }

    /// build a preprocessed birth circuit
    fn preprocessed_birth_circuit(entire_input_size: usize) -> Result<Self, DPCApiError> {
        let proof_gen_key = ProofGenerationKey::default();

        let dummy_blinding_local_data = InnerScalarField::default();
        let dummy_comm_local_data = InnerScalarField::default();
        let dummy_input_notes = vec![NoteInput::dummy(&proof_gen_key); entire_input_size];
        let dummy_output_records = vec![RecordOpening::dummy(); entire_input_size];
        let dummy_memo = [InnerScalarField::zero(); MEMO_LEN];

        Self::gen_birth_circuit_core(
            &dummy_input_notes,
            &dummy_output_records,
            &dummy_memo,
            dummy_blinding_local_data,
            dummy_comm_local_data,
        )
    }

    /// Build a birth circuit with real data.
    /// Inputs:
    /// - entire input notes
    /// - entire output records
    /// - local data blinding factor
    /// - local data commitment
    /// - allowed policy identifiers
    ///
    /// Note that native token fee related proofs are handled via UTXO circuits.
    ///
    /// For both input note and output records, the data payload is
    /// a fixed `PAYLOAD_DATA_LEN` length of array,
    /// formatted as `[ asset_id | asset_value | 0 | ... 0 ]`
    fn gen_birth_circuit(
        entire_input_notes: &[NoteInput],
        entire_output_records: &[RecordOpening],
        memo: &[InnerScalarField; MEMO_LEN],
        blinding_local_data: InnerScalarField,
        comm_local_data: InnerScalarField,
    ) -> Result<Self, DPCApiError> {
        if entire_input_notes.len() != entire_output_records.len() {
            return Err(DPCApiError::GeneralError(format!(
                "Input length ({}) does not match output length ({})",
                entire_input_notes.len(),
                entire_output_records.len()
            )));
        }
        Self::gen_birth_circuit_core(
            entire_input_notes,
            entire_output_records,
            memo,
            blinding_local_data,
            comm_local_data,
        )
    }
}

/// A death predicate that may vary among example applications.
pub(crate) trait TypeBCircuit
where
    Self: Sized + From<PredicateCircuit> + TypeACircuit,
{
    /// Internal function that generates the actual circuit for the
    /// customized statements.
    fn gen_death_circuit_core(
        entire_input_notes: &[NoteInput],
        entire_output_records: &[RecordOpening],
        memo: &[InnerScalarField; MEMO_LEN],
        blinding_local_data: InnerScalarField,
        comm_local_data: InnerScalarField,
    ) -> Result<Self, DPCApiError>;

    /// build a dummy death circuit
    fn preprocessed_death_circuit(entire_input_size: usize) -> Result<Self, DPCApiError> {
        let proof_gen_key = ProofGenerationKey::default();

        let dummy_blinding_local_data = InnerScalarField::default();
        let dummy_comm_local_data = InnerScalarField::default();
        let dummy_input_notes = vec![NoteInput::dummy(&proof_gen_key); entire_input_size];
        let dummy_output_records = vec![RecordOpening::dummy(); entire_input_size];
        let dummy_memo = [InnerScalarField::zero(); MEMO_LEN];

        Self::gen_death_circuit_core(
            &dummy_input_notes,
            &dummy_output_records,
            &dummy_memo,
            dummy_blinding_local_data,
            dummy_comm_local_data,
        )
    }

    /// Build a birth circuit with real data.
    /// Inputs:
    /// - entire input notes
    /// - entire output records
    /// - local data blinding factor
    /// - local data commitment
    ///
    /// Note that native token fee related proofs are handled via UTXO circuits.
    ///
    /// For both input note and output records, the data payload is
    /// a fixed `PAYLOAD_DATA_LEN` length of array,
    /// formatted as `[ asset_id | asset_value | 0 | ... 0 ]`
    fn gen_death_circuit(
        entire_input_notes: &[NoteInput],
        entire_output_records: &[RecordOpening],
        memo: &[InnerScalarField; MEMO_LEN],
        blinding_local_data: InnerScalarField,
        comm_local_data: InnerScalarField,
    ) -> Result<Self, DPCApiError> {
        Self::gen_death_circuit_core(
            entire_input_notes,
            entire_output_records,
            memo,
            blinding_local_data,
            comm_local_data,
        )
    }
}

pub(crate) trait PredicateOps<'a>
where
    Self: Sized + From<Predicate>,
{
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
    >;

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
    ) -> Result<(), DPCApiError>;
}

#[cfg(test)]
pub(crate) mod tests {
    use crate::{
        constants::TREE_DEPTH,
        errors::DPCApiError,
        keys::{DiversifiedAddress, DiversifierRandomizer, ProofGenerationKey},
        structs::{NoteInput, Nullifier, Payload, PolicyIdentifier, RecordOpening},
        types::InnerScalarField,
    };
    use ark_ff::Zero;
    use ark_std::{
        rand::{CryptoRng, RngCore},
        vec,
        vec::Vec,
    };
    use jf_primitives::merkle_tree::{AccMemberWitness, MerkleTree};

    pub(crate) fn build_notes_and_records<R: RngCore + CryptoRng>(
        rng: &mut R,
        addr: &DiversifiedAddress,
        pgk: &ProofGenerationKey,
        asset_id: u64,
        input_values: &[u64],
        output_values: &[u64],
        birth_pid: PolicyIdentifier,
        death_pid: PolicyIdentifier,
    ) -> Result<(Vec<RecordOpening>, Vec<RecordOpening>), DPCApiError> {
        // input records
        let mut inputs = vec![];
        for (i, &value) in input_values.iter().enumerate() {
            let input_payload = Payload::from_scalars(&[
                InnerScalarField::from(asset_id),
                InnerScalarField::from(value),
            ])?;

            let input_ro = RecordOpening::new(
                rng,
                addr.clone(),
                input_payload,
                InnerScalarField::zero(),
                death_pid.0,
                i,
                Nullifier::default(),
            );

            inputs.push(input_ro);
        }
        let first_nf = inputs[0].nullify(&pgk.nk)?;

        // output records
        let mut outputs = vec![];
        for (i, &value) in output_values.iter().enumerate() {
            let input_payload = Payload::from_scalars(&[
                InnerScalarField::from(asset_id),
                InnerScalarField::from(value),
            ])?;

            let output_ro = RecordOpening::new(
                rng,
                addr.clone(),
                input_payload,
                birth_pid.0,
                InnerScalarField::zero(),
                i,
                first_nf.clone(),
            );

            outputs.push(output_ro);
        }

        Ok((inputs, outputs))
    }

    pub(crate) fn build_notes<'a>(
        entire_input_records: &[RecordOpening],
        pgk: &'a ProofGenerationKey,
        rd: &DiversifierRandomizer,
    ) -> Result<Vec<NoteInput<'a>>, DPCApiError> {
        // initialize the simulated merkle tree
        let mut merkle_tree = MerkleTree::new(TREE_DEPTH).unwrap();
        for input_record in entire_input_records.iter() {
            let input_rc = input_record.derive_record_commitment()?;
            merkle_tree.push(input_rc);
        }

        // build the input notes
        let mut input_notes = vec![];
        for (i, record) in entire_input_records.iter().enumerate() {
            let (_, mt_witness) = AccMemberWitness::lookup_from_tree(&merkle_tree, i as u64)
                .expect_ok()
                .unwrap();
            let input_note = NoteInput {
                ro: record.clone(),
                acc_member_witness: mt_witness,
                proof_gen_key: &pgk,
                authorization_randomizer: Default::default(),
                diversifier_randomizer: rd.clone(),
            };
            input_notes.push(input_note);
        }
        Ok(input_notes)
    }
}
