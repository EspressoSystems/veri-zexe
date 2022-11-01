// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the VeriZexe library.

// This program is free software: you can redistribute it and/or modify it under
// the terms of the GNU General Public License as published by the Free Software
// Foundation, either version 3 of the License, or (at your option) any later
// version. This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
// details. You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>.

use crate::{
    circuit::structs::{NoteInputVar, RecordOpeningVar},
    constants::MEMO_LEN,
    errors::DPCApiError,
    keys::KeyChainMasterKey,
    proofs::utxo::{DPCUtxoPublicInput, DPCUtxoWitness},
    types::{InnerEmbeddedGroup, InnerScalarField},
};
use ark_ff::Zero;
use ark_std::{format, vec, vec::Vec};
use jf_plonk::errors::PlonkError;
use jf_primitives::circuit::{
    commitment::CommitmentGadget,
    merkle_tree::{AccElemVars, MerkleTreeGadget},
    rescue::RescueGadget,
};
use jf_relation::{
    gadgets::ecc::{Point, PointVariable},
    BoolVar, Circuit, PlonkCircuit, Variable,
};

pub(crate) struct DPCUtxoWitnessVar {
    pub(crate) inputs: Vec<NoteInputVar>,
    pub(crate) output_records_openings: Vec<RecordOpeningVar>,
    pub(crate) blinding_local_data: Variable,
    pub(crate) blinding_predicates: Variable,
}

impl DPCUtxoWitnessVar {
    pub(crate) fn new(
        circuit: &mut PlonkCircuit<InnerScalarField>,
        witness: &DPCUtxoWitness,
    ) -> Result<Self, PlonkError> {
        let inputs = witness
            .entire_inputs
            .iter()
            .map(|input| NoteInputVar::new(circuit, input))
            .collect::<Result<Vec<_>, _>>()?;
        let output_records_openings = witness
            .entire_output_records_openings
            .iter()
            .map(|ro| RecordOpeningVar::new(circuit, ro))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(DPCUtxoWitnessVar {
            inputs,
            output_records_openings,
            blinding_local_data: circuit.create_variable(witness.blinding_local_data)?,
            blinding_predicates: circuit.create_variable(witness.blinding_predicates)?,
        })
    }
}

pub(crate) struct DPCUtxoPubInputVar {
    pub(crate) nullifiers: Vec<Variable>,
    pub(crate) output_commitments: Vec<Variable>,
    pub(crate) predicates_commitment: Variable,
    pub(crate) local_data_commitment: Variable,
    pub(crate) root: Variable,
    pub(crate) memo: Vec<Variable>,
    pub(crate) authorization_verification_key: PointVariable,
}

impl DPCUtxoPubInputVar {
    pub(crate) fn new(
        circuit: &mut PlonkCircuit<InnerScalarField>,
        public_input: &DPCUtxoPublicInput,
    ) -> Result<Self, PlonkError> {
        let nullifiers = public_input
            .input_nullifiers
            .iter()
            .map(|nullifier| circuit.create_public_variable(nullifier.0))
            .collect::<Result<Vec<_>, _>>()?;
        let output_commitments = public_input
            .output_commitments
            .iter()
            .map(|commitment| circuit.create_public_variable(*commitment))
            .collect::<Result<Vec<_>, _>>()?;
        let predicates_commitment =
            circuit.create_public_variable(public_input.commitment_predicates)?;
        let local_data_commitment =
            circuit.create_public_variable(public_input.commitment_local_data)?;
        let root = circuit.create_public_variable(public_input.root.to_scalar())?;
        let memo = public_input
            .memo
            .iter()
            .map(|memo_elem| circuit.create_public_variable(*memo_elem))
            .collect::<Result<Vec<_>, _>>()?;
        let auth_pk_point = Point::from(public_input.authorization_verification_key.to_affine());
        let authorization_verification_key = circuit.create_public_point_variable(auth_pk_point)?;
        Ok(DPCUtxoPubInputVar {
            nullifiers,
            output_commitments,
            predicates_commitment,
            local_data_commitment,
            root,
            memo,
            authorization_verification_key,
        })
    }
}

pub(crate) struct DPCUtxoCircuit(pub(crate) PlonkCircuit<InnerScalarField>);

impl DPCUtxoCircuit {
    /// Build a pre-processed circuit for `n_inputs` number of notes/records.
    pub(crate) fn build_for_preprocessing(n_inputs: usize) -> Result<Self, DPCApiError> {
        let memo = vec![InnerScalarField::zero(); MEMO_LEN];
        let wallet_key = [0u8; 32];
        let msk = KeyChainMasterKey::generate(wallet_key, &[]);
        let (_, pgk, _) = msk.derive_key_chain_single_consumer();
        let dummy_witness = DPCUtxoWitness::dummy(n_inputs, &pgk);
        let pub_input = DPCUtxoPublicInput::from_witness(&dummy_witness, memo)?;
        Self::build(&dummy_witness, &pub_input)
        .map_err(|_| DPCApiError::InternalError(format!(
                "Utxo Circuit Build for preprocessing unexpected error: Please report bug. Number of inputs {}",
                n_inputs
            )))
    }

    pub(crate) fn build(
        witness: &DPCUtxoWitness,
        public_input: &DPCUtxoPublicInput,
    ) -> Result<Self, PlonkError> {
        let mut circuit = PlonkCircuit::default();
        let witness_var = DPCUtxoWitnessVar::new(&mut circuit, witness)?;
        let public_input_var = DPCUtxoPubInputVar::new(&mut circuit, public_input)?;

        let mut compressed_local_data = vec![];
        let mut derived_authorization_key = circuit.neutral_point_variable();

        // check input
        for (input, input_nullifier) in witness_var
            .inputs
            .iter()
            .zip(public_input_var.nullifiers.iter())
        {
            let (record_commitment, rand_auth_key) =
                Self::prove_spend(&mut circuit, input, *input_nullifier, public_input_var.root)?;

            // update local data
            compressed_local_data.push(record_commitment);

            derived_authorization_key = circuit
                .ecc_add::<InnerEmbeddedGroup>(&derived_authorization_key, &rand_auth_key)?;
        }

        // check aggregated randomized verification key
        circuit.enforce_point_equal(
            &public_input_var.authorization_verification_key,
            &derived_authorization_key,
        )?;

        // check output
        for (i, (output_ro, output_rc)) in witness_var
            .output_records_openings
            .iter()
            .zip(public_input_var.output_commitments.iter())
            .enumerate()
        {
            Self::prove_output(
                &mut circuit,
                output_ro,
                *output_rc,
                i,
                public_input_var.nullifiers[0],
            )?;
            // update local data
            compressed_local_data.push(*output_rc);
        }

        // check compressed local data commitment
        {
            // append memo to local data
            // TODO: should we add fee to local data??
            compressed_local_data.extend(public_input_var.memo.iter());

            let derived_ldata_com =
                circuit.commit(&compressed_local_data, witness_var.blinding_local_data)?;
            circuit.enforce_equal(derived_ldata_com, public_input_var.local_data_commitment)?;
        }

        // check commitment predicates
        {
            let mut pids: Vec<_> = witness_var
                .inputs
                .iter()
                .map(|input| input.record_opening_var.pid_death)
                .collect();
            let output_pid_birth: Vec<_> = witness_var
                .output_records_openings
                .iter()
                .map(|ro| ro.pid_birth)
                .collect();
            pids.extend(output_pid_birth.iter());
            let derived_predicates_commitment =
                circuit.commit(&pids, witness_var.blinding_predicates)?;
            circuit.enforce_equal(
                derived_predicates_commitment,
                public_input_var.predicates_commitment,
            )?;
        }
        #[cfg(test)]
        {
            ark_std::println!(
                "ℹ️ num_constraint of (unpadded) UTXO circuit: {}",
                circuit.num_gates(),
            );
        }
        circuit.finalize_for_arithmetization()?;
        Ok(DPCUtxoCircuit(circuit))
    }

    fn prove_spend(
        circuit: &mut PlonkCircuit<InnerScalarField>,
        input: &NoteInputVar,
        public_nullifier: Variable,
        public_root: Variable,
    ) -> Result<(Variable, PointVariable), PlonkError> {
        circuit.enforce_bool(input.record_opening_var.payload.is_dummy)?;
        let is_dummy = input.record_opening_var.payload.is_dummy;
        // derive commitment
        let record_commitment = input
            .record_opening_var
            .derive_record_commitment_var(circuit)?;
        // compute root
        let derived_root = circuit.compute_merkle_root(
            AccElemVars {
                uid: input.acc_member_witness_var.uid,
                elem: record_commitment,
            },
            &input.acc_member_witness_var.merkle_path,
        )?;

        let is_in_acc = circuit.is_equal(derived_root, public_root)?;
        circuit.logic_or_gate(BoolVar(is_dummy), is_in_acc)?;

        // check correct nullifier
        let nullifier = input
            .record_opening_var
            .nullify(circuit, &input.proof_generation_key_var.nk)?;
        let correct_nullifier = circuit.is_equal(nullifier, public_nullifier)?;
        circuit.logic_or_gate(BoolVar(is_dummy), correct_nullifier)?;

        // compute randomized authorization key
        let rand_auth_key = circuit.ecc_add::<InnerEmbeddedGroup>(
            &input.proof_generation_key_var.ak.0,
            &input.authorization_randomizer_var,
        )?;

        // check diversifier
        let diversifier = input
            .proof_generation_key_var
            .derive_diversifier(circuit, input.diversifier_randomizer_var)?;
        let correct_diversifier = circuit.is_equal(diversifier, input.record_opening_var.addr.0)?;
        circuit.logic_or_gate(BoolVar(is_dummy), correct_diversifier)?;

        Ok((record_commitment, rand_auth_key))
    }

    fn prove_output(
        circuit: &mut PlonkCircuit<InnerScalarField>,
        output: &RecordOpeningVar,
        output_rc_var: Variable,
        position_in_note: usize,
        first_nullifier: Variable,
    ) -> Result<(), PlonkError> {
        // derive correct nonce
        let is_not_dummy = circuit.is_zero(output.payload.is_dummy)?;
        let is_dummy = circuit.logic_neg(is_not_dummy)?;
        let i_var = circuit.create_variable(InnerScalarField::from(position_in_note as u64))?;
        let msg = [i_var, first_nullifier, circuit.one()]; // add one as official padding
        let derived_nonce = circuit.rescue_sponge_no_padding(&msg, 1)?[0];
        let correct_nonce = circuit.is_equal(derived_nonce, output.nonce)?; // should I avoid this gate and replace output_ro.nonce with derived_nonce
        circuit.logic_or_gate(correct_nonce, is_dummy)?;
        let derived_output_rc = output.derive_record_commitment_var(circuit)?;
        let correct_rc = circuit.is_equal(derived_output_rc, output_rc_var)?;
        circuit.logic_or_gate(correct_rc, is_dummy)?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::{
        circuit::{
            structs::{NoteInputVar, RecordOpeningVar},
            utxo::DPCUtxoCircuit,
        },
        keys::KeyChainMasterKey,
        proofs::utxo::{DPCUtxoPublicInput, DPCUtxoWitness},
        structs::{NoteInput, Nullifier, Payload, RecordOpening},
        types::InnerScalarField,
    };
    use ark_ff::{One, UniformRand, Zero};
    use ark_std::{
        rand::{CryptoRng, Rng, RngCore},
        vec,
    };
    use jf_primitives::merkle_tree::{AccMemberWitness, MerkleTree};
    use jf_relation::{Circuit, PlonkCircuit};

    #[test]
    fn test_spend() {
        let rng = &mut ark_std::test_rng();
        let seed = [0u8; 32];
        let mut merkle_tree = MerkleTree::new(crate::constants::TREE_DEPTH).unwrap();
        let msk = KeyChainMasterKey::generate(seed, b"Hello");
        let (_ask, pgk, ivk) = msk.derive_key_chain_single_consumer();
        let (address, _diversifier) = msk.derive_diversified_address(&pgk, &ivk, 0).unwrap();
        // basic passing test with normal record
        let mut ro = RecordOpening {
            addr: address.clone(),
            payload: Default::default(),
            pid_birth: InnerScalarField::rand(rng),
            pid_death: InnerScalarField::rand(rng),
            nonce: InnerScalarField::rand(rng),
            blinding: InnerScalarField::rand(rng),
        };
        do_spend_test(rng, &msk, &ro, false, true, &mut merkle_tree);
        // check with bad witness for root
        do_spend_test(rng, &msk, &ro, true, false, &mut merkle_tree);
        // check again with bad witness but record is dummy
        ro.payload.is_dummy = true;
        do_spend_test(rng, &msk, &ro, true, true, &mut merkle_tree);

        // if record is dummy all should pass
        let ro = RecordOpening::dummy();
        do_spend_test(rng, &msk, &ro, false, true, &mut merkle_tree);
    }

    fn do_spend_test<R: CryptoRng + RngCore>(
        rng: &mut R,
        msk: &KeyChainMasterKey,
        ro: &RecordOpening,
        bad_root: bool,
        should_pass: bool,
        merkle_tree: &mut MerkleTree<InnerScalarField>,
    ) {
        // recompute addresses and keys from msk to avoid more parameters
        let (_ask, pgk, ivk) = msk.derive_key_chain_single_consumer();
        let (_address, diversifier) = msk.derive_diversified_address(&pgk, &ivk, 0).unwrap();
        let nullifier = ro.nullify(&pgk.nk).unwrap();
        let rc = ro.derive_record_commitment().unwrap();
        merkle_tree.push(rc);

        let (witness_rc, acc_witness) =
            AccMemberWitness::lookup_from_tree(&merkle_tree, merkle_tree.num_leaves() - 1)
                .expect_ok()
                .unwrap();
        assert_eq!(rc, witness_rc);

        let input = NoteInput {
            ro: ro.clone(),
            acc_member_witness: acc_witness.clone(),
            proof_gen_key: &pgk,
            authorization_randomizer: Default::default(),
            diversifier_randomizer: diversifier.clone(),
        };

        let merkle_root = if bad_root {
            InnerScalarField::rand(rng)
        } else {
            acc_witness.root.to_scalar()
        };

        let mut circuit = PlonkCircuit::<InnerScalarField>::new_turbo_plonk();

        let root_var = circuit.create_public_variable(merkle_root).unwrap();
        let nullifier_var = circuit.create_public_variable(nullifier.0).unwrap();
        let input_var = NoteInputVar::new(&mut circuit, &input).unwrap();

        let (rc_var, _randomizer_auth_key) =
            DPCUtxoCircuit::prove_spend(&mut circuit, &input_var, nullifier_var, root_var).unwrap();
        assert_eq!(rc, circuit.witness(rc_var).unwrap());
        if should_pass {
            circuit
                .check_circuit_satisfiability(&[merkle_root, nullifier.0])
                .unwrap();
        } else {
            assert!(circuit
                .check_circuit_satisfiability(&[merkle_root, nullifier.0])
                .is_err())
        }
    }

    #[test]
    fn test_prove_output() {
        let rng = &mut ark_std::test_rng();
        let seed = [0u8; 32];
        let msk = KeyChainMasterKey::generate(seed, b"Hello");
        let (_ask, pgk, ivk) = msk.derive_key_chain_single_consumer();
        let (address, _diversifier) = msk.derive_diversified_address(&pgk, &ivk, 0).unwrap();
        let first_nullifier = InnerScalarField::rand(rng);
        let position_in_note = 0;
        // basic passing test with normal record
        let ro = RecordOpening::new(
            rng,
            address.clone(),
            Default::default(),
            InnerScalarField::zero(),
            InnerScalarField::zero(),
            position_in_note,
            Nullifier(first_nullifier),
        );
        // successful case
        do_test_prove_output(&ro, position_in_note, first_nullifier, true);
        // fail if position in note is incorrect
        do_test_prove_output(&ro, position_in_note + 1, first_nullifier, false);
        // fail if wrong first nullifier
        do_test_prove_output(&ro, position_in_note, InnerScalarField::rand(rng), false);

        // test dummy outputs
        let ro = RecordOpening::dummy();
        do_test_prove_output(&ro, position_in_note, first_nullifier, true);
    }

    fn do_test_prove_output(
        ro: &RecordOpening,
        position: usize,
        first_nullifier: InnerScalarField,
        should_pass: bool,
    ) {
        let rc = ro.derive_record_commitment().unwrap();
        let mut circuit = PlonkCircuit::<InnerScalarField>::new_turbo_plonk();
        let rc_var = circuit.create_public_variable(rc).unwrap();
        let ro_var = RecordOpeningVar::new(&mut circuit, &ro).unwrap();
        let first_nullifier_var = circuit.create_public_variable(first_nullifier).unwrap();
        DPCUtxoCircuit::prove_output(&mut circuit, &ro_var, rc_var, position, first_nullifier_var)
            .unwrap();
        if should_pass {
            circuit
                .check_circuit_satisfiability(&[rc, first_nullifier])
                .unwrap();
        } else {
            assert!(circuit
                .check_circuit_satisfiability(&[rc, first_nullifier])
                .is_err())
        }
    }

    #[test]
    fn test_circuit_build() {
        let rng = &mut ark_std::test_rng();
        let mut seed = [0u8; 32];
        rng.fill(&mut seed);
        let mut merkle_tree = MerkleTree::new(crate::constants::TREE_DEPTH).unwrap();
        let msk = KeyChainMasterKey::generate(seed, b"my wallet");
        let (_ask, pgk, ivk) = msk.derive_key_chain_single_consumer();
        let (addr_source, diversifier_source) =
            msk.derive_diversified_address(&pgk, &ivk, 0).unwrap();
        let (addr_dest, _) = msk.derive_diversified_address(&pgk, &ivk, 1).unwrap();

        let ro_source = RecordOpening::new(
            rng,
            addr_source.clone(),
            Payload::default(),
            InnerScalarField::zero(),
            InnerScalarField::zero(),
            1,
            Nullifier(InnerScalarField::one()),
        );
        let rc_source = ro_source.derive_record_commitment().unwrap();
        let first_nullifier = ro_source.nullify(&pgk.nk).unwrap();

        merkle_tree.push(rc_source);
        let (_, acc_witness) = AccMemberWitness::lookup_from_tree(&merkle_tree, 0)
            .expect_ok()
            .unwrap();
        let source_input = NoteInput {
            ro: ro_source,
            acc_member_witness: acc_witness,
            proof_gen_key: &pgk,
            authorization_randomizer: Default::default(),
            diversifier_randomizer: diversifier_source.clone(),
        };

        let dummy_input = NoteInput::dummy(&pgk);

        let inputs = vec![source_input, dummy_input];

        let ro_dest0 = RecordOpening::new(
            rng,
            addr_source,
            Payload::default(),
            InnerScalarField::default(),
            InnerScalarField::default(),
            0,
            first_nullifier.clone(),
        );
        let ro_dest1 = RecordOpening::new(
            rng,
            addr_dest,
            Payload::default(),
            InnerScalarField::default(),
            InnerScalarField::default(),
            1,
            first_nullifier,
        );

        let outputs = vec![ro_dest0, ro_dest1];

        let blinding_local_data = InnerScalarField::rand(rng);
        let witness = DPCUtxoWitness::new_unchecked(rng, inputs, outputs, blinding_local_data);
        let public_input = DPCUtxoPublicInput::from_witness(&witness, vec![]).unwrap();

        let circuit = DPCUtxoCircuit::build(&witness, &public_input).unwrap();

        circuit
            .0
            .check_circuit_satisfiability(&public_input.to_scalars())
            .unwrap();

        // bad paths
        // 2.  bad authorization verification key
        let mut public_input = DPCUtxoPublicInput::from_witness(&witness, vec![]).unwrap();
        public_input.authorization_verification_key = Default::default();
        let circuit = DPCUtxoCircuit::build(&witness, &public_input).unwrap();
        assert!(circuit
            .0
            .check_circuit_satisfiability(&public_input.to_scalars())
            .is_err());

        // 3.  bad commitment local data
        let mut public_input = DPCUtxoPublicInput::from_witness(&witness, vec![]).unwrap();
        public_input.commitment_local_data = Default::default();
        let circuit = DPCUtxoCircuit::build(&witness, &public_input).unwrap();
        assert!(circuit
            .0
            .check_circuit_satisfiability(&public_input.to_scalars())
            .is_err());

        // 4.  bad commitment predicates
        let mut public_input = DPCUtxoPublicInput::from_witness(&witness, vec![]).unwrap();
        public_input.commitment_predicates = Default::default();
        let circuit = DPCUtxoCircuit::build(&witness, &public_input).unwrap();
        assert!(circuit
            .0
            .check_circuit_satisfiability(&public_input.to_scalars())
            .is_err());
    }
}
