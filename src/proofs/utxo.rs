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
    circuit::utxo::DPCUtxoCircuit,
    constants::TREE_DEPTH,
    errors::DPCApiError,
    keys::ProofGenerationKey,
    structs::{
        compress_local_data, derive_predicates_commitment, NoteInput, Nullifier, RecordOpening,
    },
    types::{
        CommitmentValue, InnerPairingEngine, InnerScalarField, InnerUniversalParam, NodeValue,
        SigVerKey,
    },
    utils,
};
use ark_ff::UniformRand;
use ark_std::{
    rand::{CryptoRng, RngCore},
    vec,
    vec::Vec,
};
use jf_plonk::{
    circuit::Circuit,
    proof_system::{PlonkKzgSnark, Snark},
    transcript::StandardTranscript,
};
use jf_primitives::merkle_tree::AccMemberWitness;

/// The UTXO part of the proving key
pub type UtxoProvingKey<'a> =
    jf_plonk::proof_system::structs::ProvingKey<'a, crate::types::InnerPairingEngine>;

/// The UTXO part of the verifying key
pub type UtxoVerifyingKey =
    jf_plonk::proof_system::structs::VerifyingKey<crate::types::InnerPairingEngine>;

pub(super) type ProofUtxo =
    jf_plonk::proof_system::structs::Proof<crate::types::InnerPairingEngine>;

#[derive(Clone, Debug)]
pub struct DPCUtxoWitness<'a> {
    // input notes
    pub(crate) entire_inputs: Vec<NoteInput<'a>>,
    // output records
    pub(crate) entire_output_records_openings: Vec<RecordOpening>,
    // the blinder for the local data commitment
    pub(crate) blinding_local_data: InnerScalarField,
    // the blinder for the predicates commitment
    pub(crate) blinding_predicates: InnerScalarField,
}

impl<'a> DPCUtxoWitness<'a> {
    /// Build a dummy witness for `n_inputs` number of notes/records.
    pub(crate) fn dummy(n_inputs: usize, pgk: &'a ProofGenerationKey) -> Self {
        let outputs = vec![RecordOpening::default(); n_inputs];
        let rng = &mut ark_std::test_rng();
        let mut inputs = vec![];
        for _ in 0..n_inputs {
            inputs.push(NoteInput {
                ro: Default::default(),
                acc_member_witness: AccMemberWitness::dummy(TREE_DEPTH),
                proof_gen_key: pgk,
                authorization_randomizer: Default::default(),
                diversifier_randomizer: Default::default(),
            });
        }
        let blinding_local_data = InnerScalarField::rand(rng);
        Self::new_unchecked(rng, inputs, outputs, blinding_local_data)
    }

    /// built an UTXO witness from all the inputs/records,
    pub(crate) fn new_unchecked<R: CryptoRng + RngCore>(
        rng: &mut R,
        entire_inputs: Vec<NoteInput<'a>>,
        entire_output_records_openings: Vec<RecordOpening>,
        blinding_local_data: InnerScalarField,
    ) -> Self {
        // TODO: (alex) why is one randomness being passed in, while another generated
        // here?
        let blinding_predicates = InnerScalarField::rand(rng);

        DPCUtxoWitness {
            entire_inputs,
            entire_output_records_openings,
            blinding_local_data,
            blinding_predicates,
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct DPCUtxoPublicInput {
    pub(crate) root: NodeValue,
    pub(crate) input_nullifiers: Vec<Nullifier>,
    pub(crate) output_commitments: Vec<CommitmentValue>,
    pub(crate) commitment_local_data: CommitmentValue,
    pub(crate) commitment_predicates: CommitmentValue,
    pub(crate) memo: Vec<InnerScalarField>,
    pub(crate) authorization_verification_key: SigVerKey,
}

impl DPCUtxoPublicInput {
    pub(crate) fn from_witness(
        witness: &DPCUtxoWitness,
        memo: Vec<InnerScalarField>,
    ) -> Result<Self, DPCApiError> {
        // 1. aggregate verification key
        let ver_keys_refs: Vec<_> = witness
            .entire_inputs
            .iter()
            .map(|input| &input.proof_gen_key.ak.0)
            .collect();
        let randomizers_refs: Vec<_> = witness
            .entire_inputs
            .iter()
            .map(|input| &input.authorization_randomizer)
            .collect();
        let auth_ver_key = crate::keys::aggregate_authorization_verification_keys(
            &ver_keys_refs,
            &randomizers_refs,
        );

        // TODO compute detection keys

        // retrieve merkle root
        let root = utils::get_root_unchecked(&witness.entire_inputs);

        // Compute commitment to predicates
        let input_death_pids: Vec<InnerScalarField> = witness
            .entire_inputs
            .iter()
            .map(|note| note.ro.pid_death)
            .collect();
        let output_birth_pids: Vec<InnerScalarField> = witness
            .entire_output_records_openings
            .iter()
            .map(|ro| ro.pid_birth)
            .collect();
        let commitment_predicates = derive_predicates_commitment(
            &input_death_pids,
            &output_birth_pids,
            witness.blinding_predicates,
        )?;

        // Compute commitment to local_data
        let compressed_local_data = compress_local_data(
            &witness.entire_inputs[..],
            &witness.entire_output_records_openings,
            memo,
        )?;
        let commitment_local_data = compressed_local_data.commit(witness.blinding_local_data)?;
        let nullifiers = witness
            .entire_inputs
            .iter()
            .map(|input| input.ro.nullify(&input.proof_gen_key.nk))
            .collect::<Result<Vec<_>, _>>()?;

        Ok(DPCUtxoPublicInput {
            root,
            input_nullifiers: nullifiers,
            output_commitments: compressed_local_data.output_record_commitments,
            commitment_local_data,
            commitment_predicates,
            memo: compressed_local_data.memo,
            authorization_verification_key: auth_ver_key,
        })
    }

    pub(crate) fn to_scalars(&self) -> Vec<InnerScalarField> {
        let mut scalars = vec![];
        self.input_nullifiers
            .iter()
            .for_each(|nullifier| scalars.push(nullifier.0));
        self.output_commitments
            .iter()
            .for_each(|commitment| scalars.push(*commitment));
        scalars.push(self.commitment_predicates);
        scalars.push(self.commitment_local_data);
        scalars.push(self.root.to_scalar());
        self.memo
            .iter()
            .for_each(|memo_elem| scalars.push(*memo_elem));
        let auth_pk_point = self.authorization_verification_key.to_affine();
        scalars.push(auth_pk_point.x);
        scalars.push(auth_pk_point.y);
        scalars
    }
}

pub(super) fn prove_utxo<R: RngCore + CryptoRng>(
    rng: &mut R,
    proving_key: &UtxoProvingKey,
    witness: &DPCUtxoWitness,
    public_inputs: &DPCUtxoPublicInput,
) -> Result<ProofUtxo, DPCApiError> {
    let utxo_circuit =
        DPCUtxoCircuit::build(witness, public_inputs).map_err(DPCApiError::FailedSnark)?;

    #[cfg(test)]
    {
        assert!(
            utxo_circuit
                .0
                .check_circuit_satisfiability(&public_inputs.to_scalars())
                .is_ok(),
            "UTXO circuit is not SAT!"
        );
    }

    PlonkKzgSnark::prove::<_, _, StandardTranscript>(rng, &utxo_circuit.0, proving_key, None)
        .map_err(DPCApiError::FailedSnark)
}

pub(super) fn verify_utxo(
    proof: &ProofUtxo,
    verifying_key: &UtxoVerifyingKey,
    public_input: &DPCUtxoPublicInput,
) -> Result<(), DPCApiError> {
    jf_plonk::proof_system::PlonkKzgSnark::<InnerPairingEngine>::verify::<StandardTranscript>(
        verifying_key,
        &public_input.to_scalars(),
        proof,
        None,
    )
    .map_err(DPCApiError::FailedSnark)
}

// `num_inputs` is the number of inputs
pub(crate) fn preprocess_utxo_keys(
    srs: &InnerUniversalParam,
    num_inputs: usize,
) -> Result<(UtxoProvingKey, UtxoVerifyingKey, usize), DPCApiError> {
    let dummy_circuit = DPCUtxoCircuit::build_for_preprocessing(num_inputs)?;
    let (proving_key, verifying_key) =
        PlonkKzgSnark::<InnerPairingEngine>::preprocess(srs, &dummy_circuit.0)
            .map_err(DPCApiError::FailedSnark)?;
    Ok((proving_key, verifying_key, dummy_circuit.0.num_gates()))
}

#[cfg(test)]
mod tests {
    use crate::{
        circuit::utxo::DPCUtxoCircuit,
        constants::{MEMO_LEN, TREE_DEPTH},
        errors::DPCApiError,
        keys::KeyChainMasterKey,
        proofs::{
            universal_setup_inner,
            utxo::{DPCUtxoPublicInput, DPCUtxoWitness},
        },
        structs::{NoteInput, Nullifier, RecordOpening},
        types::{InnerScalarField, InnerUniversalParam},
    };
    use ark_ff::{UniformRand, Zero};
    use ark_std::{rand::Rng, vec};
    use jf_plonk::circuit::Circuit;
    use jf_primitives::merkle_tree::{AccMemberWitness, MerkleTree};

    #[test]
    fn test_pub_input_order_consistency() {
        let rng = &mut ark_std::test_rng();
        let mut seed = [0u8; 32];
        rng.fill(&mut seed);
        let mut merkle_tree = MerkleTree::new(crate::constants::TREE_DEPTH).unwrap();
        let msk = KeyChainMasterKey::generate(seed, b"my wallet");
        let (_ask, pgk, ivk) = msk.derive_key_chain_single_consumer();
        let (addr, diversifier_rand) = msk.derive_diversified_address(&pgk, &ivk, 0).unwrap();

        let n_inputs = 4usize;
        let mut input_ros = vec![];
        for i in 0..n_inputs {
            let ro = RecordOpening::new_native_asset(
                rng,
                addr.clone(),
                (i as u128 + 1) * 5,
                0,
                Nullifier(InnerScalarField::zero()),
            );
            merkle_tree.push(ro.derive_record_commitment().unwrap());
            input_ros.push(ro);
        }
        let mut inputs = vec![];
        for (i, ro) in input_ros.iter().enumerate() {
            let (_, acc_witness) = AccMemberWitness::lookup_from_tree(&merkle_tree, i as u64)
                .expect_ok()
                .unwrap();
            inputs.push(NoteInput {
                ro: ro.clone(),
                acc_member_witness: acc_witness,
                proof_gen_key: &pgk,
                authorization_randomizer: Default::default(),
                diversifier_randomizer: diversifier_rand.clone(),
            });
        }

        let first_nullifier = inputs[0].ro.nullify(&pgk.nk).unwrap();
        let mut output_ros = vec![];
        for i in 0..n_inputs {
            output_ros.push(RecordOpening::new_native_asset(
                rng,
                addr.clone(),
                (4 - i as u128) * 5,
                i,
                first_nullifier.clone(),
            ));
        }

        let blinding_local_data = InnerScalarField::rand(rng);
        let witness = DPCUtxoWitness::new_unchecked(rng, inputs, output_ros, blinding_local_data);
        let public_input = DPCUtxoPublicInput::from_witness(&witness, vec![]).unwrap();
        let public_input_scalars = public_input.to_scalars();

        let circuit = DPCUtxoCircuit::build(&witness, &public_input).unwrap();
        let circuit_pub_input = circuit.0.public_input().unwrap();
        assert_eq!(public_input_scalars, circuit_pub_input);
    }

    fn _test_utxo_proof(
        universal_params: &InnerUniversalParam,
        num_inputs: usize,
    ) -> Result<(), DPCApiError> {
        assert!(num_inputs > 0, "Need at least 1 input 1 output.");
        let (proving_key, verifying_key, _) =
            super::preprocess_utxo_keys(&universal_params, num_inputs)?;

        let mut merkle_tree = MerkleTree::new(TREE_DEPTH).unwrap();
        let mut wsk = [0u8; 32];
        let rng = &mut ark_std::test_rng();
        rng.fill(&mut wsk[..]);
        let msk = KeyChainMasterKey::generate(wsk, &[]);
        let (_, pgk, ivk) = msk.derive_key_chain_single_consumer();
        let (addr, rd) = msk.derive_diversified_address(&pgk, &ivk, 0)?;

        let mut inputs = vec![];
        for i in 0..num_inputs - 1 {
            let ro = RecordOpening::new(
                rng,
                addr.clone(),
                Default::default(),
                InnerScalarField::zero(),
                InnerScalarField::zero(),
                i,
                Nullifier::default(),
            );
            merkle_tree.push(ro.derive_record_commitment()?);
            inputs.push(ro);
        }

        // push an additional dummy input
        let dummy_ro = RecordOpening::dummy();
        merkle_tree.push(dummy_ro.derive_record_commitment()?);
        inputs.push(dummy_ro);

        let fst_nullifier = inputs[0].nullify(&pgk.nk)?;

        let mut note_inputs = vec![];
        for (i, ro) in inputs.into_iter().enumerate() {
            let (_, mt_witness) = AccMemberWitness::lookup_from_tree(&merkle_tree, i as u64)
                .expect_ok()
                .unwrap();

            note_inputs.push(NoteInput {
                ro,
                acc_member_witness: mt_witness,
                proof_gen_key: &pgk,
                authorization_randomizer: Default::default(),
                diversifier_randomizer: rd.clone(),
            });
        }

        let mut outputs = vec![];
        for i in 0..num_inputs - 1 {
            outputs.push(RecordOpening::new(
                rng,
                addr.clone(),
                Default::default(),
                InnerScalarField::zero(),
                InnerScalarField::zero(),
                i,
                fst_nullifier.clone(),
            ));
        }
        // push an additional dummy output
        outputs.push(RecordOpening::dummy());

        let blinding_local_data = InnerScalarField::rand(rng);
        let witness = DPCUtxoWitness::new_unchecked(rng, note_inputs, outputs, blinding_local_data);
        let mut pubinput =
            DPCUtxoPublicInput::from_witness(&witness, vec![InnerScalarField::zero(); MEMO_LEN])?;

        let proof = super::prove_utxo(rng, &proving_key, &witness, &pubinput)?;

        super::verify_utxo(&proof, &verifying_key, &pubinput)?;

        // change public input should fail: bad root when verifying
        pubinput.root = Default::default();
        assert!(super::verify_utxo(&proof, &verifying_key, &pubinput).is_err());
        Ok(())
    }

    #[test]
    fn test_utxo_proof() -> Result<(), DPCApiError> {
        let rng = &mut ark_std::test_rng();
        let max_degree = 32770 * 4;
        let universal_params = universal_setup_inner(max_degree, rng)?;
        _test_utxo_proof(&universal_params, 2)?;
        _test_utxo_proof(&universal_params, 3)?;
        _test_utxo_proof(&universal_params, 5)
    }
}
