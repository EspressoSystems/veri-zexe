//! Transaction-related Proof preprocessing, generation, verification API

use crate::{
    constants::{NONNATIVE_FIELD_M, RANGE_BIT_LEN},
    errors::DPCApiError,
    predicates::PredicateTrait,
    proofs::{
        policies_vfy,
        policies_vfy::{
            InnerPartialVfyProof, PoliciesVfyParams, PoliciesVfyProvingKey, PoliciesVfyPublicInput,
            PoliciesVfyValidityProof, PoliciesVfyVerifyingKey, PoliciesVfyWitness,
        },
        predicates,
        predicates::Predicate,
        utxo::{
            preprocess_utxo_keys, DPCUtxoPublicInput, DPCUtxoWitness, ProofUtxo, UtxoProvingKey,
            UtxoVerifyingKey,
        },
    },
    structs::{NoteInput, RecordOpening},
    types::{
        InnerBaseField, InnerG1Affine, InnerPairingEngine, InnerScalarField, InnerUniversalParam,
        OuterUniversalParam,
    },
};
use ark_ff::{Field, UniformRand};
use ark_serialize::{CanonicalSerialize, *};
use ark_std::{
    rand::{CryptoRng, RngCore},
    string::ToString,
    time::Instant,
    vec::Vec,
};
use jf_plonk::proof_system::structs::VerifyingKey;
use jf_utils::tagged_blob;

#[tagged_blob("DPC_PROOF")]
#[derive(Clone, Debug, PartialEq, Eq, Hash, CanonicalSerialize, CanonicalDeserialize)]
/// Proof of correctness for a DPC Transaction
pub struct DPCValidityProof {
    // Universal UTXO proof
    utxo_proof: ProofUtxo,
    // Universal outer proof that verifies the inner policy proofs
    policies_vfy_proof: PoliciesVfyValidityProof,
    // Inner predicates partial verification proof
    pub(crate) inner_partial_vfy_proof: InnerPartialVfyProof,
}

#[derive(Clone, Debug, PartialEq)] // TODO: derive hash and serialize/deserialize
/// DPC Transaction proving key
pub struct DPCProvingKey<'a> {
    utxo_proving_key: UtxoProvingKey<'a>,
    policies_vfy_proving_key: PoliciesVfyProvingKey<'a>,
    // A group element used in inner predicate proofs verification circuit.
    pub(crate) beta_g: InnerG1Affine,
}

#[derive(Clone, Debug, PartialEq)] // TODO: derive hash and serialize/deserialize
/// DPC Transaction verifying key
pub struct DPCVerifyingKey {
    utxo_verifying_key: UtxoVerifyingKey,
    policies_vfy_verifying_key: PoliciesVfyVerifyingKey,
}

pub(crate) struct DPCWitness<'a> {
    pub(crate) utxo_witness: DPCUtxoWitness<'a>,
    pub(crate) policies_vfy_witness: PoliciesVfyWitness,
}

impl<'a> DPCWitness<'a> {
    pub(crate) fn new_unchecked<R: CryptoRng + RngCore>(
        rng: &mut R,
        entire_inputs: Vec<NoteInput<'a>>,
        entire_outputs: Vec<RecordOpening>,
        input_death_predicates: &[Predicate],
        output_birth_predicates: &[Predicate],
        blinding_local_data: InnerScalarField,
    ) -> Result<Self, DPCApiError> {
        // When a predicate circuit was initialized, it does not have the
        // correct commitment to the local data (and thus cannot generate)
        // a correct proof. So to generate a correct witness, it is required
        // that the predicates are finalized
        for predicate in input_death_predicates {
            if !predicate.is_finalized {
                return Err(DPCApiError::InternalError(
                    "The input predicate hasn't been finalized".to_string(),
                ));
            }
        }

        for predicate in output_birth_predicates {
            if !predicate.is_finalized {
                return Err(DPCApiError::InternalError(
                    "The input predicate hasn't been finalized".to_string(),
                ));
            }
        }

        // derive utxo circuit witness
        let utxo_witness =
            DPCUtxoWitness::new_unchecked(rng, entire_inputs, entire_outputs, blinding_local_data);

        let now = Instant::now();
        // derive outer circuit witness
        let batch_proof = predicates::prove(rng, output_birth_predicates, input_death_predicates)?;
        ark_std::println!(
            "⏱️ all {} predicate proofs gen takes: {} ms",
            output_birth_predicates.len() + input_death_predicates.len(),
            now.elapsed().as_millis()
        );

        // TODO: remove clone
        let input_death_vks: Vec<VerifyingKey<InnerPairingEngine>> = input_death_predicates
            .iter()
            .map(|pred| pred.verifying_key().clone())
            .collect();
        let output_birth_vks: Vec<VerifyingKey<InnerPairingEngine>> = output_birth_predicates
            .iter()
            .map(|pred| pred.verifying_key().clone())
            .collect();
        let blind_partial_proof = InnerScalarField::rand(rng);

        let policies_vfy_witness = PoliciesVfyWitness::new(
            input_death_vks,
            output_birth_vks,
            batch_proof,
            utxo_witness.blinding_predicates,
            blind_partial_proof,
        )?;
        Ok(Self {
            utxo_witness,
            policies_vfy_witness,
        })
    }
}

#[derive(Clone, Debug)]
pub(crate) struct DPCPublicInput {
    pub(crate) utxo_public_input: DPCUtxoPublicInput,
    // The policies_vfy public input and the UTXO public input share the same `comm_local_data` and
    // `comm_predicates`.
    pub(crate) inner_partial_vfy_proof: InnerPartialVfyProof,
}

impl DPCPublicInput {
    pub(crate) fn from_witness(
        witness: &DPCWitness,
        memo: Vec<InnerScalarField>,
        beta_g: InnerG1Affine, // TODO: (alex) why is this needed?
    ) -> Result<Self, DPCApiError> {
        // derive utxo circuit public input
        let utxo_public_input = DPCUtxoPublicInput::from_witness(&witness.utxo_witness, memo)?;

        // derive outer circuit public input
        let params = PoliciesVfyParams {
            beta_g,
            generator_g: witness.policies_vfy_witness.input_death_vks[0].open_key.g,
            m: NONNATIVE_FIELD_M,
            two_power_m: Some(InnerBaseField::from(2u8).pow(&[NONNATIVE_FIELD_M as u64])),
            range_bit_len: RANGE_BIT_LEN,
        };
        let policies_vfy_public_input = PoliciesVfyPublicInput::from_witness(
            &witness.policies_vfy_witness,
            &params,
            utxo_public_input.commitment_local_data,
        )?;

        if policies_vfy_public_input.comm_predicates != utxo_public_input.commitment_predicates {
            return Err(DPCApiError::InvalidParameters(
                "The predicates commitment computed in the UTXO circuit is different from that in the outer circuit".to_string(),
            ));
        }
        // double-check that the inner predicates batch proof is valid
        let output_birth_vks_ref: Vec<&VerifyingKey<InnerPairingEngine>> = witness
            .policies_vfy_witness
            .output_birth_vks
            .iter()
            .collect();
        let input_death_vks_ref: Vec<&VerifyingKey<InnerPairingEngine>> = witness
            .policies_vfy_witness
            .input_death_vks
            .iter()
            .collect();
        predicates::verify::<Predicate>(
            &output_birth_vks_ref,
            &input_death_vks_ref,
            &[utxo_public_input.commitment_local_data],
            &witness.policies_vfy_witness.batch_proof,
        )?;

        Ok(Self {
            utxo_public_input,
            inner_partial_vfy_proof: policies_vfy_public_input.partial_plonk_proof,
        })
    }
}

/// Pre-process to generate keys for DPC transaction proofs.
/// input:
/// - outer circuit SRS
/// - inner circuit SRS
/// - number of input/output records
/// - unmerged inner circuit domain size
///
/// output:
/// - DPC proving key
/// - DPC verification key
/// - total number of constraints of the utxo/outer circuit
pub fn preprocess<'a>(
    outer_srs: &'a OuterUniversalParam,
    inner_srs: &'a InnerUniversalParam,
    num_inputs: usize,
    unmerged_inner_policy_domain_size: usize,
) -> Result<(DPCProvingKey<'a>, DPCVerifyingKey, (usize, usize)), DPCApiError> {
    let (utxo_proving_key, utxo_verifying_key, utxo_n_constraints) =
        preprocess_utxo_keys(inner_srs, num_inputs)?;

    let (policies_vfy_proving_key, policies_vfy_verifying_key, outer_n_constraints) =
        policies_vfy::preprocess(
            outer_srs,
            inner_srs,
            num_inputs,
            unmerged_inner_policy_domain_size,
        )?;

    #[cfg(test)]
    {
        ark_std::println!(
            "ℹ️ num_constraint of UTXO circuit: {}, of outer circuit: {}",
            utxo_n_constraints,
            outer_n_constraints,
        );
    }

    let dpc_proving_key = DPCProvingKey {
        utxo_proving_key,
        policies_vfy_proving_key,
        beta_g: inner_srs.powers_of_g_ref()[1],
    };

    let dpc_verifying_key = DPCVerifyingKey {
        utxo_verifying_key,
        policies_vfy_verifying_key,
    };

    Ok((
        dpc_proving_key,
        dpc_verifying_key,
        (utxo_n_constraints, outer_n_constraints),
    ))
}

/// Generate a transaction validity proof (a zk-SNARK proof) given the witness,
/// public inputs, and the proving key.
pub(crate) fn prove<R: RngCore + CryptoRng>(
    rng: &mut R,
    proving_key: &DPCProvingKey,
    witness: &DPCWitness,
    public_inputs: &DPCPublicInput,
) -> Result<DPCValidityProof, DPCApiError> {
    let now = Instant::now();
    // compute inner UTXO proof
    let utxo_proof = super::utxo::prove_utxo(
        rng,
        &proving_key.utxo_proving_key,
        &witness.utxo_witness,
        &public_inputs.utxo_public_input,
    )?;
    ark_std::println!("⏱️️ UTXO proof gen takes: {} ms", now.elapsed().as_millis());

    // compute outer proof
    let params = PoliciesVfyParams {
        beta_g: proving_key.beta_g,
        generator_g: witness.policies_vfy_witness.input_death_vks[0].open_key.g,
        m: NONNATIVE_FIELD_M,
        two_power_m: Some(InnerBaseField::from(2u8).pow(&[NONNATIVE_FIELD_M as u64])),
        range_bit_len: RANGE_BIT_LEN,
    };

    let pub_input = PoliciesVfyPublicInput {
        comm_local_data: public_inputs.utxo_public_input.commitment_local_data,
        comm_predicates: public_inputs.utxo_public_input.commitment_predicates,
        partial_plonk_proof: public_inputs.inner_partial_vfy_proof,
    };

    let now = Instant::now();
    let policies_vfy_proof = super::policies_vfy::prove(
        rng,
        &proving_key.policies_vfy_proving_key,
        &witness.policies_vfy_witness,
        &params,
        &pub_input,
        None,
    )?;
    ark_std::println!("⏱️ Outer proof gen takes: {} ms", now.elapsed().as_millis());

    Ok(DPCValidityProof {
        utxo_proof,
        policies_vfy_proof,
        inner_partial_vfy_proof: pub_input.partial_plonk_proof,
    })
}

pub(crate) fn verify(
    proof: &DPCValidityProof,
    verifying_key: &DPCVerifyingKey,
    public_inputs: &DPCPublicInput,
) -> Result<(), DPCApiError> {
    // check UTXO proof
    super::utxo::verify_utxo(
        &proof.utxo_proof,
        &verifying_key.utxo_verifying_key,
        &public_inputs.utxo_public_input,
    )?;

    // check outer proof
    let pub_input = PoliciesVfyPublicInput {
        comm_local_data: public_inputs.utxo_public_input.commitment_local_data,
        comm_predicates: public_inputs.utxo_public_input.commitment_predicates,
        partial_plonk_proof: public_inputs.inner_partial_vfy_proof,
    };
    super::policies_vfy::verify(
        &verifying_key.policies_vfy_verifying_key,
        &pub_input,
        None,
        &proof.policies_vfy_proof,
    )?;

    // check inner partial verification proof
    predicates::decide(
        &verifying_key.utxo_verifying_key.open_key,
        &proof.inner_partial_vfy_proof,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        constants::{MEMO_LEN, TREE_DEPTH},
        keys::{DiversifiedAddress, DiversifierRandomizer, KeyChainMasterKey, ProofGenerationKey},
        proofs::{predicates::PredicateCircuit, universal_setup_inner, universal_setup_outer},
        structs::{compress_local_data, Nullifier, PolicyIdentifier},
        types::{CommitmentValue, NodeValue},
    };
    use ark_ff::{One, Zero};
    use ark_std::{rand::Rng, test_rng, vec};
    use jf_plonk::circuit::{Circuit, PlonkCircuit};
    use jf_primitives::{
        circuit::commitment::CommitmentGadget,
        merkle_tree::{AccMemberWitness, MerkleTree},
    };

    const INNER_DOMAIN_SIZE_FOR_TEST: usize = 1 << 12;

    #[test]
    #[ignore]
    fn test_dpc_proof() -> Result<(), DPCApiError> {
        // universal setup
        let rng = &mut test_rng();
        let max_inner_degree = (1 << 16) + 4;
        let inner_srs = universal_setup_inner(max_inner_degree, rng)?;
        let max_outer_degree = (1 << 17) + 4;
        let outer_srs = universal_setup_outer(max_outer_degree, rng)?;

        // preprocessing
        let num_inputs = 2;
        let (dpc_pk, dpc_vk, (..)) = preprocess(
            &outer_srs,
            &inner_srs,
            num_inputs,
            INNER_DOMAIN_SIZE_FOR_TEST,
        )?;
        let (bad_dpc_pk, bad_dpc_vk, (..)) = preprocess(&outer_srs, &inner_srs, 1, 1)?;

        // generate proof generation key and addresses
        let mut wsk = [0u8; 32];
        rng.fill(&mut wsk[..]);
        let msk = KeyChainMasterKey::generate(wsk, &[]);
        let (_, pgk, ivk) = msk.derive_key_chain_single_consumer();
        let (addr, rd) = msk.derive_diversified_address(&pgk, &ivk, 0)?;

        // proof generation
        let (
            inputs,
            outputs,
            input_death_predicates,
            output_birth_predicates,
            memo,
            blinding_local_data,
        ) = build_dpc_info_for_test(rng, &inner_srs, &pgk, addr, rd, num_inputs)?;
        let witness = DPCWitness::new_unchecked(
            rng,
            inputs,
            outputs,
            &input_death_predicates[..],
            &output_birth_predicates[..],
            blinding_local_data,
        )?;
        let pub_input =
            DPCPublicInput::from_witness(&witness, memo, inner_srs.powers_of_g_ref()[1])?;
        let dpc_proof = prove(rng, &dpc_pk, &witness, &pub_input)?;

        // good path
        assert!(verify(&dpc_proof, &dpc_vk, &pub_input).is_ok());

        // bad path: wrong proving key
        {
            assert!(prove(rng, &bad_dpc_pk, &witness, &pub_input).is_err());
        }

        // bad path: wrong verification key
        {
            assert!(verify(&dpc_proof, &bad_dpc_vk, &pub_input).is_err());
        }

        // bad path: wrong proof
        {
            let mut bad_dpc_proof = dpc_proof.clone();
            bad_dpc_proof.inner_partial_vfy_proof.0 = InnerG1Affine::zero();
            assert!(verify(&bad_dpc_proof, &dpc_vk, &pub_input).is_err());
        }

        // bad path: wrong public input
        {
            // wrong inner partial verification proof
            let mut bad_pub_input = pub_input.clone();
            bad_pub_input.inner_partial_vfy_proof.0 = InnerG1Affine::zero();
            assert!(verify(&dpc_proof, &dpc_vk, &bad_pub_input).is_err());

            // wrong local data commitment
            let mut bad_pub_input = pub_input.clone();
            bad_pub_input.utxo_public_input.commitment_local_data = CommitmentValue::default();
            assert!(verify(&dpc_proof, &dpc_vk, &bad_pub_input).is_err());

            // wrong predicates commitment
            let mut bad_pub_input = pub_input.clone();
            bad_pub_input.utxo_public_input.commitment_predicates = CommitmentValue::default();
            assert!(verify(&dpc_proof, &dpc_vk, &bad_pub_input).is_err());

            // wrong nullifier
            let mut bad_pub_input = pub_input.clone();
            bad_pub_input.utxo_public_input.input_nullifiers[0] = Nullifier::default();
            assert!(verify(&dpc_proof, &dpc_vk, &bad_pub_input).is_err());

            // wrong memo
            let mut bad_pub_input = pub_input.clone();
            bad_pub_input.utxo_public_input.memo[0] = InnerScalarField::one();
            assert!(verify(&dpc_proof, &dpc_vk, &bad_pub_input).is_err());

            // wrong output commitment
            let mut bad_pub_input = pub_input.clone();
            bad_pub_input.utxo_public_input.output_commitments[0] = CommitmentValue::zero();
            assert!(verify(&dpc_proof, &dpc_vk, &bad_pub_input).is_err());

            // wrong output commitment
            let mut bad_pub_input = pub_input.clone();
            bad_pub_input.utxo_public_input.root = NodeValue::empty_node_value();
            assert!(verify(&dpc_proof, &dpc_vk, &bad_pub_input).is_err());
        }

        Ok(())
    }

    // The inner predicate circuit proves knowledge of the local data commitment.
    fn build_inner_predicate_circuit_for_test(
        compressed_local_data: &[InnerScalarField],
        blinding_local_data: InnerScalarField,
        comm_local_data: InnerScalarField,
    ) -> PredicateCircuit {
        let mut inner_pred_cs = PlonkCircuit::new_turbo_plonk();
        let comm_local_data = inner_pred_cs
            .create_public_variable(comm_local_data)
            .unwrap();
        let blinding_local_data = inner_pred_cs.create_variable(blinding_local_data).unwrap();
        let mut compressed_local_data_vars = vec![];
        for &val in compressed_local_data.iter() {
            compressed_local_data_vars.push(inner_pred_cs.create_variable(val).unwrap());
        }
        let derived_comm_local_data = inner_pred_cs
            .commit(&compressed_local_data_vars[..], blinding_local_data)
            .unwrap();
        inner_pred_cs
            .equal_gate(derived_comm_local_data, comm_local_data)
            .unwrap();
        PredicateCircuit(inner_pred_cs)
    }

    fn build_dpc_info_for_test<'a, 'b, R: CryptoRng + RngCore>(
        rng: &mut R,
        inner_srs: &'a InnerUniversalParam,
        pgk: &'b ProofGenerationKey,
        addr: DiversifiedAddress,
        rd: DiversifierRandomizer,
        num_inputs: usize,
    ) -> Result<
        (
            Vec<NoteInput<'b>>,
            Vec<RecordOpening>,
            Vec<Predicate<'a>>,
            Vec<Predicate<'a>>,
            Vec<InnerScalarField>,
            InnerScalarField,
        ),
        DPCApiError,
    > {
        // 1. Compute input/output predicates identifiers
        //
        // create the inner predicate circuit with dummy public input
        let dummy_comm_local_data = InnerScalarField::zero();
        let dummy_compressed_local_data = vec![InnerScalarField::zero(); 2 * num_inputs + MEMO_LEN];
        let dummy_blinding_local_data = InnerScalarField::zero();
        let inner_pred_cs = build_inner_predicate_circuit_for_test(
            &dummy_compressed_local_data[..],
            dummy_blinding_local_data,
            dummy_comm_local_data,
        );

        let mut birth_predicate = Predicate::new(inner_srs, &inner_pred_cs, true)?;
        let birth_pid = PolicyIdentifier::from_verifying_key(birth_predicate.verifying_key());
        let mut death_predicate = Predicate::new(inner_srs, &inner_pred_cs, false)?;
        let death_pid = PolicyIdentifier::from_verifying_key(death_predicate.verifying_key());

        // 2. prepare info for the UTXO circuit
        // initialize the simulated merkle tree
        let mut merkle_tree = MerkleTree::new(TREE_DEPTH).unwrap();

        // prepare transaction inputs notes
        let mut input_ros = vec![];
        for i in 0..num_inputs - 1 {
            // death predicate identifier should match the inner predicate generated before.
            let ro = RecordOpening::new(
                rng,
                addr.clone(),
                Default::default(),
                InnerScalarField::zero(),
                death_pid.0,
                i,
                Nullifier::default(),
            );
            merkle_tree.push(ro.derive_record_commitment()?);
            input_ros.push(ro);
        }

        let first_nullifier = input_ros[0].nullify(&pgk.nk)?;

        let mut note_inputs = vec![];
        for (i, ro) in input_ros.into_iter().enumerate() {
            let (_, mt_witness) = AccMemberWitness::lookup_from_tree(&merkle_tree, i as u64)
                .expect_ok()
                .unwrap();
            note_inputs.push(NoteInput {
                ro,
                acc_member_witness: mt_witness,
                proof_gen_key: &pgk,
                authorization_randomizer: Default::default(),
                diversifier_randomizer: rd.clone(),
            })
        }
        note_inputs.push(NoteInput::dummy_with_pid(
            &pgk,
            PolicyIdentifier::default(),
            death_pid,
        )); // add a dummy note input, the death predicate identifier should match

        // prepare transaction output record openings
        let mut output_ros = vec![];
        for i in 0..num_inputs - 1 {
            // birth predicate identifier should match the inner predicate generated before.
            output_ros.push(RecordOpening::new(
                rng,
                addr.clone(),
                Default::default(),
                birth_pid.0,
                InnerScalarField::zero(),
                i,
                first_nullifier.clone(),
            ));
        }
        output_ros.push(RecordOpening::dummy_with_pid(
            birth_pid,
            PolicyIdentifier::default(),
        )); // add a dummy output, the birth predicate identifier should match

        // prepare memo
        let dummy_memo = vec![InnerScalarField::zero(); MEMO_LEN];

        // 3. update the predicates to use the correct witness circuit that matches the
        // correct local data commitment
        // TODO: have more friendly predicate APIs.
        let compressed_local_data =
            compress_local_data(&note_inputs[..], &output_ros[..], dummy_memo.clone())?;
        let blinding_local_data = InnerScalarField::rand(rng);
        let comm_local_data = compressed_local_data.commit(blinding_local_data)?;
        let inner_pred_cs = build_inner_predicate_circuit_for_test(
            &compressed_local_data.to_scalars(),
            blinding_local_data,
            comm_local_data,
        );
        assert!(inner_pred_cs
            .0
            .check_circuit_satisfiability(&[comm_local_data])
            .is_ok());
        let mut inner_birth_pred_cs = inner_pred_cs.clone();
        inner_birth_pred_cs
            .0
            .finalize_for_mergeable_circuit(jf_plonk::MergeableCircuitType::TypeA)
            .unwrap();
        let mut inner_death_pred_cs = inner_pred_cs;
        inner_death_pred_cs
            .0
            .finalize_for_mergeable_circuit(jf_plonk::MergeableCircuitType::TypeB)
            .unwrap();
        birth_predicate.update_witness(inner_birth_pred_cs)?;
        death_predicate.update_witness(inner_death_pred_cs)?;
        let input_death_predicates = vec![death_predicate; num_inputs];
        let output_birth_predicates = vec![birth_predicate; num_inputs];

        // double check the length of the inputs/outputs
        assert_eq!(note_inputs.len(), num_inputs);
        assert_eq!(output_ros.len(), num_inputs);
        assert_eq!(input_death_predicates.len(), num_inputs);
        assert_eq!(output_birth_predicates.len(), num_inputs);

        Ok((
            note_inputs,
            output_ros,
            input_death_predicates,
            output_birth_predicates,
            dummy_memo,
            blinding_local_data,
        ))
    }
}
