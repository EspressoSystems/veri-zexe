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
    circuit::policies_vfy::PoliciesVfyCircuit,
    errors::DPCApiError,
    structs::{derive_predicates_commitment, PolicyIdentifier},
    types::{
        CommitmentValue, InnerBaseField, InnerG1Affine, InnerG1Group, InnerPairingEngine,
        InnerScalarField, InnerUniversalParam, OuterPairingEngine, OuterUniversalParam,
    },
};
use ark_ec::ProjectiveCurve;
use ark_ff::Zero;
use ark_std::{
    format,
    rand::{CryptoRng, RngCore},
    string::ToString,
    vec,
    vec::Vec,
};
use jf_plonk::{
    circuit::customized::ecc::Point,
    proof_system::{
        batch_arg::BatchArgument,
        structs::{BatchProof, Proof, ProvingKey, VerifyingKey},
        PlonkKzgSnark, Snark,
    },
    transcript::{RescueTranscript, StandardTranscript},
};
use jf_utils::fr_to_fq;

#[derive(Clone, Debug, PartialEq)]
pub struct PoliciesVfyProvingKey<'a> {
    /// The actual proving key
    pub(crate) proving_key: ProvingKey<'a, OuterPairingEngine>,
    /// Number of input records, i.e., #death predicates
    /// Note that the number of output records, i.e., #birth predicates
    /// should match this value.
    pub(crate) num_input_records: usize,
}

pub(crate) type PoliciesVfyVerifyingKey = VerifyingKey<OuterPairingEngine>;

pub(crate) type PoliciesVfyValidityProof = Proof<OuterPairingEngine>;

pub(crate) type InnerPartialVfyProof = (InnerG1Affine, InnerG1Affine);

#[derive(Debug, Clone, Default)]
/// Struct for the public input of a policies verification circuit witness
pub(crate) struct PoliciesVfyPublicInput {
    /// Commitment to record policy identifiers.
    pub(crate) comm_predicates: CommitmentValue,
    /// Commitment to local data.
    pub(crate) comm_local_data: CommitmentValue,
    /// Partial Plonk proof for verifying the inner predicates
    pub(crate) partial_plonk_proof: InnerPartialVfyProof,
}

#[derive(Debug, Clone)]
/// Witness for an outer policies verification circuit.
pub(crate) struct PoliciesVfyWitness {
    /// Input death predicate verification keys
    pub(crate) input_death_vks: Vec<VerifyingKey<InnerPairingEngine>>,
    /// Output birth predicate verification keys
    pub(crate) output_birth_vks: Vec<VerifyingKey<InnerPairingEngine>>,
    /// Batch proof for record policies
    pub(crate) batch_proof: BatchProof<InnerPairingEngine>,
    /// Blinding factor for the policy identifier commitment
    pub(crate) blind_comm_predicates: InnerScalarField,
    /// Blinding factor for the partial Plonk proof
    pub(crate) blind_partial_proof: InnerScalarField,
}

#[derive(Debug)]
/// Struct for the constant parameters of a policies verification circuit
pub(crate) struct PoliciesVfyParams {
    /// Group elements used in the Plonk verification circuit
    pub(crate) beta_g: InnerG1Affine,
    pub(crate) generator_g: InnerG1Affine,

    /// Parameters for `FpElemVar` that simulates `InnerScalarField` in
    /// `InnerBaseField`
    pub(crate) m: usize,
    pub(crate) two_power_m: Option<InnerBaseField>,

    /// Bit length for UltraPlonk range gates
    pub(crate) range_bit_len: usize,
}

/// Pre-process to generate a pair of keys for policies circuit
/// input:
/// - outer circuit SRS
/// - inner circuit SRS
/// - number of (birth, death) predicate pairs
/// - inner circuit domain size
/// output:
/// - proving key
/// - verification key
/// - total number of constraints of the policies circuit
pub fn preprocess<'a>(
    outer_srs: &'a OuterUniversalParam,
    inner_srs: &InnerUniversalParam,
    num_inputs: usize,
    inner_policy_domain_size: usize,
) -> Result<(PoliciesVfyProvingKey<'a>, PoliciesVfyVerifyingKey, usize), DPCApiError> {
    let (dummy_circuit, n_constraints) = PoliciesVfyCircuit::build_for_preprocessing(
        inner_srs,
        num_inputs,
        inner_policy_domain_size,
    )?;
    let (proving_key, verifying_key) =
        PlonkKzgSnark::<OuterPairingEngine>::preprocess(outer_srs, &dummy_circuit.0).map_err(
            |e| {
                DPCApiError::InvalidParameters(format!(
                    "Preprocessing policy circuit of {}-inputs failed: {}",
                    num_inputs, e
                ))
            },
        )?;

    Ok((
        PoliciesVfyProvingKey {
            proving_key,
            num_input_records: num_inputs,
        },
        verifying_key,
        n_constraints,
    ))
}

/// Generate a proof for the policy circuit satisfaction
/// input:
/// - proving key
/// - witness to the policies
/// - parameters for the policies
/// - public inputs
/// - extra transcript message
/// output:
/// - proof
pub(crate) fn prove<R>(
    rng: &mut R,
    proving_key: &PoliciesVfyProvingKey,
    witness: &PoliciesVfyWitness,
    params: &PoliciesVfyParams,
    pub_input: &PoliciesVfyPublicInput,
    extra_transcript_init_msg: Option<Vec<u8>>,
) -> Result<PoliciesVfyValidityProof, DPCApiError>
where
    R: RngCore + CryptoRng,
{
    if proving_key.num_input_records != witness.input_death_vks.len()
        || proving_key.num_input_records != witness.output_birth_vks.len()
    {
        return Err(DPCApiError::InvalidParameters(format!(
            "Expected input numbers: {}, actual number of birth and death predicates {} {}",
            proving_key.num_input_records,
            witness.output_birth_vks.len(),
            witness.input_death_vks.len(),
        )));
    }

    let (circuit, _) = PoliciesVfyCircuit::build(witness, pub_input, params)?;

    #[cfg(test)]
    {
        use jf_plonk::circuit::Circuit;
        assert!(
            circuit
                .0
                .check_circuit_satisfiability(&pub_input.to_scalars())
                .is_ok(),
            "Outer circuit is not SAT!"
        );
    }

    PlonkKzgSnark::<OuterPairingEngine>::prove::<_, _, StandardTranscript>(
        rng,
        &circuit.0,
        &proving_key.proving_key,
        extra_transcript_init_msg,
    )
    .map_err(|e| {
        DPCApiError::GeneralError(format!(
            "Outer policies verification circuit: proof creation failure: {:?}",
            e
        ))
    })
}

/// Verify a proof for the policy circuit
/// input:
/// - verification key
/// - public inputs
/// - extra transcript message
/// - proof
/// output:
/// - Ok if the verification passes; or an error if fails
pub(crate) fn verify(
    verifying_key: &PoliciesVfyVerifyingKey,
    public_inputs: &PoliciesVfyPublicInput,
    extra_transcript_init_msg: Option<Vec<u8>>,
    proof: &PoliciesVfyValidityProof,
) -> Result<(), DPCApiError> {
    PlonkKzgSnark::<OuterPairingEngine>::verify::<StandardTranscript>(
        verifying_key,
        &public_inputs.to_scalars(),
        proof,
        extra_transcript_init_msg,
    )
    .map_err(|e| {
        DPCApiError::GeneralError(format!(
            "Policies circuit proof verification failure: {}",
            e
        ))
    })
}

impl PoliciesVfyWitness {
    /// Create a dummy witness for a transaction with `num_input` input records
    /// where each inner record policy circuit has domain size
    /// `inner_policy_domain_size`
    pub(crate) fn dummy(num_inputs: usize, inner_policy_domain_size: usize) -> Self {
        // the underlying relation of `VerifyingKey` only has 1 public input: cm_ldata
        let num_public_inputs = 1;
        Self {
            input_death_vks: vec![
                VerifyingKey::<InnerPairingEngine>::dummy(
                    num_public_inputs,
                    inner_policy_domain_size
                );
                num_inputs
            ],
            output_birth_vks: vec![
                VerifyingKey::<InnerPairingEngine>::dummy(
                    num_public_inputs,
                    inner_policy_domain_size
                );
                num_inputs
            ],
            batch_proof: BatchProof::<InnerPairingEngine>::dummy(num_inputs),
            blind_comm_predicates: InnerScalarField::zero(),
            blind_partial_proof: InnerScalarField::zero(),
        }
    }

    /// Create a witness
    ///
    /// - `blind_partial_proof`: the masking randomness to hide the partial
    ///   proof (2 G1 points used in KZG10 to be pairing-checked)
    pub(crate) fn new(
        input_death_vks: Vec<VerifyingKey<InnerPairingEngine>>,
        output_birth_vks: Vec<VerifyingKey<InnerPairingEngine>>,
        batch_proof: BatchProof<InnerPairingEngine>,
        blind_comm_predicates: InnerScalarField,
        blind_partial_proof: InnerScalarField,
    ) -> Result<Self, DPCApiError> {
        if input_death_vks.len() != output_birth_vks.len() {
            return Err(DPCApiError::InvalidParameters(
                "input death predicates and output birth predicates length mismatch".to_string(),
            ));
        }
        Ok(Self {
            input_death_vks,
            output_birth_vks,
            batch_proof,
            blind_comm_predicates,
            blind_partial_proof,
        })
    }
}

impl PoliciesVfyPublicInput {
    /// Compute the public input from witness
    pub(crate) fn from_witness(
        witness: &PoliciesVfyWitness,
        params: &PoliciesVfyParams,
        comm_local_data: InnerScalarField,
    ) -> Result<Self, DPCApiError> {
        // Compute predicates commitment
        let input_death_pids: Vec<InnerScalarField> =
            PolicyIdentifier::from_verifying_keys(&witness.input_death_vks)
                .into_iter()
                .map(|pid| pid.0)
                .collect();
        let output_birth_pids: Vec<InnerScalarField> =
            PolicyIdentifier::from_verifying_keys(&witness.output_birth_vks)
                .into_iter()
                .map(|pid| pid.0)
                .collect();
        let comm_predicates = derive_predicates_commitment(
            &input_death_pids,
            &output_birth_pids,
            witness.blind_comm_predicates,
        )?;

        // Compute partial Plonk proof
        let birth_vks_ref: Vec<&VerifyingKey<InnerPairingEngine>> =
            witness.output_birth_vks.iter().collect();
        let death_vks_ref: Vec<&VerifyingKey<InnerPairingEngine>> =
            witness.input_death_vks.iter().collect();
        let merged_vks = BatchArgument::aggregate_verify_keys(&birth_vks_ref, &death_vks_ref)?;
        let (inner1, inner2) = BatchArgument::partial_verify::<RescueTranscript<_>>(
            &params.beta_g,
            &params.generator_g,
            &merged_vks,
            &[comm_local_data],
            &witness.batch_proof,
            witness.blind_partial_proof,
        )?;
        let partial_plonk_proof = (inner1.into_affine(), inner2.into_affine());

        Ok(Self {
            comm_predicates,
            comm_local_data,
            partial_plonk_proof,
        })
    }

    /// Flatten out all pubic input fields into a vector of InnerBaseFields.
    /// Note that the order matters.
    pub(crate) fn to_scalars(&self) -> Vec<InnerBaseField> {
        let inner1_point = Point::<InnerBaseField>::from(&self.partial_plonk_proof.0);
        let inner2_point = Point::<InnerBaseField>::from(&self.partial_plonk_proof.1);

        vec![
            fr_to_fq::<InnerBaseField, InnerG1Group>(&self.comm_predicates),
            fr_to_fq::<InnerBaseField, InnerG1Group>(&self.comm_local_data),
            inner1_point.get_x(),
            inner1_point.get_y(),
            inner2_point.get_x(),
            inner2_point.get_y(),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        circuit::policies_vfy::tests::build_policies_vfy_circuit_params,
        proofs::{universal_setup_inner, universal_setup_outer},
    };
    use ark_std::test_rng;

    const INNER_DOMAIN_SIZE_FOR_TEST: usize = 32;

    #[test]
    fn test_policies_vfy_proof() -> Result<(), DPCApiError> {
        let rng = &mut test_rng();
        let max_inner_degree = 32 + 4;
        let inner_srs = universal_setup_inner(max_inner_degree, rng)?;

        let max_outer_degree = (1 << 17) + 4;
        let outer_srs = universal_setup_outer(max_outer_degree, rng)?;

        let num_inputs = 2;
        let (pk, vk, _n_constraints) = preprocess(
            &outer_srs,
            &inner_srs,
            num_inputs,
            INNER_DOMAIN_SIZE_FOR_TEST,
        )?;
        let (witness, pub_input, params) =
            build_policies_vfy_circuit_params(rng, &inner_srs, num_inputs)?;

        let proof = prove(rng, &pk, &witness, &params, &pub_input, None)?;

        // good path
        assert!(verify(&vk, &pub_input, None, &proof).is_ok());

        // wrong transcript_ini_msg should fail
        {
            assert!(verify(
                &vk,
                &pub_input,
                Some(b"wrong init message".to_vec()),
                &proof
            )
            .is_err());
        }

        // bad proving key
        {
            let mut bad_proving_key = pk.clone();
            bad_proving_key.num_input_records -= 1;

            assert!(prove(rng, &bad_proving_key, &witness, &params, &pub_input, None).is_err());
        }

        // bad verification key
        {
            let (_pk, bad_verification_key, _n_constraints) = preprocess(
                &outer_srs,
                &inner_srs,
                num_inputs - 1,
                INNER_DOMAIN_SIZE_FOR_TEST,
            )?;
            assert!(verify(&bad_verification_key, &pub_input, None, &proof).is_err());
        }

        // incorrect input
        {
            // empty
            let bad_pub_input = PoliciesVfyPublicInput::default();
            assert!(verify(&vk, &bad_pub_input, None, &proof).is_err());

            // wrong predicate
            let mut bad_pub_input = pub_input.clone();
            bad_pub_input.comm_predicates = InnerScalarField::default();
            assert!(verify(&vk, &bad_pub_input, None, &proof).is_err());

            // wrong local data
            let mut bad_pub_input = pub_input.clone();
            bad_pub_input.comm_local_data = InnerScalarField::default();
            assert!(verify(&vk, &bad_pub_input, None, &proof).is_err());

            // wrong inner circuit proof
            let mut bad_pub_input = pub_input.clone();
            bad_pub_input.partial_plonk_proof.0 = InnerG1Affine::zero();
            assert!(verify(&vk, &bad_pub_input, None, &proof).is_err());
        }

        // ark_std::println!(
        //     "num_inputs: {}, _constraint count: {}",
        //     num_inputs,
        //     n_constraints
        // );

        Ok(())
    }
}
