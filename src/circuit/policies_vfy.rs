// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the VeriZexe library.

// This program is free software: you can redistribute it and/or modify it under
// the terms of the GNU General Public License as published by the Free Software
// Foundation, either version 3 of the License, or (at your option) any later
// version. This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
// details. You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>.

//! Outer circuit for verifying satisfiability of inner record policies.
use crate::{
    constants::{NONNATIVE_FIELD_M, RANGE_BIT_LEN},
    errors::DPCApiError,
    proofs::policies_vfy::*,
    types::{
        InnerBaseField, InnerG1Group, InnerPairingEngine, InnerScalarField, InnerUniversalParam,
    },
};
use ark_ff::{Field, PrimeField, Zero};
use ark_std::{string::ToString, vec, vec::Vec};
use jf_plonk::{
    circuit::{
        customized::{
            ecc::{Point, PointVariable},
            rescue::{RescueGadget, RescueNonNativeGadget},
            ultraplonk::{
                mod_arith::FpElemVar,
                plonk_verifier::{BatchProofVar, VerifyingKeyVar},
            },
        },
        Circuit, PlonkCircuit, Variable,
    },
    errors::PlonkError,
};
use jf_rescue::RATE;
use jf_utils::{compute_len_to_next_multiple, field_switching};

pub(crate) struct PoliciesVfyCircuit(pub(crate) PlonkCircuit<InnerBaseField>);

impl PoliciesVfyCircuit {
    /// Build a circuit during preprocessing for derivation of proving key and
    /// verifying key.
    pub(crate) fn build_for_preprocessing(
        srs: &InnerUniversalParam,
        num_input: usize,
        inner_policy_domain_size: usize,
    ) -> Result<(Self, usize), DPCApiError> {
        let dummy_witness = PoliciesVfyWitness::dummy(num_input, inner_policy_domain_size);
        let comm_local_data = InnerScalarField::zero();
        let params = PoliciesVfyParams {
            beta_g: srs.powers_of_g_ref()[1],
            generator_g: srs.powers_of_g_ref()[0],
            m: NONNATIVE_FIELD_M,
            two_power_m: Some(InnerBaseField::from(2u8).pow(&[NONNATIVE_FIELD_M as u64])),
            range_bit_len: RANGE_BIT_LEN,
        };
        let pub_input =
            PoliciesVfyPublicInput::from_witness(&dummy_witness, &params, comm_local_data)?;
        Self::build_unchecked(&dummy_witness, &pub_input, &params).map_err(DPCApiError::FailedSnark)
    }

    /// Build the circuit given a satisfiable assignment of
    /// secret witness.
    pub(crate) fn build(
        witness: &PoliciesVfyWitness,
        pub_input: &PoliciesVfyPublicInput,
        params: &PoliciesVfyParams,
    ) -> Result<(Self, usize), DPCApiError> {
        if witness.input_death_vks.len() != witness.output_birth_vks.len() {
            return Err(DPCApiError::InvalidParameters(
                "input death predicates and output birth predicates length mismatch".to_string(),
            ));
        }
        if witness.input_death_vks.len() != witness.batch_proof.len() {
            return Err(DPCApiError::InvalidParameters(
                "the number of inputs/outputs mismatches the number of instances in batch proof"
                    .to_string(),
            ));
        }
        Self::build_unchecked(witness, pub_input, params).map_err(DPCApiError::FailedSnark)
    }

    /// This is only used for testing or called internally by `Self::build()`
    fn build_unchecked(
        witness: &PoliciesVfyWitness,
        pub_input: &PoliciesVfyPublicInput,
        params: &PoliciesVfyParams,
    ) -> Result<(Self, usize), PlonkError> {
        let mut circuit = PlonkCircuit::new_ultra_plonk(params.range_bit_len);
        let witness = PoliciesVfyWitnessVar::new(&mut circuit, witness, params)?;
        let pub_input = PoliciesVfyPubInputVar::new(&mut circuit, pub_input)?;

        // 1. Derive policy identifiers
        let input_death_pids =
            derive_policy_identifier_vars(&mut circuit, &witness.input_death_vks)?;
        let input_death_pids = input_death_pids
            .iter()
            .map(|&pid| FpElemVar::new_unchecked(&mut circuit, pid, params.m, params.two_power_m))
            .collect::<Result<Vec<_>, PlonkError>>()?;

        let output_birth_pids =
            derive_policy_identifier_vars(&mut circuit, &witness.output_birth_vks)?;
        let output_birth_pids = output_birth_pids
            .iter()
            .map(|&pid| FpElemVar::new_unchecked(&mut circuit, pid, params.m, params.two_power_m))
            .collect::<Result<Vec<_>, PlonkError>>()?;

        // 2. Check predicates commitment
        let zero_fp_elem_var = FpElemVar::zero(&circuit, params.m, params.two_power_m);
        let expected_comm_predicates = derive_predicate_commitment_var(
            &mut circuit,
            &input_death_pids,
            &output_birth_pids,
            witness.blind_comm_predicates,
            zero_fp_elem_var,
        )?;
        circuit.equal_gate(expected_comm_predicates, pub_input.comm_predicates)?;

        // 3. Derive aggregated verification key and check partial verification circuit
        let merged_vks = circuit.aggregate_verify_keys::<InnerPairingEngine, InnerG1Group>(
            &witness.output_birth_vks,
            &witness.input_death_vks,
        )?;
        let shared_public_input = FpElemVar::new_unchecked(
            &mut circuit,
            pub_input.comm_local_data,
            params.m,
            params.two_power_m,
        )?;
        let expected_partial_proof = VerifyingKeyVar::partial_verify_circuit(
            &mut circuit,
            &Point::from(&params.beta_g),
            &Point::from(&params.generator_g),
            &merged_vks,
            &[shared_public_input],
            &witness.batch_proof,
            witness.blind_partial_proof,
        )?;
        circuit.point_equal_gate(&pub_input.partial_plonk_proof.0, &expected_partial_proof.0)?;
        circuit.point_equal_gate(&pub_input.partial_plonk_proof.1, &expected_partial_proof.1)?;
        let n_constraints = circuit.num_gates();
        #[cfg(test)]
        {
            ark_std::println!(
                "ℹ️ num_constraint of (unpadded) outer circuit: {}",
                circuit.num_gates(),
            );
        }
        circuit.finalize_for_arithmetization()?;
        Ok((Self(circuit), n_constraints))
    }
}

#[derive(Debug)]
pub(crate) struct PoliciesVfyWitnessVar {
    /// Input death predicate verification keys
    input_death_vks: Vec<VerifyingKeyVar<InnerPairingEngine>>,
    /// Output birth predicate verification keys
    output_birth_vks: Vec<VerifyingKeyVar<InnerPairingEngine>>,
    /// Batch proof for record policies/predicates
    batch_proof: BatchProofVar<InnerBaseField>,
    /// Blinding factor for the policy identifier commitment
    blind_comm_predicates: FpElemVar<InnerBaseField>,
    /// Blinding factor for the partial Plonk proof, converted from an
    /// `InnerScalarField` element
    blind_partial_proof: Variable,
}

impl PoliciesVfyWitnessVar {
    /// Create witness variables for an outer policies verification circuit.
    pub(crate) fn new(
        circuit: &mut PlonkCircuit<InnerBaseField>,
        witness: &PoliciesVfyWitness,
        params: &PoliciesVfyParams,
    ) -> Result<Self, PlonkError> {
        let input_death_vks = witness
            .input_death_vks
            .iter()
            .map(|vk| VerifyingKeyVar::new(circuit, vk))
            .collect::<Result<Vec<_>, PlonkError>>()?;
        let output_birth_vks = witness
            .output_birth_vks
            .iter()
            .map(|vk| VerifyingKeyVar::new(circuit, vk))
            .collect::<Result<Vec<_>, PlonkError>>()?;
        let batch_proof = witness
            .batch_proof
            .create_variables::<InnerBaseField, InnerG1Group>(
                circuit,
                params.m,
                params.two_power_m,
            )?;
        let blind_comm_predicates = FpElemVar::new_from_field_element(
            circuit,
            &field_switching(&witness.blind_comm_predicates),
            params.m,
            params.two_power_m,
        )?;
        let blind_partial_proof =
            circuit.create_variable(field_switching(&witness.blind_partial_proof))?;

        Ok(Self {
            input_death_vks,
            output_birth_vks,
            batch_proof,
            blind_comm_predicates,
            blind_partial_proof,
        })
    }
}

#[derive(Debug)]
pub(crate) struct PoliciesVfyPubInputVar {
    /// Commitment to record policy identifiers, converted from an
    /// `InnerScalarField` element.
    pub(crate) comm_predicates: Variable, // TODO: change to CommitmentVar
    /// Commitment to local data, converted from an `InnerScalarField` element.
    pub(crate) comm_local_data: Variable,
    /// Partial Plonk proof for the circuit
    pub(crate) partial_plonk_proof: (PointVariable, PointVariable),
}

impl PoliciesVfyPubInputVar {
    /// Create a public input variable for an outer policies verification
    /// circuit.
    pub(crate) fn new(
        circuit: &mut PlonkCircuit<InnerBaseField>,
        pub_input: &PoliciesVfyPublicInput,
    ) -> Result<Self, PlonkError> {
        let comm_predicates =
            circuit.create_public_variable(field_switching(&pub_input.comm_predicates))?;
        let comm_local_data =
            circuit.create_public_variable(field_switching(&pub_input.comm_local_data))?;
        let point_0 = circuit.create_public_point_variable(Point::<InnerBaseField>::from(
            &pub_input.partial_plonk_proof.0,
        ))?;
        let point_1 = circuit.create_public_point_variable(Point::<InnerBaseField>::from(
            &pub_input.partial_plonk_proof.1,
        ))?;
        Ok(Self {
            comm_predicates,
            comm_local_data,
            partial_plonk_proof: (point_0, point_1),
        })
    }
}

// Helper circuit: derive policy identifier variables from verifying key
// variables.
fn derive_policy_identifier_vars(
    circuit: &mut PlonkCircuit<InnerBaseField>,
    vks: &[VerifyingKeyVar<InnerPairingEngine>],
) -> Result<Vec<Variable>, PlonkError> {
    let mut pids = vec![];
    let truncated_length = (InnerScalarField::size_in_bits() >> 3) * 8;
    for vk in vks.iter() {
        let tmp = RescueGadget::rescue_sponge_with_padding(circuit, &vk.to_vec(), 1)?[0];
        let pid = circuit.truncate(tmp, truncated_length)?;
        pids.push(pid);
    }
    Ok(pids)
}

// Helper circuit: derive policies/predicates commitment variable from policy
// identifier variables and blinding factor variable.
fn derive_predicate_commitment_var(
    circuit: &mut PlonkCircuit<InnerBaseField>,
    input_death_pids: &[FpElemVar<InnerBaseField>],
    output_birth_pids: &[FpElemVar<InnerBaseField>],
    blind_comm_predicates: FpElemVar<InnerBaseField>,
    zero_fp_elem_var: FpElemVar<InnerBaseField>,
) -> Result<Variable, PlonkError> {
    // Hash commitment should start with blinding factor.
    let mut data_vars = vec![blind_comm_predicates];
    data_vars.extend(input_death_pids);
    data_vars.extend(output_birth_pids);
    // Ok to pad with 0's since input length is fixed for the commitment instance
    let new_len = compute_len_to_next_multiple(data_vars.len(), RATE);
    data_vars.resize(new_len, zero_fp_elem_var);
    let expected_comm_predicates = RescueNonNativeGadget::rescue_sponge_no_padding::<
        InnerScalarField,
    >(circuit, &data_vars, 1)?[0];
    expected_comm_predicates.convert_to_var(circuit)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::types::{InnerG1Affine, InnerG1Projective, InnerUniversalParam};
    use ark_ec::ProjectiveCurve;
    use ark_std::{
        rand::{CryptoRng, RngCore},
        test_rng, UniformRand,
    };
    use jf_plonk::{
        proof_system::{
            batch_arg::build_batch_proof_and_vks_for_test, PlonkKzgSnark, UniversalSNARK,
        },
        transcript::RescueTranscript,
    };

    const INNER_DOMAIN_SIZE_FOR_TEST: usize = 32;

    #[test]
    fn test_pub_input_order_consistency() {
        let mut rng = test_rng();
        let g1 = InnerG1Projective::rand(&mut rng).into_affine();
        let g2 = InnerG1Projective::rand(&mut rng).into_affine();
        let pub_input = PoliciesVfyPublicInput {
            comm_predicates: InnerScalarField::from(2u8),
            comm_local_data: InnerScalarField::from(3u8),
            partial_plonk_proof: (g1, g2),
        };
        let pub_input_vec = pub_input.to_scalars();
        let mut circuit = PlonkCircuit::new_ultra_plonk(RANGE_BIT_LEN);
        PoliciesVfyPubInputVar::new(&mut circuit, &pub_input).unwrap(); // safe unwrap

        let circuit_pub_input = circuit.public_input().unwrap();
        assert_eq!(pub_input_vec, circuit_pub_input);
    }

    pub(crate) fn build_policies_vfy_circuit_params<R>(
        rng: &mut R,
        srs: &InnerUniversalParam,
        num_instances: usize,
    ) -> Result<
        (
            PoliciesVfyWitness,
            PoliciesVfyPublicInput,
            PoliciesVfyParams,
        ),
        DPCApiError,
    >
    where
        R: CryptoRng + RngCore,
    {
        let comm_local_data = InnerScalarField::rand(rng);
        let (batch_proof, output_birth_vks, input_death_vks) =
            build_batch_proof_and_vks_for_test::<_, _, _, _, RescueTranscript<_>>(
                rng,
                srs,
                num_instances,
                comm_local_data,
            )?;
        let blind_comm_predicates = InnerScalarField::rand(rng);
        let blind_partial_proof = InnerScalarField::rand(rng);
        let witness = PoliciesVfyWitness::new(
            input_death_vks,
            output_birth_vks,
            batch_proof,
            blind_comm_predicates,
            blind_partial_proof,
        )?;
        let params = PoliciesVfyParams {
            beta_g: srs.powers_of_g_ref()[1],
            generator_g: srs.powers_of_g_ref()[0],
            m: NONNATIVE_FIELD_M,
            two_power_m: Some(InnerBaseField::from(2u8).pow(&[NONNATIVE_FIELD_M as u64])),
            range_bit_len: RANGE_BIT_LEN,
        };
        let pub_input = PoliciesVfyPublicInput::from_witness(&witness, &params, comm_local_data)?;
        Ok((witness, pub_input, params))
    }

    fn check_preprocessed_circuit_consistency(
        preproc_cs: &PoliciesVfyCircuit,
        cs: &PoliciesVfyCircuit,
    ) -> Result<(), DPCApiError> {
        assert_eq!(
            preproc_cs.0.num_gates(),
            cs.0.num_gates(),
            "preprocessed circuit size = {}, online circuit size = {}",
            preproc_cs.0.num_gates(),
            cs.0.num_gates(),
        );
        assert_eq!(
            preproc_cs.0.num_inputs(),
            cs.0.num_inputs(),
            "preprocessed circuit num_inputs = {}, online circuit num_inputs = {}",
            preproc_cs.0.num_inputs(),
            cs.0.num_inputs(),
        );
        assert_eq!(
            preproc_cs.0.num_vars(),
            cs.0.num_vars(),
            "preprocessed circuit num_vars = {}, online circuit num_vars = {}",
            preproc_cs.0.num_vars(),
            cs.0.num_vars(),
        );
        Ok(())
    }

    #[test]
    fn test_policies_vfy_circuit_build() -> Result<(), DPCApiError> {
        let rng = &mut test_rng();
        let max_degree = 32 + 4;
        let srs = PlonkKzgSnark::<InnerPairingEngine>::universal_setup(max_degree, rng)?;

        for num_input in 2..5 {
            let (preproc_cs, _) = PoliciesVfyCircuit::build_for_preprocessing(
                &srs,
                num_input,
                INNER_DOMAIN_SIZE_FOR_TEST,
            )?;
            let (witness, pub_input, params) =
                build_policies_vfy_circuit_params(rng, &srs, num_input)?;
            let (cs, _) = PoliciesVfyCircuit::build(&witness, &pub_input, &params)?;
            check_preprocessed_circuit_consistency(&preproc_cs, &cs)?;

            // good path
            assert!(cs
                .0
                .check_circuit_satisfiability(&pub_input.to_scalars())
                .is_ok());

            // wrong `comm_predicates`
            let mut bad_pub_input = pub_input.clone();
            bad_pub_input.comm_predicates = InnerScalarField::zero();
            assert!(cs
                .0
                .check_circuit_satisfiability(&bad_pub_input.to_scalars())
                .is_err());

            // wrong `comm_local_data`
            let mut bad_pub_input = pub_input.clone();
            bad_pub_input.comm_local_data = InnerScalarField::zero();
            assert!(cs
                .0
                .check_circuit_satisfiability(&bad_pub_input.to_scalars())
                .is_err());

            // wrong `partial_plonk_proof`
            let mut bad_pub_input = pub_input.clone();
            bad_pub_input.partial_plonk_proof.0 = InnerG1Affine::zero();
            assert!(cs
                .0
                .check_circuit_satisfiability(&bad_pub_input.to_scalars())
                .is_err());

            let mut bad_pub_input = pub_input;
            bad_pub_input.partial_plonk_proof.1 = InnerG1Affine::zero();
            assert!(cs
                .0
                .check_circuit_satisfiability(&bad_pub_input.to_scalars())
                .is_err());
        }

        Ok(())
    }
}
