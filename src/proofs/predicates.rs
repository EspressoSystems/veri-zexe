use crate::{
    errors::DPCApiError,
    predicates::PredicateTrait,
    types::{
        InnerBaseField, InnerPairingEngine, InnerScalarField, InnerTranscript, InnerUniversalParam,
    },
};
use ark_ec::AffineCurve;
use ark_std::{
    format,
    rand::{CryptoRng, RngCore},
    string::ToString,
    vec,
    vec::Vec,
};
use jf_plonk::{
    circuit::{Circuit, PlonkCircuit},
    proof_system::{
        batch_arg::{BatchArgument, Instance as PlonkPredicate},
        structs::{BatchProof, OpenKey, ProvingKey, VerifyingKey},
        PlonkKzgSnark,
    },
    transcript::RescueTranscript,
    MergeableCircuitType,
};

use super::policies_vfy::InnerPartialVfyProof;

#[derive(Clone, Debug)]
/// A wrapper of the plonk circuit
pub struct PredicateCircuit(pub(crate) PlonkCircuit<InnerScalarField>);

/// This type can be an instantiation of either a birth predicate or a death
/// predicate
#[derive(Clone)]
pub struct Predicate<'a> {
    pub(crate) is_finalized: bool,
    pub(crate) predicate: PlonkPredicate<'a, InnerPairingEngine>,
}

impl<'a> PredicateTrait<'a> for Predicate<'a> {
    /// the actual, unwrapped predicate.
    type PlonkPredicate = PlonkPredicate<'a, InnerPairingEngine>;

    /// the circuit corresponding to this predicate
    type PredicateCircuit = PredicateCircuit;

    /// Proving key
    type ProvingKey = ProvingKey<'a, InnerPairingEngine>;

    /// Verification key
    type VerificationKey = VerifyingKey<InnerPairingEngine>;

    /// Proof for predicate satisfaction
    type Proof = BatchProof<InnerPairingEngine>;

    /// Blinding factor
    type BlindFactor = InnerScalarField;

    /// Get the actual, unwrapped predicate.
    fn predicate(&self) -> Self::PlonkPredicate {
        // TODO: improve the code here to avoid the clones
        self.predicate.clone()
    }

    /// Get the number of constraints in the underlying `PredicateCircuit`
    fn num_constraints(&self) -> usize {
        // TODO: (alex) poor API design, can't get a immutable reference to the
        // underlying `PlonkCircuit`/`Instance` in jf-plonk
        self.predicate().circuit_mut_ref().num_gates()
    }

    /// Return a pointer to the verification key
    fn verifying_key(&self) -> &Self::VerificationKey {
        self.predicate.verify_key_ref()
    }

    /// Generate a new predicate given the following inputs:
    /// - the SRS
    /// - a dummy description of the circuit
    /// - an indicator whether this is a birth or death predicate
    /// Output the predicate or an error
    fn new(
        srs: &'a InnerUniversalParam,
        circuit: &Self::PredicateCircuit,
        is_birth_predicate: bool,
    ) -> Result<Self, DPCApiError> {
        let circuit_type = if is_birth_predicate {
            MergeableCircuitType::TypeA
        } else {
            MergeableCircuitType::TypeB
        };
        Ok(Predicate {
            predicate: BatchArgument::<InnerPairingEngine>::setup_instance(
                srs,
                // TODO: improve the code here to avoid the clones
                circuit.0.clone(),
                circuit_type,
            )?,
            is_finalized: false,
        })
    }

    fn update_witness(&mut self, circuit: Self::PredicateCircuit) -> Result<(), DPCApiError> {
        if self.is_finalized {
            return Err(DPCApiError::GeneralError(
                "The input predicate is already finalized".to_string(),
            ));
        }

        *self.predicate.circuit_mut_ref() = circuit.0;
        self.is_finalized = true;
        Ok(())
    }
}
/// Generate a proof for the predicate circuit satisfaction
/// input:
/// - birth predicate
/// - death predicate
/// output:
/// - proof
pub fn prove<'a, P, R>(
    rng: &mut R,
    birth_predicates: &[P],
    death_predicates: &[P],
) -> Result<P::Proof, DPCApiError>
where
    R: RngCore + CryptoRng,
    P: PredicateTrait<
        'a,
        Proof = BatchProof<InnerPairingEngine>,
        PlonkPredicate = PlonkPredicate<'a, InnerPairingEngine>,
    >,
{
    let birth_predicates: Vec<P::PlonkPredicate> =
        birth_predicates.iter().map(|x| x.predicate()).collect();
    let death_predicates: Vec<P::PlonkPredicate> =
        death_predicates.iter().map(|x| x.predicate()).collect();

    let proof = BatchArgument::<'a, InnerPairingEngine>::batch_prove::<
        R,
        RescueTranscript<InnerBaseField>,
    >(rng, &birth_predicates, &death_predicates)
    .map_err(|e| {
        DPCApiError::InvalidParameters(format!(
            "Batch proving birth & death predicates failed: {}",
            e
        ))
    })?;

    Ok(proof)
}

/// Verify a batch proof for the inner predicates
/// input:
/// - birth predicate verification key
/// - death predicate verification key
/// - public inputs
/// - batched proof
/// output:
/// - Ok if the verification passes; or an error if fails
pub fn verify<'a, P>(
    birth_vks: &[&P::VerificationKey],
    death_vks: &[&P::VerificationKey],
    public_inputs: &[InnerScalarField],
    batch_proof: &P::Proof,
) -> Result<(), DPCApiError>
where
    P: PredicateTrait<
        'a,
        VerificationKey = VerifyingKey<InnerPairingEngine>,
        Proof = BatchProof<InnerPairingEngine>,
    >,
{
    let verifying_keys =
        BatchArgument::aggregate_verify_keys(birth_vks, death_vks).map_err(|e| {
            DPCApiError::GeneralError(format!("Verification key aggregation failed: {}", e))
        })?;
    let vks_ref: Vec<&VerifyingKey<InnerPairingEngine>> = verifying_keys.iter().collect();
    let merged_pub_input_per_instance: Vec<InnerScalarField> =
        [public_inputs, public_inputs].concat();
    let pub_inputs = vec![&merged_pub_input_per_instance[..]; vks_ref.len()];

    PlonkKzgSnark::<InnerPairingEngine>::verify_batch_proof::<InnerTranscript>(
        &vks_ref,
        &pub_inputs,
        batch_proof,
    )
    .map_err(|e| DPCApiError::InvalidParameters(format!("Inner batch proof is invalid: {}", e)))
}

/// Decide if an inner circuit partial verification proof is valid.
/// input:
/// - open key
/// - inner predicates partial verification proof
/// output:
/// - Ok if the verification passes; or an error if fails
pub(crate) fn decide(
    open_key: &OpenKey<InnerPairingEngine>,
    inner_partial_proof: &InnerPartialVfyProof,
) -> Result<(), DPCApiError> {
    let inner1 = inner_partial_proof.0.into_projective();
    let inner2 = inner_partial_proof.1.into_projective();
    let b = BatchArgument::decide(open_key, inner1, inner2).map_err(|e| {
        DPCApiError::InvalidParameters(format!(
            "Inner partial verification proof is invalid: {}",
            e
        ))
    })?;
    if !b {
        return Err(DPCApiError::GeneralError(
            "Inner partial verification proof doesn't pass the final pairing check".to_string(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::UniformRand;
    use ark_std::{test_rng, vec};
    use jf_plonk::{circuit::Circuit, proof_system::PlonkKzgSnark};

    #[test]
    fn test_predicate_proof() -> Result<(), DPCApiError> {
        // 1. Simulate universal setup
        let rng = &mut test_rng();
        let max_inner_degree = 128 + 2;
        let srs = PlonkKzgSnark::<InnerPairingEngine>::universal_setup(max_inner_degree, rng)?;

        // 2. A user creates new predicates/vks from circuits using Predicate::new().
        let shared_public_input = InnerScalarField::rand(rng);
        let mut birth_predicates = vec![];
        let mut death_predicates = vec![];
        for i in 32..50 {
            let birth_circuit = new_predicate_circuit_for_test(shared_public_input, i, true)?;
            let predicate = Predicate::new(&srs, &birth_circuit, true)?;
            birth_predicates.push(predicate);

            let death_circuit = new_predicate_circuit_for_test(shared_public_input, i, false)?;
            let predicate = Predicate::new(&srs, &death_circuit, false)?;
            death_predicates.push(predicate);
        }

        // 3. The user generates predicate proofs from predicates using prove().
        let batch_proof = prove(rng, &birth_predicates, &death_predicates)?;

        // 4. Prepare verification keys
        let birth_vks: Vec<&<Predicate as PredicateTrait>::VerificationKey> = birth_predicates
            .iter()
            .map(|pred| pred.verifying_key())
            .collect();
        let death_vks: Vec<&<Predicate as PredicateTrait>::VerificationKey> = death_predicates
            .iter()
            .map(|pred| pred.verifying_key())
            .collect();

        // 5. Before feeding proofs/vks as witness to the outer circuit, the user checks
        // that the inner proofs/vks are correct using verify().
        assert!(
            verify::<Predicate>(&birth_vks, &death_vks, &[shared_public_input], &batch_proof)
                .is_ok()
        );

        // bad path: incorrect vks
        let wrong_birth_vks = birth_vks[1..].to_vec();
        assert!(verify::<Predicate>(
            &wrong_birth_vks,
            &death_vks,
            &[shared_public_input],
            &batch_proof
        )
        .is_err());

        let wrong_death_vks = death_vks[1..].to_vec();
        assert!(verify::<Predicate>(
            &birth_vks,
            &wrong_death_vks,
            &[shared_public_input],
            &batch_proof
        )
        .is_err());

        // bad path: wrong input
        let wrong_shared_public_input = InnerScalarField::rand(rng);
        assert!(verify::<Predicate>(
            &birth_vks,
            &death_vks,
            &[wrong_shared_public_input],
            &batch_proof
        )
        .is_err());

        // bad path: wrong proof
        let wrong_proof = BatchProof::dummy(max_inner_degree);
        assert!(
            verify::<Predicate>(&birth_vks, &death_vks, &[shared_public_input], &wrong_proof)
                .is_err()
        );

        Ok(())
    }

    fn new_predicate_circuit_for_test<'a>(
        shared_public_input: InnerScalarField,
        i: usize,
        is_birth_predicate: bool,
    ) -> Result<<Predicate<'a> as PredicateTrait<'a>>::PredicateCircuit, DPCApiError> {
        let mut circuit = PlonkCircuit::new_turbo_plonk();
        let shared_pub_var = circuit.create_public_variable(shared_public_input)?;
        let mut var = shared_pub_var;
        if is_birth_predicate {
            // compute birth predicates: add `shared_public_input` by i times
            for _ in 0..i {
                var = circuit.add(var, shared_pub_var)?;
            }
        } else {
            // compute death predicates: mul `shared_public_input` by i times
            for _ in 0..i {
                var = circuit.mul(var, shared_pub_var)?;
            }
        }
        Ok(PredicateCircuit(circuit))
    }
}
