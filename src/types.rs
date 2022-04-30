//! Type information about curve choices

#![allow(dead_code)]
use ark_ec::{ModelParameters, PairingEngine};
use jf_plonk::transcript::RescueTranscript;

/// type alias for pairing engine of the inner circuit (BLS).
pub type InnerPairingEngine = ark_bls12_377::Bls12_377;

/// type alias for source group 1 curve for the inner circuit.
pub type InnerG1Group = ark_bls12_377::g1::Parameters;

/// type alias for affine source group elements for the inner circuit.
pub type InnerG1Affine = ark_bls12_377::G1Affine;

/// type alias for projective source group elements for the inner circuit.
pub type InnerG1Projective = ark_bls12_377::G1Projective;

/// type alias for embeded curve of the inner circuit (Jubjub).
pub type InnerEmbeddedGroup = ark_ed_on_bls12_377::EdwardsParameters;

/// type alias for pairing engine of the outer circuit (BW).
pub type OuterPairingEngine = ark_bw6_761::BW6_761;

/// type alias for scalar field of the inner curve (BLS12).
/// Should be equivalent to `InnerEmbeddedBaseField`.
pub type InnerScalarField = <InnerPairingEngine as PairingEngine>::Fr;

/// type alias for base field of the inner curve (BLS12).
/// Should be equivalent to `OuterScalarField`.
pub type InnerBaseField = <InnerPairingEngine as PairingEngine>::Fq;

/// type alias for scalar field of the embedded curve of the inner circuit
/// (Jubjub Scalar).
pub type InnerEmbeddedScalarField = <InnerEmbeddedGroup as ModelParameters>::ScalarField;

/// type alias for scalar field of the embedded curve of the inner circuit
/// (Jubjub Scalar).
/// Should be equivalent to `InnerScalarField`, use `InnerScalarField` when
/// possible.
pub type InnerEmbeddedBaseField = <InnerEmbeddedGroup as ModelParameters>::BaseField;

/// type alias for scalar field of the outer curve (BW6).
/// Should be equivalent to `InnerBaseField`.
pub type OuterScalarField = <OuterPairingEngine as PairingEngine>::Fr;

/// type alias for base field of the outer curve (BW6).
pub type OuterBaseField = <OuterPairingEngine as PairingEngine>::Fq;

/// type alias for inner proof Fiat-Shamir transcripts.
pub type InnerTranscript = RescueTranscript<InnerBaseField>;

#[cfg(test)]
mod test {
    use super::*;
    use ark_ff::{FpParameters, PrimeField};

    macro_rules! test_equal_field {
        ($f1:tt, $f2:tt) => {
            assert_eq!(
                <<$f1 as PrimeField>::Params as FpParameters>::MODULUS,
                <<$f2 as PrimeField>::Params as FpParameters>::MODULUS
            );
        };
    }

    #[test]
    fn curve_choice_sanity_check() {
        test_equal_field!(InnerEmbeddedBaseField, InnerScalarField);
        test_equal_field!(InnerBaseField, OuterScalarField);
    }
}

use jf_plonk::proof_system::structs::UniversalSrs;
use jf_primitives::{merkle_tree, signatures::schnorr};

/// type alias for scalar field of the bls curve
pub type NodeValue = merkle_tree::NodeValue<InnerScalarField>;
/// type alias for signature verification key
pub type Signature = schnorr::Signature<InnerEmbeddedGroup>;
/// type alias for signature verification key
pub type SigVerKey = schnorr::VerKey<InnerEmbeddedGroup>;
/// type alias for signing keypair
pub type SigKeyPair = schnorr::KeyPair<InnerEmbeddedGroup>;
/// type alies for commitments
pub type CommitmentValue = InnerScalarField;

/// The universal parameters (Structured Reference String) for proving/verifying
/// UTXO relations and inner predicate policies. Generate only once during a
/// multi-party setup. For testing purpose, use `universal_setup()` for a
/// one-time generation.
pub type InnerUniversalParam = UniversalSrs<InnerPairingEngine>;

/// The universal parameters (Structured Reference String) for proving/verifying
/// the outer relation that recursively verifies the inner policy proofs.
/// Generate only once during a multi-party setup. For testing purpose, use
/// `universal_setup()` for a one-time generation.
pub type OuterUniversalParam = UniversalSrs<OuterPairingEngine>;
