//! DPC transaction API to build DPCTxnNote
use crate::{
    errors::DPCApiError,
    proofs::{
        predicates::Predicate,
        transaction::{
            DPCProvingKey, DPCPublicInput, DPCValidityProof, DPCVerifyingKey, DPCWitness,
        },
        utxo::DPCUtxoPublicInput,
    },
    structs::{NoteInput, Nullifier, RecordOpening},
    types::{CommitmentValue, InnerScalarField, NodeValue, SigKeyPair, SigVerKey},
};
use ark_serialize::{CanonicalSerialize, *};
use ark_std::{
    rand::{CryptoRng, RngCore},
    string::ToString,
    vec::Vec,
};
use jf_utils::{hash_to_field, tagged_blob};

/// DPC transaction note body
#[tagged_blob("DPC_NOTE")]
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct DPCTxnNote {
    /// Transaction body
    pub body: DPCTxnBody,
    /// Authorization signature
    pub signature: crate::types::Signature,
}

impl DPCTxnNote {
    /// Verify transaction note
    pub fn verify(
        &self,
        verifying_key: &DPCVerifyingKey,
        merkle_root: NodeValue,
    ) -> Result<(), DPCApiError> {
        self.verify_validity_proof(verifying_key, merkle_root)?;
        self.verify_authorization()
    }

    /// Verify transaction body validity proof
    pub(crate) fn verify_validity_proof(
        &self,
        verifying_key: &DPCVerifyingKey,
        merkle_root: NodeValue,
    ) -> Result<(), DPCApiError> {
        self.body.verify_validity_proof(verifying_key, merkle_root)
    }

    /// Verify authorization signature
    pub fn verify_authorization(&self) -> Result<(), DPCApiError> {
        let hashed_body = self.body.hash_to_inner_scalar()?;
        self.body
            .aux_info
            .auth_verification_key
            .verify(&[hashed_body], &self.signature)
            .map_err(DPCApiError::FailedAuthorizationSignature)
    }
}
/// DPC transaction note body
#[tagged_blob("DPC_NOTE_BODY")]
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct DPCTxnBody {
    /// Input nullifiers, not including fee input
    pub input_nullifiers: Vec<Nullifier>,
    /// Output record commitment, not including fee change output
    pub output_commitments: Vec<CommitmentValue>,
    /// Arbitrary note memo data
    pub memo: Vec<InnerScalarField>,
    /// Auxiliary information such as valid Merkle root, fee information (value,
    /// input, change outpout)
    pub aux_info: DPCNoteAuxInfo,
    /// Commitment to input and output predicates
    pub(crate) predicates_commitment: CommitmentValue,
    /// Commitment to local data
    pub(crate) local_data_commitment: CommitmentValue,
    /// Proof of validity of DPC transaction
    pub(crate) proof: DPCValidityProof,
}

/// Auxiliary information associated with a transaction note, such as merkle
/// root and fee
#[tagged_blob("DPC_NOTE_AUX_INFO")]
#[derive(Clone, Default, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct DPCNoteAuxInfo {
    /// Accumulator state
    pub merkle_root: NodeValue,
    /// Proposed fee in native asset type for the transfer
    pub fee: u64,
    /// Authorization verification key
    pub auth_verification_key: SigVerKey,
}

impl DPCTxnBody {
    /// Generate a DPC transaction Body
    ///
    /// NOTE: `input_death_predicates` and `output_birth_predicates` exclude
    /// that of the first input (fee) and output (fee change) since their don't
    /// have any predicate.
    #[allow(clippy::too_many_arguments)]
    pub fn generate<'a, R: CryptoRng + RngCore>(
        rng: &mut R,
        proving_key: &DPCProvingKey,
        inputs: Vec<NoteInput<'a>>,
        outputs: Vec<RecordOpening>,
        input_death_predicates: &[Predicate],
        output_birth_predicates: &[Predicate],
        fee: u64,
        memo: Vec<InnerScalarField>,
        local_data_commitment_randomness: InnerScalarField,
    ) -> Result<DPCTxnBody, DPCApiError> {
        // check parameters are correct
        crate::utils::txn_parameter_sanity_check(
            &inputs,
            &outputs,
            input_death_predicates,
            output_birth_predicates,
            fee,
        )?;

        // assemble witness
        let witness = DPCWitness::new_unchecked(
            rng,
            inputs,
            outputs,
            input_death_predicates,
            output_birth_predicates,
            local_data_commitment_randomness,
        )?;
        // derive transaction public inputs
        let pub_input = DPCPublicInput::from_witness(&witness, fee, memo, proving_key.beta_g)?;

        let proof = crate::proofs::transaction::prove(rng, proving_key, &witness, &pub_input)?;

        Ok(DPCTxnBody {
            input_nullifiers: pub_input.utxo_public_input.input_nullifiers,
            output_commitments: pub_input.utxo_public_input.output_commitments,
            memo: pub_input.utxo_public_input.memo,
            aux_info: DPCNoteAuxInfo {
                merkle_root: pub_input.utxo_public_input.root,
                fee: pub_input.utxo_public_input.fee,
                auth_verification_key: pub_input.utxo_public_input.authorization_verification_key,
            },
            predicates_commitment: pub_input.utxo_public_input.commitment_predicates,
            local_data_commitment: pub_input.utxo_public_input.commitment_local_data,
            proof,
        })
    }

    /// Authorize transaction body by signing it and returning a DPCTxnNote
    /// object
    pub fn authorize(self, authorization_keypair: &SigKeyPair) -> Result<DPCTxnNote, DPCApiError> {
        let hashed = self.hash_to_inner_scalar()?;
        let signature = authorization_keypair.sign(&[hashed]);
        Ok(DPCTxnNote {
            body: self,
            signature,
        })
    }

    /// Verify transaction body validity proof
    pub(crate) fn verify_validity_proof(
        &self,
        verifying_key: &DPCVerifyingKey,
        merkle_root: NodeValue,
    ) -> Result<(), DPCApiError> {
        let pub_input = self.check_instance_and_get_public_input(merkle_root)?;
        crate::proofs::transaction::verify(&self.proof, verifying_key, &pub_input)
    }

    fn check_instance_and_get_public_input(
        &self,
        merkle_root: NodeValue,
    ) -> Result<DPCPublicInput, DPCApiError> {
        // check root consistency
        if merkle_root != self.aux_info.merkle_root {
            return Err(DPCApiError::FailedTransactionVerification(
                "Merkle root do not match".to_string(),
            ));
        }
        let utxo_public_input = DPCUtxoPublicInput {
            root: self.aux_info.merkle_root,
            fee: self.aux_info.fee,
            input_nullifiers: self.input_nullifiers.clone(),
            output_commitments: self.output_commitments.clone(),
            commitment_local_data: self.local_data_commitment,
            commitment_predicates: self.predicates_commitment,
            memo: self.memo.clone(),
            authorization_verification_key: self.aux_info.auth_verification_key.clone(),
        };

        Ok(DPCPublicInput {
            utxo_public_input,
            inner_partial_vfy_proof: self.proof.inner_partial_vfy_proof,
        })
    }

    fn hash_to_inner_scalar(&self) -> Result<InnerScalarField, DPCApiError> {
        let mut serialized_body: Vec<u8> = Vec::new();
        self.serialize(&mut serialized_body).map_err(|_| {
            DPCApiError::InternalError("Unable to serialize transaction body".to_string())
        })?;
        Ok(hash_to_field(&serialized_body))
    }
}
