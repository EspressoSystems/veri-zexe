// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the VeriZexe library.

// This program is free software: you can redistribute it and/or modify it under
// the terms of the GNU General Public License as published by the Free Software
// Foundation, either version 3 of the License, or (at your option) any later
// version. This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
// details. You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>.

//! Data structures used in DPC scheme
use crate::{
    constants::{MEMO_LEN, NATIVE_ASSET_CODE, PAYLOAD_DATA_LEN, TREE_DEPTH},
    errors::DPCApiError,
    keys::{
        DetectionKeyPair, DetectionPubKey, DiversifiedAddress, DiversifierRandomizer,
        IncomingViewingKey, NullifierDerivingKey, ProofGenerationKey,
    },
    types::*,
};
use ark_ec::{group::Group, models::twisted_edwards_extended::GroupProjective};
use ark_ff::UniformRand;
use ark_serialize::{CanonicalSerialize, *};
use ark_std::{
    borrow::ToOwned,
    format,
    rand::{CryptoRng, RngCore},
    string::ToString,
    vec,
    vec::Vec,
    Zero,
};
use chacha20poly1305::{
    aead::{Aead, NewAead},
    ChaCha20Poly1305, Nonce,
};
use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT,
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar as Curve25519Scalar,
};
use hkdf::Hkdf;
use jf_plonk::proof_system::structs::VerifyingKey;
use jf_primitives::{
    commitment::Commitment, hash_to_group::TEHashToGroup, merkle_tree::AccMemberWitness, prf::PRF,
};
use jf_rescue::Permutation;
use jf_utils::{fq_to_fr_with_mask, tagged_blob};

#[tagged_blob("NULLIFIER")]
#[derive(Clone, Default, Debug, PartialEq, Eq, Hash, CanonicalSerialize, CanonicalDeserialize)]
/// Record nullifier, unique across ledger to prevent double spending
pub struct Nullifier(pub(crate) InnerScalarField);

#[tagged_blob("POLICY_ID")]
#[derive(
    Copy, Clone, Default, Debug, PartialEq, Eq, Hash, CanonicalSerialize, CanonicalDeserialize,
)]
/// Record policy identifier
pub struct PolicyIdentifier(pub(crate) InnerScalarField);

impl PolicyIdentifier {
    pub(crate) fn from_verifying_key(vk: &VerifyingKey<InnerPairingEngine>) -> Self {
        let rescue = Permutation::default();
        let tmp = rescue.sponge_with_padding(&vk.convert_te_coordinates_to_scalars(), 1)[0];
        Self(fq_to_fr_with_mask::<InnerBaseField, InnerScalarField>(&tmp))
    }
    pub(crate) fn from_verifying_keys(vks: &[VerifyingKey<InnerPairingEngine>]) -> Vec<Self> {
        vks.iter().map(|vk| Self::from_verifying_key(vk)).collect()
    }
}

#[tagged_blob("REC_OPENING")]
#[derive(Clone, Default, Debug, PartialEq, Eq, Hash, CanonicalSerialize, CanonicalDeserialize)]
/// DPC record plaintext data
pub struct RecordOpening {
    pub(crate) addr: DiversifiedAddress,
    pub(crate) payload: Payload,
    pub(crate) pid_birth: InnerScalarField,
    pub(crate) pid_death: InnerScalarField,
    pub(crate) nonce: InnerScalarField,
    pub(crate) blinding: InnerScalarField,
}

impl RecordOpening {
    /// Create a new record opening
    pub fn new<R: CryptoRng + RngCore>(
        rng: &mut R,
        addr: DiversifiedAddress,
        payload: Payload,
        pid_birth: InnerScalarField,
        pid_death: InnerScalarField,
        position_in_note: usize,
        note_first_nullifier: Nullifier,
    ) -> RecordOpening {
        let blinding = InnerScalarField::rand(rng);
        let hash = jf_rescue::Permutation::default();
        let input = [
            InnerScalarField::from(position_in_note as u64),
            note_first_nullifier.0,
        ];
        let nonce = hash.sponge_with_padding(&input[..], 1);
        RecordOpening {
            addr,
            payload,
            pid_birth,
            pid_death,
            nonce: nonce[0],
            blinding,
        }
    }

    /// Sample a new native asset record
    pub fn new_native_asset<R: CryptoRng + RngCore>(
        rng: &mut R,
        addr: DiversifiedAddress,
        amount: u128,
        position_in_note: usize,
        note_first_nullifier: Nullifier,
    ) -> Self {
        let mut payload = Payload::default();
        payload.data[0] = NATIVE_ASSET_CODE;
        payload.data[1] = InnerScalarField::from(amount);
        Self::new(
            rng,
            addr,
            payload,
            InnerScalarField::zero(),
            InnerScalarField::zero(),
            position_in_note,
            note_first_nullifier,
        )
    }

    /// Return a dummy record
    pub fn dummy() -> Self {
        Self {
            addr: DiversifiedAddress::default(),
            payload: Payload::dummy(),
            pid_birth: PolicyIdentifier::default().0,
            pid_death: PolicyIdentifier::default().0,
            nonce: InnerScalarField::zero(),
            blinding: InnerScalarField::zero(),
        }
    }

    /// Return a dummy record
    pub fn dummy_with_pid(pid_birth: PolicyIdentifier, pid_death: PolicyIdentifier) -> Self {
        Self {
            addr: DiversifiedAddress::default(),
            payload: Payload::dummy(),
            pid_birth: pid_birth.0,
            pid_death: pid_death.0,
            nonce: InnerScalarField::zero(),
            blinding: InnerScalarField::zero(),
        }
    }

    /// Compute record commitment for record
    pub fn derive_record_commitment(&self) -> Result<CommitmentValue, DPCApiError> {
        let mut msg = self.addr.to_elems();
        msg.push(InnerScalarField::from(self.payload.is_dummy as u128));
        msg.extend_from_slice(&self.payload.data);
        msg.push(self.pid_birth);
        msg.push(self.pid_death);
        msg.push(self.nonce);

        let comm_scheme =
            jf_primitives::commitment::Commitment::new(7usize + (PAYLOAD_DATA_LEN as usize));
        comm_scheme
            .commit(&msg, &self.blinding)
            .map_err(DPCApiError::FailedPrimitives)
    }

    /// Nullify a record and return the nullifier
    pub fn nullify(&self, nk: &NullifierDerivingKey) -> Result<Nullifier, DPCApiError> {
        let nullifier_value = PRF::new(1, 1).eval(&nk.0, &[self.nonce])?[0];
        Ok(Nullifier(nullifier_value))
    }
}

/// Memos for receiver of the output records of a transaction.
#[tagged_blob("RECMEMO")]
#[derive(Clone, Default, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct ReceiverMemo {
    /// ephemeral public key
    pub epk: GroupProjective<InnerEmbeddedGroup>,
    /// ciphertext under derived, shared symmetric key
    pub ct: Vec<u8>,
    /// detection tag for outsourced `ReceiverMemo` detection
    pub tag: Option<DetectionTag>,
}

impl ReceiverMemo {
    // Calculate the shared symmetric encryption key.
    // Return KDF(DH(public, private))
    #[allow(dead_code)] // TODO remove it
    fn derive_enc_key(
        public: &GroupProjective<InnerEmbeddedGroup>,
        private: &InnerEmbeddedScalarField,
    ) -> Result<chacha20poly1305::Key, DPCApiError> {
        let shared_key = Group::mul(public, private);
        let mut shared_key_bytes = Vec::new();
        shared_key.serialize(&mut shared_key_bytes)?;

        let h = Hkdf::<sha2::Sha256>::new(None, &shared_key_bytes); // empty salt is fine
        let mut okm = [0u8; 32]; // output key material size is 32 for Chacha20Poly1305
        h.expand(&[], &mut okm).map_err(|e| {
            DPCApiError::GeneralError(format!(
                "HKDF failed during receiver memo enc key derivation: {:?}",
                e
            ))
        })?;
        Ok(chacha20poly1305::Key::from_slice(&okm).to_owned())
    }

    // internal function to create `ReceiverMemo` from data in plaintext bytes.
    #[allow(dead_code)] // TODO remove it
    pub(crate) fn from_bytes<R: CryptoRng + RngCore>(
        rng: &mut R,
        data: &[u8],
        receiver: &DiversifiedAddress,
    ) -> Result<Self, DPCApiError> {
        // randomly sample an ephemeral secret key,
        let esk: InnerEmbeddedScalarField = InnerEmbeddedScalarField::rand(rng);
        // diversified base `g_d = HashToGroup(d)`
        let diversified_base = {
            let mut d_bytes = vec![];
            receiver.d.serialize(&mut d_bytes)?;
            <InnerEmbeddedGroup as TEHashToGroup>::hash_to_group::<&[u8]>(
                &d_bytes,
                "diversified base".as_ref(),
            )?
        };

        // derive ephemeral public key `epk = g_d ^ esk`
        let epk = Group::mul(&diversified_base, &esk);
        // enc key = KDF(pk_d ^ esk)
        let enc_key = Self::derive_enc_key(&receiver.pk, &esk)?;

        // use ChaCha20Poly1305 for symmetric encryption
        let sym_cipher = ChaCha20Poly1305::new(&enc_key);
        // NOTE: usually unique nonce is never to be reused for the same key, but we
        // sample a new key for each data, therefore it is fine.
        let nonce = Nonce::default();
        let ct = sym_cipher.encrypt(&nonce, data).map_err(|e| {
            DPCApiError::GeneralError(format!("symmetric encryption failed: {:?}", e))
        })?;

        Ok(Self { epk, ct, tag: None })
    }

    /// Decrypt the receiver memo with the correct `IncomingViewKey`
    pub fn decrypt(&self, ivk: &IncomingViewingKey) -> Result<Vec<u8>, DPCApiError> {
        let dec_key = Self::derive_enc_key(&self.epk, &ivk.0)?;
        let sym_cipher = ChaCha20Poly1305::new(&dec_key);
        let nonce = Nonce::default();
        let data = sym_cipher
            .decrypt(&nonce, self.ct.as_slice())
            .map_err(|e| {
                DPCApiError::GeneralError(format!("symmetric decryption failed: {:?}", e))
            })?;
        Ok(data)
    }
}

/// Detection tag for detector to quickly filter out transactions (specifically
/// their `ReceiverMemo`s) under a detection key.
#[tagged_blob("DETTAG")]
#[derive(Clone, Default, Debug, PartialEq, Eq)]
pub struct DetectionTag {
    /// random point: `r = g^\gamma` where `\gamma` is a random scalar
    pub r: RistrettoPoint,
    /// t = `dpk^\gamma = g^(\gamma * dsk)` where `(dsk, dpk)` are detection
    /// private/public keys.
    pub t: RistrettoPoint,
}

impl DetectionTag {
    /// Create a tag for `DetectionPubKey`.
    pub fn create<R>(rng: &mut R, dpk: &DetectionPubKey) -> Self
    where
        R: RngCore + CryptoRng,
    {
        let gamma = Curve25519Scalar::random(rng);
        let r = RISTRETTO_BASEPOINT_POINT * gamma;
        let t = dpk.0 * gamma;
        Self { r, t }
    }

    /// Detect if this tag belongs to `dk`
    pub fn detect(&self, dk: &DetectionKeyPair) -> bool {
        self.t == dk.sk * self.r
    }
}
impl CanonicalSerialize for DetectionTag {
    fn serialize<W>(&self, mut w: W) -> Result<(), ark_serialize::SerializationError>
    where
        W: ark_serialize::Write,
    {
        let len = 32u8;
        // Scalar is 32 bytes
        len.serialize(&mut w)?;
        w.write_all(self.r.compress().as_bytes())?;

        // So is a compressed Ristretto group
        len.serialize(&mut w)?;
        w.write_all(self.t.compress().as_bytes())?;
        Ok(())
    }

    fn serialized_size(&self) -> usize {
        core::mem::size_of::<u8>() * 2 + 32 * 2
    }
}

impl CanonicalDeserialize for DetectionTag {
    fn deserialize<R>(mut reader: R) -> Result<Self, ark_serialize::SerializationError>
    where
        R: ark_serialize::Read,
    {
        let len = u8::deserialize(&mut reader)?;
        if len != 32 {
            return Err(ark_serialize::SerializationError::InvalidData);
        }
        let mut point = [0u8; 32];
        reader.read_exact(&mut point)?;
        let r = CompressedRistretto::from_slice(&point)
            .decompress()
            .ok_or(ark_serialize::SerializationError::InvalidData)?;

        let len = u8::deserialize(&mut reader)?;
        if len != 32 {
            return Err(ark_serialize::SerializationError::InvalidData);
        }
        let mut point = [0u8; 32];
        reader.read_exact(&mut point)?;
        let t = CompressedRistretto::from_slice(&point)
            .decompress()
            .ok_or(ark_serialize::SerializationError::InvalidData)?;
        Ok(Self { r, t })
    }
}

/// Record Payload
#[tagged_blob("PAYLOAD")]
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Payload {
    /// true only if record is dummy
    pub is_dummy: bool,
    pub(crate) data: [InnerScalarField; PAYLOAD_DATA_LEN],
}

impl CanonicalSerialize for Payload {
    fn serialize<W>(&self, mut writer: W) -> Result<(), ark_serialize::SerializationError>
    where
        W: ark_serialize::Write,
    {
        writer.write_all(&[self.is_dummy as u8])?;
        for e in self.data.iter() {
            e.serialize(&mut writer)?
        }
        Ok(())
    }

    fn serialized_size(&self) -> usize {
        PAYLOAD_DATA_LEN * self.data[0].serialized_size() + 1
    }
}

impl CanonicalDeserialize for Payload {
    fn deserialize<R>(mut reader: R) -> Result<Self, ark_serialize::SerializationError>
    where
        R: ark_serialize::Read,
    {
        let mut res = Self::default();
        let mut is_dummy = [0u8; 1];
        reader.read_exact(&mut is_dummy)?;

        res.is_dummy = match is_dummy[0] {
            1 => true,
            0 => false,
            _ => return Err(ark_serialize::SerializationError::InvalidData),
        };
        for e in res.data.iter_mut() {
            *e = InnerScalarField::deserialize(&mut reader)?;
        }
        Ok(res)
    }
}

impl Payload {
    /// Creating a dummy payload.
    fn dummy() -> Payload {
        Self {
            is_dummy: true,
            data: [InnerScalarField::zero(); PAYLOAD_DATA_LEN as usize],
        }
    }

    /// Build the payload from a list of scalars. Pad with zeros if the input
    /// length is less than PAYLOAD_DATA_LEN; return an error if the length
    /// exceeds PAYLOAD_DATA_LEN.
    pub fn from_scalars(scalars: &[InnerScalarField]) -> Result<Self, DPCApiError> {
        if scalars.len() > PAYLOAD_DATA_LEN as usize {
            return Err(DPCApiError::InvalidParameters(format!(
                "input payload length {} is greater than max allowed {}",
                scalars.len(),
                PAYLOAD_DATA_LEN
            )));
        }

        let mut res = Self::default();
        for (i, &scalar) in scalars.iter().enumerate() {
            res.data[i] = scalar;
        }
        res.is_dummy = false;

        Ok(res)
    }
}
impl Default for Payload {
    fn default() -> Self {
        Self {
            is_dummy: false,
            data: [InnerScalarField::zero(); PAYLOAD_DATA_LEN as usize],
        }
    }
}

/// Commitment structure
#[derive(Clone, Default, Debug, PartialEq, Eq)]
pub struct CompressedLocalData {
    pub(crate) input_record_commitments: Vec<CommitmentValue>,
    pub(crate) output_record_commitments: Vec<CommitmentValue>,
    pub(crate) memo: Vec<InnerScalarField>,
}

impl CompressedLocalData {
    pub(crate) fn commit(
        &self,
        blinding: InnerScalarField,
    ) -> Result<CommitmentValue, DPCApiError> {
        let mut msg = vec![];
        for in_rc in self.input_record_commitments.iter() {
            msg.push(*in_rc)
        }

        for out_rc in self.output_record_commitments.iter() {
            msg.push(*out_rc)
        }
        msg.extend_from_slice(&self.memo);
        let com_scheme = jf_primitives::commitment::Commitment::new(msg.len());
        com_scheme
            .commit(&msg, &blinding)
            .map_err(DPCApiError::FailedPrimitives)
    }

    // Convert to scalars. Used in inner predicate generation
    #[allow(dead_code)] // TODO: remove
    pub(crate) fn to_scalars(&self) -> Vec<InnerScalarField> {
        let mut res = self.input_record_commitments.clone();
        res.extend_from_slice(&self.output_record_commitments[..]);
        res.extend_from_slice(&self.memo[..]);
        res
    }

    // create a dummy CompressedLocalData with n inputs
    #[allow(dead_code)]
    pub(crate) fn dummy(input_size: usize) -> Self {
        Self {
            input_record_commitments: vec![CommitmentValue::default(); input_size],
            output_record_commitments: vec![CommitmentValue::default(); input_size],
            memo: vec![CommitmentValue::default(); MEMO_LEN],
        }
    }
}

#[derive(Clone, Debug)]
/// A DPC Transaction Note input record and spending data
pub struct NoteInput<'a> {
    /// Record Opening of the input
    pub ro: RecordOpening,
    /// Witness of record membership in accumulator
    pub acc_member_witness: AccMemberWitness<InnerScalarField>,
    /// Proof generation key
    pub proof_gen_key: &'a ProofGenerationKey,
    /// Authorization randomizer
    pub authorization_randomizer: GroupProjective<InnerEmbeddedGroup>,
    /// Diversifier randomizer
    pub diversifier_randomizer: DiversifierRandomizer,
}

impl<'a> NoteInput<'a> {
    /// Create a dummy note input.
    pub fn dummy(proof_gen_key: &'a ProofGenerationKey) -> Self {
        Self {
            ro: RecordOpening::dummy(),
            acc_member_witness: AccMemberWitness::dummy(TREE_DEPTH),
            proof_gen_key,
            authorization_randomizer: Default::default(),
            diversifier_randomizer: DiversifierRandomizer(InnerScalarField::zero()),
        }
    }

    /// Create a dummy note input.
    pub fn dummy_with_pid(
        proof_gen_key: &'a ProofGenerationKey,
        pid_birth: PolicyIdentifier,
        pid_death: PolicyIdentifier,
    ) -> Self {
        Self {
            ro: RecordOpening::dummy_with_pid(pid_birth, pid_death),
            acc_member_witness: AccMemberWitness::dummy(TREE_DEPTH),
            proof_gen_key,
            authorization_randomizer: Default::default(),
            diversifier_randomizer: DiversifierRandomizer(InnerScalarField::zero()),
        }
    }
}

// Derive predicates/policies commitment from policy identifiers and blinding
// factor.
pub(crate) fn derive_predicates_commitment(
    input_death_pids: &[InnerScalarField],
    output_birth_pids: &[InnerScalarField],
    blind_comm_predicates: InnerScalarField,
) -> Result<CommitmentValue, DPCApiError> {
    if input_death_pids.len() != output_birth_pids.len() {
        return Err(DPCApiError::InvalidParameters(
            "input death predicates and output birth predicates length mismatch".to_string(),
        ));
    }
    let input_len = 2 * input_death_pids.len();
    let comm = Commitment::new(input_len);
    let input = [input_death_pids, output_birth_pids].concat();
    comm.commit(&input, &blind_comm_predicates)
        .map_err(DPCApiError::FailedPrimitives)
}

// this function compresses the entire local data (including fees).
pub(crate) fn compress_local_data(
    entire_note_inputs: &[NoteInput],
    entire_output_ros: &[RecordOpening],
    memo: Vec<InnerScalarField>,
) -> Result<CompressedLocalData, DPCApiError> {
    let mut input_record_commitments = vec![];
    let mut output_record_commitments = vec![];
    for input in entire_note_inputs.iter() {
        input_record_commitments.push(input.ro.derive_record_commitment()?)
    }
    for output in entire_output_ros.iter() {
        output_record_commitments.push(output.derive_record_commitment()?)
    }

    Ok(CompressedLocalData {
        input_record_commitments,
        output_record_commitments,
        memo,
    })
}

#[cfg(test)]
mod test {
    use crate::{
        constants::{NATIVE_ASSET_CODE, PAYLOAD_DATA_LEN},
        errors::DPCApiError,
        keys::{DetectionKeyPair, KeyChainMasterKey},
        structs::{DetectionTag, Nullifier, Payload, ReceiverMemo, RecordOpening},
        types::InnerScalarField,
    };
    use ark_ff::Zero;
    use jf_utils::test_serde_default;

    #[test]
    fn receiver_memo_enc_dec() -> Result<(), DPCApiError> {
        let rng = &mut ark_std::test_rng();

        let wsk = KeyChainMasterKey::test_rand(rng);
        let wsk2 = KeyChainMasterKey::test_rand(rng);
        let (_ask, pgk, ivk) = wsk.derive_key_chain_single_consumer();
        let (_ask2, _pgk2, ivk2) = wsk2.derive_key_chain_single_consumer();
        let (addr, _d) = wsk.derive_diversified_address(&pgk, &ivk, 0)?;

        let data = b"record opening blah".to_vec();
        let memo = ReceiverMemo::from_bytes(rng, &data, &addr)?;
        assert!(memo.decrypt(&ivk).is_ok());
        assert!(memo.decrypt(&ivk2).is_err());

        let decrypted = memo.decrypt(&ivk)?;
        assert_eq!(data, decrypted);
        Ok(())
    }

    #[test]
    fn detection_tag() {
        let rng = &mut ark_std::test_rng();

        let dk = DetectionKeyPair::generate(rng);
        let dpk = dk.public_key();
        let dk2 = DetectionKeyPair::generate(rng);

        let tag = DetectionTag::create(rng, &dpk);
        assert_eq!(tag.detect(&dk), true);
        assert_eq!(tag.detect(&dk2), false);
    }

    #[test]
    fn test_record() -> Result<(), DPCApiError> {
        let rng = &mut ark_std::test_rng();
        let wsk = KeyChainMasterKey::test_rand(rng);
        let (_ask, pgk, ivk) = wsk.derive_key_chain_single_consumer();
        let (addr, _d) = wsk.derive_diversified_address(&pgk, &ivk, 0)?;

        let ro_native0 =
            RecordOpening::new_native_asset(rng, addr.clone(), 10, 0, Nullifier::default());

        let mut expected_payload_data = [InnerScalarField::zero(); PAYLOAD_DATA_LEN as usize];
        expected_payload_data[0] = NATIVE_ASSET_CODE;
        expected_payload_data[1] = InnerScalarField::from(10u128);

        assert!(!ro_native0.payload.is_dummy);
        assert_eq!(&ro_native0.payload.data, &expected_payload_data);

        assert!(RecordOpening::dummy().payload.is_dummy);

        let ro_native1 = RecordOpening::new_native_asset(rng, addr, 10, 1, Nullifier::default());
        let commitment0 = ro_native0.derive_record_commitment()?;
        let commitment1 = ro_native1.derive_record_commitment()?;
        assert_ne!(commitment0, commitment1);

        let nullifier0 = ro_native0.nullify(&pgk.nk)?;
        let nullifier1 = ro_native1.nullify(&pgk.nk)?;
        assert_ne!(nullifier0, nullifier1);

        Ok(())
    }

    #[test]
    fn test_serde() {
        test_serde_default!(DetectionTag);
        test_serde_default!(ReceiverMemo);
        test_serde_default!(RecordOpening);
        test_serde_default!(Payload);
    }
}
