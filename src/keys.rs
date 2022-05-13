//! Account related data structures, especially spending & viewing keys
use ark_ec::{
    group::Group, twisted_edwards_extended::GroupProjective, AffineCurve, ProjectiveCurve,
};
use ark_ff::{BigInteger, PrimeField};
use ark_serialize::*;
use ark_std::{
    ops::{Add, AddAssign},
    rand::{CryptoRng, RngCore},
    string::ToString,
    vec,
    vec::Vec,
    Zero,
};
use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT,
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar as Curve25519Scalar,
};
use jf_primitives::{commitment, hash_to_group::HashToGroup, prf::PrfKey, signatures::schnorr};
use jf_utils::tagged_blob;

use crate::{constants::dom_sep::*, errors::DPCApiError, types::*};

/// Key pair for transaction authorization
#[tagged_blob("AUTH-KEY")]
#[derive(Clone, Default, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct AuthorizationKeyPair(pub(crate) schnorr::KeyPair<InnerEmbeddedGroup>);

impl AuthorizationKeyPair {
    /// Getter for the public key
    pub fn public_key(&self) -> AuthorizationPubKey {
        AuthorizationPubKey(self.0.ver_key())
    }

    /// Randomize the key pair with the `randomizer`, returns the randomized key
    /// pair.
    pub fn randomize_with<R>(&self, randomizer: &InnerEmbeddedScalarField) -> Self
    where
        R: CryptoRng + RngCore,
    {
        Self(self.0.randomize_with(randomizer))
    }
}

/// Public key for verifying signatures over authorized transactions
#[tagged_blob("AUTH-PUBKEY")]
#[derive(Clone, Default, Debug, PartialEq, Eq, Hash, CanonicalSerialize, CanonicalDeserialize)]
pub struct AuthorizationPubKey(pub(crate) schnorr::VerKey<InnerEmbeddedGroup>);

impl AuthorizationPubKey {
    /// Prepare for circuit-compatible operations by converting to scalar fields
    /// that the circuit is over.
    pub fn prepare(&self) -> (InnerScalarField, InnerScalarField) {
        (&self.0).into()
    }
}

/// Used to derive the signature randomizer to further derive the record
/// nullifier. It is part of the `ProofGenerationKey`
#[tagged_blob("NULL-KEY")]
#[derive(Clone, Default, Debug, PartialEq, Eq, Hash, CanonicalSerialize, CanonicalDeserialize)]
pub struct NullifierDerivingKey(pub(crate) PrfKey<InnerScalarField>);

/// Randomizer for the diversifier of each diversified address.
#[tagged_blob("DIV-RAND")]
#[derive(Clone, Default, Debug, PartialEq, Eq, Hash, CanonicalSerialize, CanonicalDeserialize)]
pub struct DiversifierRandomizer(pub(crate) InnerScalarField);

/// Spending key used to prove correct ownership during SNARK proof generation,
/// consisting of an authorization key `ak`, a nullifier deriving key `nk`, and
/// a diversifier randomizer `rd`.
#[tagged_blob("PROOF-GEN-KEY")]
#[derive(Clone, Default, Debug, PartialEq, Eq, Hash, CanonicalSerialize, CanonicalDeserialize)]
pub struct ProofGenerationKey {
    pub(crate) ak: AuthorizationPubKey,
    pub(crate) nk: NullifierDerivingKey,
}

/// The viewing key to receive all incoming records, shared across all
/// diversified addresses of a key-chain
#[tagged_blob("VIEW-KEY")]
#[derive(Clone, Default, Debug, PartialEq, Eq, Hash, CanonicalSerialize, CanonicalDeserialize)]
pub struct IncomingViewingKey(pub(crate) InnerEmbeddedScalarField);

/// A diverisifed public address to receive records, unlinkable from other
/// addresses even those generated inside the same key-chain, thanks to its
/// unique diversifier `d`.
#[tagged_blob("DIV-ADDR")]
#[derive(Clone, Default, Debug, PartialEq, Eq, Hash, CanonicalSerialize, CanonicalDeserialize)]
pub struct DiversifiedAddress {
    /// diversifier (derived from `ProofGenerationKey` with fresh diversifier
    /// randomizer)
    pub d: InnerScalarField,
    /// diversified public key (derived from diversifier and
    /// `IncomingViewingKey`).
    pub pk: GroupProjective<InnerEmbeddedGroup>,
}

impl DiversifiedAddress {
    pub(crate) fn to_elems(&self) -> Vec<InnerScalarField> {
        let affine = self.pk.into_affine();
        vec![self.d, affine.x, affine.y]
    }
}

/// The master key of a key-chain used to deterministically derive the rest.
#[tagged_blob("KEYCHAIN-MASTER-KEY")]
#[derive(Clone, Default, Debug, PartialEq, Eq, Hash, CanonicalSerialize, CanonicalDeserialize)]
pub struct KeyChainMasterKey(InnerScalarField);

impl KeyChainMasterKey {
    /// Deterministically compute a key-chain for a user
    pub fn generate(wallet_master_key: [u8; 32], aux: &[u8]) -> Self {
        let bytes = [
            KEYCHAIN_MASTERKEY_DOM_SEP.as_bytes(),
            aux,
            &wallet_master_key,
        ]
        .concat();
        let key = jf_utils::hash_to_field(&bytes);
        Self(key)
    }

    /// Key Chain derivation
    pub fn derive_key_chain_single_consumer(
        &self,
    ) -> (AuthorizationKeyPair, ProofGenerationKey, IncomingViewingKey) {
        let ask = self.derive_authorization_key_pair();
        let nk = self.derive_single_consumer_nullifier_deriving_key();
        let ivk = self.derive_incoming_viewing_key();
        let ak = ask.public_key();
        let pgk = ProofGenerationKey { ak, nk };
        (ask, pgk, ivk)
    }

    /// Generate new diversified address
    pub fn derive_diversified_address(
        &self,
        pgk: &ProofGenerationKey,
        ivk: &IncomingViewingKey,
        j: u16,
    ) -> Result<(DiversifiedAddress, DiversifierRandomizer), DPCApiError> {
        let diversifier = self.get_diverisifer_randomizer_by_index(j);
        let d = {
            let (ak_x, ak_y) = pgk.ak.prepare();
            commitment::Commitment::new(3)
                .commit(&[ak_x, ak_y, pgk.nk.0.internal()], &diversifier.0)?
        };

        let pk = {
            // diversified base `g_d = HashToGroup(d)`
            let diversified_base =
                <InnerEmbeddedGroup as HashToGroup>::hash_to_group(&d, &"diversified base")?;

            // diversified public key `pk_d = g_d^ivk`
            Group::mul(&diversified_base, &ivk.0)
        };
        let addr = DiversifiedAddress { d, pk };
        Ok((addr, diversifier))
    }

    /// Get byte representation of key
    pub fn as_bytes(&self) -> Vec<u8> {
        self.0.into_repr().to_bytes_le()
    }
}

#[allow(dead_code)] // TODO remove this
impl KeyChainMasterKey {
    /// Deterministically generate the `AuthorizationKeyPair` of a key-chain
    pub(crate) fn derive_authorization_key_pair(&self) -> AuthorizationKeyPair {
        let bytes = [AUTHORIZATION_KEY_PAIR_DOM_SEP.as_bytes(), &self.as_bytes()].concat();
        let sk = jf_utils::hash_to_field(&bytes);
        let key_pair = schnorr::KeyPair::generate_with_sign_key(sk);
        AuthorizationKeyPair(key_pair)
    }

    /// Deterministically generate the default `NullifierDerivingKey` for a
    /// key-chain with single consumer.
    pub(crate) fn derive_single_consumer_nullifier_deriving_key(&self) -> NullifierDerivingKey {
        let bytes = [NULLIFYING_KEY_DOM_SEP.as_bytes(), &self.as_bytes()].concat();
        let key: InnerScalarField = jf_utils::hash_to_field(&bytes);
        NullifierDerivingKey(key.into())
    }

    /// Generate the app-specific `NullifierDerivingKey` of a key-chain with
    /// multi-consumer support (i.e. "freezer support") via k-DH.
    // TODO: implement interactive k-DH here with (k-1) `others`
    pub(crate) fn generate_multi_consumer_nullifier_deriving_key(
        &self,
        _others: &[GroupProjective<InnerEmbeddedGroup>],
    ) -> NullifierDerivingKey {
        // deterministically calculate: H('DomSep' || wsk)
        let bytes = [NULLIFYING_KEY_DOM_SEP.as_bytes(), &self.as_bytes()].concat();
        let _key: InnerEmbeddedScalarField = jf_utils::hash_to_field(&bytes);
        unimplemented!();
    }

    /// Deterministically generate the `IncomingViewingKey` of the key-chain.
    pub(crate) fn derive_incoming_viewing_key(&self) -> IncomingViewingKey {
        let bytes = [INCOMING_VIEWING_KEY_DOM_SEP.as_bytes(), &self.as_bytes()].concat();
        IncomingViewingKey(jf_utils::hash_to_field(&bytes))
    }

    // /// Generate a new `ParticipationKeyPair` for consensus-related voting
    // pub(crate) fn generate_new_participation_key(
    //     &mut self,
    // ) -> Result<ParticipationKeyPair, DPCError> {
    //     self.increment_nonce()?;
    //     let bytes = [
    //         PARTICIPATION_KEY_DOM_SEP.as_bytes(),
    //         &self.nonce().to_le_bytes(),
    //         &self.key,
    //     ]
    //     .concat();

    //     let sk = bls_signatures::PrivateKey::new(bytes);
    //     let pk = sk.public_key();
    //     Ok(ParticipationKeyPair { sk, pk })
    // }

    // return the rd for `index`-th address
    fn get_diverisifer_randomizer_by_index(&self, index: u16) -> DiversifierRandomizer {
        let bytes = [
            DIVERSIFIER_RAND_DOM_SEP.as_bytes(),
            &index.to_le_bytes(),
            &self.as_bytes(),
        ]
        .concat();
        DiversifierRandomizer(jf_utils::hash_to_field(&bytes))
    }
}

/// Public key to give to senders to generate detection tag
#[tagged_blob("DET-PUBKEY")]
#[derive(Clone, Default, Debug, PartialEq)]
pub struct DetectionPubKey(pub(crate) RistrettoPoint);

impl CanonicalSerialize for DetectionPubKey {
    fn serialize<W>(&self, mut w: W) -> Result<(), ark_serialize::SerializationError>
    where
        W: ark_serialize::Write,
    {
        Ok(w.write_all(self.0.compress().as_bytes())?)
    }

    fn serialized_size(&self) -> usize {
        32
    }
}

impl CanonicalDeserialize for DetectionPubKey {
    fn deserialize<R>(mut r: R) -> Result<Self, ark_serialize::SerializationError>
    where
        R: ark_serialize::Read,
    {
        let mut buf = [0u8; 32];
        r.read_exact(&mut buf)?;
        let point = CompressedRistretto::from_slice(&buf)
            .decompress()
            .ok_or(ark_serialize::SerializationError::InvalidData)?;
        Ok(Self(point))
    }
}

/// Key pair to give to detector to filter out matching `ReceiverMemo`s with
/// designated detection tags.
#[tagged_blob("DET-KEY")]
#[derive(Clone, Default, Debug, PartialEq)]
pub struct DetectionKeyPair {
    pub(crate) sk: Curve25519Scalar,
    pub(crate) pk: RistrettoPoint,
}

impl DetectionKeyPair {
    /// Generate a random key pair
    pub fn generate<R>(rng: &mut R) -> Self
    where
        R: RngCore + CryptoRng,
    {
        let sk = Curve25519Scalar::random(rng);
        let pk = RISTRETTO_BASEPOINT_POINT * sk;
        Self { sk, pk }
    }

    /// Get its public key
    pub fn public_key(&self) -> DetectionPubKey {
        DetectionPubKey(self.pk)
    }
}

impl CanonicalSerialize for DetectionKeyPair {
    fn serialize<W>(&self, mut w: W) -> Result<(), ark_serialize::SerializationError>
    where
        W: ark_serialize::Write,
    {
        let len = 32u8;
        // Scalar is 32 bytes
        len.serialize(&mut w)?;
        w.write_all(self.sk.as_bytes())?;

        // So is a compressed Ristretto group
        len.serialize(&mut w)?;
        w.write_all(self.pk.compress().as_bytes())?;
        Ok(())
    }

    fn serialized_size(&self) -> usize {
        core::mem::size_of::<u8>() * 2 + 32 * 2
    }
}

impl CanonicalDeserialize for DetectionKeyPair {
    fn deserialize<R>(mut r: R) -> Result<Self, ark_serialize::SerializationError>
    where
        R: ark_serialize::Read,
    {
        let len = u8::deserialize(&mut r)?;
        if len != 32 {
            return Err(ark_serialize::SerializationError::InvalidData);
        }
        let mut scalar = [0u8; 32];
        r.read_exact(&mut scalar)?;
        let sk = Curve25519Scalar::from_bytes_mod_order(scalar);

        let len = u8::deserialize(&mut r)?;
        if len != 32 {
            return Err(ark_serialize::SerializationError::InvalidData);
        }
        let mut point = [0u8; 32];
        r.read_exact(&mut point)?;
        let pk = CompressedRistretto::from_slice(&point)
            .decompress()
            .ok_or(ark_serialize::SerializationError::InvalidData)?;

        Ok(Self { sk, pk })
    }
}

/// Aggregate `authorization_keys` and randomize it with `randomizer_scalars` by
/// adding them all.
pub fn aggregate_authorization_signing_keypairs(
    authorization_keys: &[SigKeyPair],
    randomizer_scalars: &[InnerEmbeddedScalarField],
) -> Result<SigKeyPair, DPCApiError> {
    if authorization_keys.len() != randomizer_scalars.len() {
        return Err(DPCApiError::InvalidParameter("authorization_keys length does not match randomizer_scalars length for authorization key aggregation".to_string()));
    }
    let mut aggregated = InnerEmbeddedScalarField::zero();
    for (key, randomizer) in authorization_keys.iter().zip(randomizer_scalars.iter()) {
        aggregated.add_assign(key.sign_key_internal());
        aggregated.add_assign(randomizer);
    }
    let sign_key = SigKeyPair::generate_with_sign_key(aggregated);
    Ok(sign_key)
}

#[allow(dead_code)] // TODO remove this when API is integrated
pub(crate) fn aggregate_authorization_verification_keys(
    verification_keys: &[&SigVerKey],
    randomizers: &[&GroupProjective<InnerEmbeddedGroup>],
) -> SigVerKey {
    let auth_ver_key = verification_keys.iter().zip(randomizers.iter()).fold(
        GroupProjective::<InnerEmbeddedGroup>::zero(),
        |accum, (key, randomizer)| {
            let auth_key_projective = key.to_affine().into_projective();
            let a = accum.add(auth_key_projective);
            a.add(*randomizer)
        },
    );
    SigVerKey::from(auth_ver_key.into_affine())
}

#[cfg(test)]
mod test {
    use super::*;
    use ark_ff::UniformRand;
    use ark_std::{rand::RngCore, vec};
    use jf_utils::test_serde_default;

    impl KeyChainMasterKey {
        // a random master key for test
        pub(crate) fn test_rand<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
            let mut bytes = vec![0u8; 32];
            rng.fill_bytes(&mut bytes);
            Self(InnerScalarField::rand(rng))
        }
    }

    // impl Default for ParticipationKeyPair {
    //     fn default() -> Self {
    //         let sk = bls_signatures::PrivateKey::new(&[0u8; 32]);
    //         let pk = sk.public_key();
    //         Self { sk, pk }
    //     }
    // }

    // impl Default for ParticipationPubKey {
    //     fn default() -> Self {
    //         let sk = bls_signatures::PrivateKey::new(&[0u8; 32]);
    //         Self(sk.public_key())
    //     }
    // }

    #[test]
    fn test_serde() {
        test_serde_default!(DetectionPubKey);
        test_serde_default!(DetectionKeyPair);
    }
}

// Commented out: Participation Key until https://gitlab.com/translucence/crypto/jellyfish/-/issues/180
//
// use bls_signatures::Serialize;
// use crate::constants::BLS12_381_G1_COMPRESSED_SIZE;
// use jf_primitives::constants::BLS_SCALAR_REPR_BYTE_LEN;
//
// /// Key pair for consensus participation and staking
// /// Generate through `MasterKey::generate_new_participation_key()`
// #[tagged_blob("STAKE-KEY")]
// #[derive(Clone, Debug, PartialEq)]
// pub struct ParticipationKeyPair {
//     sk: bls_signatures::PrivateKey,
//     pk: bls_signatures::PublicKey,
// }

// impl ParticipationKeyPair {
//     /// Return the public key
//     pub fn public_key(&self) -> ParticipationPubKey {
//         ParticipationPubKey(self.pk)
//     }

//     /// Sign a message, returns the signature
//     /// use `bls_signatures::aggregate()` to aggregate
//     pub fn sign<T: AsRef<[u8]>>(&self, message: T) ->
// bls_signatures::Signature {         self.sk.sign(message)
//     }
// }

// impl CanonicalSerialize for ParticipationKeyPair {
//     fn serialize<W>(&self, mut w: W) -> Result<(),
// ark_serialize::SerializationError>     where
//         W: ark_serialize::Write,
//     {
//         // Bls12_381 Scalar is 32 bytes
//         let len = BLS_SCALAR_REPR_BYTE_LEN as u8;
//         len.serialize(&mut w)?;
//         w.write_all(&bls_signatures::Serialize::as_bytes(&self.sk))?;
//         Ok(())
//     }

//     fn serialized_size(&self) -> usize {
//         core::mem::size_of::<u8>() + BLS_SCALAR_REPR_BYTE_LEN as usize
//     }
// }

// impl CanonicalDeserialize for ParticipationKeyPair {
//     fn deserialize<R>(mut r: R) -> Result<Self,
// ark_serialize::SerializationError>     where
//         R: ark_serialize::Read,
//     {
//         let len = u8::deserialize(&mut r)?;
//         if len != BLS_SCALAR_REPR_BYTE_LEN as u8 {
//             return Err(ark_serialize::SerializationError::InvalidData);
//         }
//         let mut scalar_bytes = [0u8; BLS_SCALAR_REPR_BYTE_LEN as usize];
//         r.read_exact(&mut scalar_bytes)?;
//         let sk = bls_signatures::PrivateKey::from_bytes(&scalar_bytes)
//             .map_err(|_| ark_serialize::SerializationError::InvalidData)?;
//         let pk = sk.public_key();

//         Ok(Self { sk, pk })
//     }
// }

// /// Public key for consensus participation and staking
// #[tagged_blob("STAKE-PUBKEY")]
// #[derive(Clone, Debug, PartialEq)]
// pub struct ParticipationPubKey(bls_signatures::PublicKey);

// impl CanonicalSerialize for ParticipationPubKey {
//     fn serialize<W>(&self, mut w: W) -> Result<(),
// ark_serialize::SerializationError>     where
//         W: ark_serialize::Write,
//     {
//         let len = BLS12_381_G1_COMPRESSED_SIZE;
//         len.serialize(&mut w)?;
//         w.write_all(&bls_signatures::Serialize::as_bytes(&self.0))?;
//         Ok(())
//     }

//     fn serialized_size(&self) -> usize {
//         core::mem::size_of::<u8>() + BLS12_381_G1_COMPRESSED_SIZE as usize
//     }
// }

// impl CanonicalDeserialize for ParticipationPubKey {
//     fn deserialize<R>(mut r: R) -> Result<Self,
// ark_serialize::SerializationError>     where
//         R: ark_serialize::Read,
//     {
//         let len = u8::deserialize(&mut r)?;
//         if len != BLS12_381_G1_COMPRESSED_SIZE {
//             return Err(ark_serialize::SerializationError::InvalidData);
//         }
//         let mut bytes = [0u8; BLS12_381_G1_COMPRESSED_SIZE as usize];
//         r.read_exact(&mut bytes)?;
//         let pk = bls_signatures::PublicKey::from_bytes(&bytes)
//             .map_err(|_| ark_serialize::SerializationError::InvalidData)?;

//         Ok(Self(pk))
//     }
// }
