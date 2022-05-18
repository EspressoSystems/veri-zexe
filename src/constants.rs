//! Constant declarations

use crate::types::InnerScalarField;

// list of domain separators
pub(crate) mod dom_sep {
    pub const KEYCHAIN_MASTERKEY_DOM_SEP: &str = "DPC Key-Chain Master Key";
    pub const AUTHORIZATION_KEY_PAIR_DOM_SEP: &str = "DPC Key-Chain Authorization Secret Key";
    pub const NULLIFYING_KEY_DOM_SEP: &str = "DPC Key-Chain Nullifiying Deriving Key";
    pub const DIVERSIFIER_RAND_DOM_SEP: &str = "DPC Key-Chain Diversifier Randomizer";
    pub const INCOMING_VIEWING_KEY_DOM_SEP: &str = "DPC Key-Chain Incoming Viewing Key";
    // pub const PARTICIPATION_KEY_DOM_SEP: &str = "DPC Key-Chain Participation
    // Key";
}

// see API here: https://docs.rs/bls12_381/0.5.0/bls12_381/struct.G1Affine.html#method.to_compressed
// design notes: https://docs.rs/bls12_381/0.5.0/bls12_381/notes/serialization/index.html
// pub(crate) const BLS12_381_G1_COMPRESSED_SIZE: u8 = 48;

// Policy verification circuit parameters
//
// Bit length of UltraPlonk range gates
pub(crate) const RANGE_BIT_LEN: usize = 16;
// Non-native field parameter
pub(crate) const NONNATIVE_FIELD_M: usize = 128;

/// Native asset code
pub const NATIVE_ASSET_CODE: InnerScalarField = ark_ff::field_new!(InnerScalarField, "1");

/// RecordsCommitment merkle tree depth
// NOTE: (alex) originally set to 26, but changed to 21 for benchmark purposes,
// since ZCash record commitment tree has 2^32 leaves.
pub const TREE_DEPTH: u8 = 21;

/// Length of payload data
pub const PAYLOAD_DATA_LEN: usize = 8;

/// Length of transaction MEMO  in InnerFieldElements
pub const MEMO_LEN: usize = 8;
