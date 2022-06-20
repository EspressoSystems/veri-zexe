// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the VeriZexe library.

// This program is free software: you can redistribute it and/or modify it under
// the terms of the GNU General Public License as published by the Free Software
// Foundation, either version 3 of the License, or (at your option) any later
// version. This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
// details. You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>.

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
pub const TREE_DEPTH: u8 = 26;

/// Length of payload data
pub const PAYLOAD_DATA_LEN: usize = 8;

/// Length of transaction MEMO  in InnerFieldElements
pub const MEMO_LEN: usize = 8;
