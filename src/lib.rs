// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the VeriZexe library.

// This program is free software: you can redistribute it and/or modify it under
// the terms of the GNU General Public License as published by the Free Software
// Foundation, either version 3 of the License, or (at your option) any later
// version. This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
// details. You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>.

//! Library for Decentralized Private Computation (DPC) scheme

#![deny(missing_docs)]
#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod bench;
mod circuit;
pub mod constants;
pub mod errors;
mod examples;
pub mod keys;
pub mod predicates;
pub mod proofs;
pub mod structs;
pub mod transaction;
mod types;
mod utils;
