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
