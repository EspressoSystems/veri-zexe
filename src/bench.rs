// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the VeriZexe library.

// This program is free software: you can redistribute it and/or modify it under
// the terms of the GNU General Public License as published by the Free Software
// Foundation, either version 3 of the License, or (at your option) any later
// version. This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
// details. You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>.

use crate::{
    constants::MEMO_LEN,
    errors::DPCApiError,
    examples::{
        tests::{build_notes, build_notes_and_records},
        zcash_example::ZcashPredicate,
        PredicateOps,
    },
    keys::{aggregate_authorization_signing_keypairs, KeyChainMasterKey},
    predicates::PredicateTrait,
    structs::compress_local_data,
    transaction::DPCTxnBody,
    types::{InnerScalarField, InnerUniversalParam, OuterUniversalParam},
};
use ark_serialize::*;
use ark_std::{end_timer, println, rand::Rng, start_timer, vec, UniformRand, Zero};
use jf_utils::{to_bytes, Vec};
use std::time::Instant;

#[test]
// #[ignore]
fn dpc_bench() -> Result<(), DPCApiError> {
    let rng = &mut ark_std::test_rng();
    // NOTE: for predicate circuit of size 2^15, SRS degree for inner and outer are:
    // 2-in-2-out: inner: (1 << 16) + 4, outer: (1 << 17) + 4;
    // 3-in-3-out: inner: (1 << 16) + 4, outer: (1 << 17) + 4;
    // 4-in-4-out: inner: (1 << 17) + 4, outer: (1 << 18) + 4;
    // 5-in-5-out: inner: (1 << 17) + 4, outer: (1 << 18) + 4;
    let max_inner_degree = (1 << 17) + 4;
    let max_outer_degree = (1 << 18) + 4;

    let start = start_timer!(|| "DPC::Setup::universal");
    let now = Instant::now();

    let inner_srs = crate::proofs::universal_setup_inner(max_inner_degree, rng)?;
    let outer_srs = crate::proofs::universal_setup_outer(max_outer_degree, rng)?;
    println!(
        "ℹ️️ inner_srs size: {} bytes, outer_srs size: {} bytes",
        to_bytes!(&inner_srs).unwrap().len(),
        to_bytes!(&outer_srs).unwrap().len()
    );

    println!(
        "⏱️ DPC::Setup::universal (inner_max_deg: {}, outer_max_deg: {}) takes {} ms",
        max_inner_degree,
        max_outer_degree,
        now.elapsed().as_millis()
    );
    end_timer!(start);

    let mem = proc_status::mem_usage().unwrap();
    println!(
        "⚠️ After UniversalSetup, Mem usage: current={} KB, peak={} KB",
        mem.current / 1024,
        mem.peak / 1024
    );

    zcash_transaction_full_cycle(&inner_srs, &outer_srs, 2)?;
    zcash_transaction_full_cycle(&inner_srs, &outer_srs, 3)?;
    zcash_transaction_full_cycle(&inner_srs, &outer_srs, 4)?;
    // zcash_transaction_full_cycle(&inner_srs, &outer_srs, 5)?;

    Ok(())
}

fn zcash_transaction_full_cycle(
    inner_srs: &InnerUniversalParam,
    outer_srs: &OuterUniversalParam,
    num_inputs: usize,
) -> Result<(), DPCApiError> {
    let rng = &mut ark_std::test_rng();
    println!("\nℹ️ num of inputs/outputs: {}", num_inputs);

    let start = start_timer!(|| "DPC::Setup::circuit-specific");
    let now = Instant::now();

    let (dpc_pk, dpc_vk, mut birth_predicate, birth_pid, mut death_predicate, death_pid) =
        ZcashPredicate::preprocess(&inner_srs, &outer_srs, num_inputs)?;
    println!(
        "ℹ️️ indexed DPC vk size: {} bytes",
        to_bytes!(&dpc_vk).unwrap().len(),
    );

    println!(
        "⏱️ DPC::Setup::circuit-specific takes {} ms",
        now.elapsed().as_millis()
    );
    end_timer!(start);

    println!(
        "ℹ️ birth predicate size: {}; death predicate size: {}",
        birth_predicate.0.num_constraints(),
        death_predicate.0.num_constraints(),
    );

    let mem = proc_status::mem_usage().unwrap();
    println!(
        "⚠️ After Indexing, Mem usage: current={} KB, peak={} KB",
        mem.current / 1024,
        mem.peak / 1024
    );

    let start = start_timer!(|| "DPC: GenAddress");
    let now = Instant::now();

    // generate proof generation key and addresses
    let mut wsk = [0u8; 32];
    rng.fill(&mut wsk[..]);
    let msk = KeyChainMasterKey::generate(wsk, &[]);
    let (ak, pgk, ivk) = msk.derive_key_chain_single_consumer();
    let (addr, rd) = msk.derive_diversified_address(&pgk, &ivk, 0)?;

    println!("⏱️ DPC::GenAddress takes {} ms", now.elapsed().as_millis());
    end_timer!(start);

    let execute_start = start_timer!(|| "DPC: Execute");
    let now = Instant::now();

    const NON_NATIVE_ASSET_ID: u64 = 2u64;
    let input_note_values: Vec<_> = (0..num_inputs).map(|i| 10 * (i as u64 + 1)).collect();
    let output_note_values: Vec<_> = (0..num_inputs)
        .map(|i| 10 * (num_inputs - i) as u64)
        .collect();

    let (entire_input_records, entire_output_records) = build_notes_and_records(
        rng,
        &addr,
        &pgk,
        NON_NATIVE_ASSET_ID,
        &input_note_values,
        &output_note_values,
        birth_pid,
        death_pid,
    )?;

    let entire_input_notes = build_notes(&entire_input_records, &pgk, &rd)?;
    let merkle_root = entire_input_notes[0].acc_member_witness.root;
    // prepare memo
    let dummy_memo = [InnerScalarField::zero(); MEMO_LEN];

    // update the predicates to use the correct witness circuit that matches the
    // correct local data commitment
    let compressed_local_data = compress_local_data(
        &entire_input_notes,
        &entire_output_records,
        dummy_memo.to_vec(),
    )?;
    let blinding_local_data = InnerScalarField::rand(rng);
    let comm_local_data = compressed_local_data.commit(blinding_local_data)?;

    // finalized predicates
    birth_predicate.finalize_for_proving(
        &entire_input_notes,
        &entire_output_records,
        &dummy_memo,
        blinding_local_data,
        comm_local_data,
        true,
    )?;
    death_predicate.finalize_for_proving(
        &entire_input_notes,
        &entire_output_records,
        &dummy_memo,
        blinding_local_data,
        comm_local_data,
        false,
    )?;

    let input_death_predicates = vec![death_predicate.0; num_inputs];
    let output_birth_predicates = vec![birth_predicate.0; num_inputs];
    println!(
        "ℹ️️ indexed predicate vk size: {} bytes",
        to_bytes!(input_death_predicates[0].predicate.verify_key_ref())
            .unwrap()
            .len(),
    );

    let aggregate_auth_key = {
        let auth_keys = vec![ak.0; num_inputs];
        let randomizers = vec![Default::default(); num_inputs];

        aggregate_authorization_signing_keypairs(&auth_keys, &randomizers)?
    };

    let txn_body = DPCTxnBody::generate(
        rng,
        &dpc_pk,
        entire_input_notes,
        entire_output_records,
        &input_death_predicates,
        &output_birth_predicates,
        dummy_memo.to_vec(),
        blinding_local_data,
    )?;

    let txn_note = txn_body.authorize(&aggregate_auth_key)?;
    {
        let mut note_bytes = vec![];
        txn_note.serialize(&mut note_bytes)?;
        let mut proof_bytes = vec![];
        txn_note.body.proof.serialize(&mut proof_bytes)?;
        println!(
            "ℹ️ txn_note size: {} bytes; txn proof size: {} bytes",
            note_bytes.len(),
            proof_bytes.len()
        );
    }

    println!("⏱️ DPC::Execute takes {} ms", now.elapsed().as_millis());
    end_timer!(execute_start);

    let mem = proc_status::mem_usage().unwrap();
    println!(
        "⚠️ After Execute, Mem usage: current={} KB, peak={} KB",
        mem.current / 1024,
        mem.peak / 1024
    );

    let verify = start_timer!(|| "DPC::Verify");
    let now = Instant::now();

    txn_note.verify(&dpc_vk, merkle_root)?;
    println!("⏱️ DPC::Verify takes {} ms", now.elapsed().as_millis());
    end_timer!(verify);

    Ok(())
}
