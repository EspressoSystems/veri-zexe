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
    types::InnerScalarField,
};
use ark_std::{end_timer, println, rand::Rng, start_timer, vec, UniformRand, Zero};

#[test]
fn dpc_bench() -> Result<(), DPCApiError> {
    let rng = &mut ark_std::test_rng();
    // TODO: Maybe adjust these two parameters after getting the circuit size
    let max_inner_degree = (1 << 17) + 4;
    let max_outer_degree = (1 << 18) + 4;

    let start = start_timer!(|| "DPC::Setup");
    let inner_srs = crate::proofs::universal_setup_inner(max_inner_degree, rng)?;
    let outer_srs = crate::proofs::universal_setup_outer(max_outer_degree, rng)?;

    // 2-input-2-output (including fee and fee change then: 3-in-3-out)
    let num_non_fee_inputs = 2;
    let num_input = num_non_fee_inputs + 1;

    println!("ℹ️ num of inputs/outputs: {}", num_input);

    let (dpc_pk, dpc_vk, mut birth_predicate, birth_pid, mut death_predicate, death_pid) =
        ZcashPredicate::preprocess(&inner_srs, &outer_srs, num_input)?;

    println!(
        "ℹ️ birth predicate size: {}; death predicate size: {}",
        birth_predicate.0.num_constraints(),
        death_predicate.0.num_constraints(),
    );

    end_timer!(start);

    let start = start_timer!(|| "DPC: GenAddress");

    // generate proof generation key and addresses
    let mut wsk = [0u8; 32];
    rng.fill(&mut wsk[..]);
    let msk = KeyChainMasterKey::generate(wsk, &[]);
    let (ak, pgk, ivk) = msk.derive_key_chain_single_consumer();
    let (addr, rd) = msk.derive_diversified_address(&pgk, &ivk, 0)?;

    end_timer!(start);

    let execute_start = start_timer!(|| "DPC: Execute");

    const NON_NATIVE_ASSET_ID: u64 = 2u64;
    // =================================
    // setup transaction parameters
    // we have four types of records:
    // - native token transaction fee note
    // - native token transaction fee change note
    // - Zcash input notes
    // - Zcash output notes
    // =================================
    let fee_in = 300;
    let fee = 5;
    let fee_out = 295;
    let input_note_values = [18, 32];
    let output_note_values = [9, 41];

    let (entire_input_records, entire_output_records) = build_notes_and_records(
        rng,
        &addr,
        &pgk,
        fee_in,
        fee_out,
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

    let input_death_predicates = vec![death_predicate.0; num_non_fee_inputs];
    let output_birth_predicates = vec![birth_predicate.0; num_non_fee_inputs];

    let txn_body = DPCTxnBody::generate(
        rng,
        &dpc_pk,
        entire_input_notes.clone(),
        entire_output_records,
        &input_death_predicates,
        &output_birth_predicates,
        fee,
        dummy_memo.to_vec(),
        blinding_local_data,
    )?;

    let txn_note = {
        // TODO: move this earlier to avoid cloning entire_input_notes
        let auth_keys = vec![ak.0; num_input];
        let randomizers = vec![Default::default(); num_input];
        let aggregate_auth_key =
            aggregate_authorization_signing_keypairs(&auth_keys, &randomizers)?;
        txn_body.authorize(&aggregate_auth_key)?
    };

    end_timer!(execute_start);

    let verify = start_timer!(|| "DPC::Verify");

    txn_note.verify(&dpc_vk, merkle_root)?;
    end_timer!(verify);
    Ok(())
}
