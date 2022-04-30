use crate::{
    constants::{PAYLOAD_DATA_LEN, TREE_DEPTH},
    errors::DPCApiError,
    predicates::PredicateTrait,
    proofs::predicates::Predicate,
    structs::{NoteInput, PolicyIdentifier, RecordOpening},
};
use ark_ff::Zero;
use ark_std::{format, string::ToString};
use jf_primitives::merkle_tree::AccMemberWitness;

pub(crate) fn txn_parameter_sanity_check(
    inputs: &[NoteInput],
    outputs: &[RecordOpening],
    input_death_predicates: &[Predicate],
    output_birth_predicates: &[Predicate],
    fee: u64,
) -> Result<(), DPCApiError> {
    if inputs.is_empty() {
        return Err(DPCApiError::InvalidParameter(
            "Cannot generate DPC transaction: input is empty".to_string(),
        ));
    }
    if outputs.is_empty() {
        return Err(DPCApiError::InvalidParameter(
            "Cannot generate DPC transaction: output is empty".to_string(),
        ));
    }
    check_payload_length(inputs, outputs)?;
    check_fee(&inputs[0].ro, &outputs[0], fee)?;
    check_non_dummy_inputs_witnesses(inputs)?;
    check_predicates_consistency(
        inputs,
        outputs,
        input_death_predicates,
        output_birth_predicates,
    )
}

fn check_predicates_consistency(
    inputs: &[NoteInput],
    outputs: &[RecordOpening],
    input_death_predicates: &[Predicate],
    output_birth_predicates: &[Predicate],
) -> Result<(), DPCApiError> {
    for (index, (note, predicate)) in inputs
        .iter()
        .skip(1)
        .zip(input_death_predicates.iter())
        .enumerate()
    {
        let pid = note.ro.pid_death;
        let expected_pid = PolicyIdentifier::from_verifying_key(predicate.verifying_key()).0;
        if pid != expected_pid {
            return Err(DPCApiError::InvalidParameter(format!(
                "Wrong input death predicate {}, expected {}, actual {}",
                index, expected_pid, pid,
            )));
        }
    }

    for (index, (ro, predicate)) in outputs
        .iter()
        .skip(1)
        .zip(output_birth_predicates.iter())
        .enumerate()
    {
        let pid = ro.pid_birth;
        let expected_pid = PolicyIdentifier::from_verifying_key(predicate.verifying_key()).0;
        if pid != expected_pid {
            return Err(DPCApiError::InvalidParameter(format!(
                "Wrong output birth predicate {}, expected {}, actual {}",
                index, expected_pid, pid,
            )));
        }
    }

    Ok(())
}

fn check_payload_length(
    inputs: &[NoteInput],
    outputs: &[RecordOpening],
) -> Result<(), DPCApiError> {
    for (index, input) in inputs.iter().enumerate() {
        if input.ro.payload.data.iter().len() != PAYLOAD_DATA_LEN as usize {
            return Err(DPCApiError::InvalidParameter(format!(
                "Wrong payload length for input {}, expected {}, actual {}",
                index,
                PAYLOAD_DATA_LEN,
                input.ro.payload.data.len()
            )));
        }
    }
    for (index, output) in outputs.iter().enumerate() {
        if output.payload.data.iter().len() != PAYLOAD_DATA_LEN as usize {
            return Err(DPCApiError::InvalidParameter(format!(
                "Wrong payload length for output {}, expected {}, actual {}",
                index,
                PAYLOAD_DATA_LEN,
                output.payload.data.len()
            )));
        }
    }
    Ok(())
}

fn check_fee(
    fee_input: &RecordOpening,
    fee_chg_output: &RecordOpening,
    fee: u64,
) -> Result<(), DPCApiError> {
    // not dummy input
    if fee_input.payload.is_dummy {
        return Err(DPCApiError::InvalidParameter(
            "Cannot generate DPC transaction: fee input is dummy".to_string(),
        ));
    }
    // payload has dummy data except amount and asset type
    if fee_input
        .payload
        .data
        .iter()
        .skip(2)
        .any(|elem| !elem.is_zero())
    {
        return Err(DPCApiError::InvalidParameter(
            "Cannot generate DPC transaction: fee input wrong payload".to_string(),
        ));
    }
    // input is of native asset type
    if fee_input.payload.data[0] != crate::constants::NATIVE_ASSET_CODE {
        return Err(DPCApiError::InvalidParameter(
            "Cannot generate DPC transaction: fee input is not native asset type".to_string(),
        ));
    }

    // Check OUTPUT
    // not dummy input
    if fee_chg_output.payload.is_dummy {
        return Err(DPCApiError::InvalidParameter(
            "Cannot generate DPC transaction: fee change is dummy".to_string(),
        ));
    }
    // payload has dummy data except amount and asset type
    if fee_chg_output
        .payload
        .data
        .iter()
        .skip(2)
        .any(|elem| !elem.is_zero())
    {
        return Err(DPCApiError::InvalidParameter(
            "Cannot generate DPC transaction: fee change output wrong payload".to_string(),
        ));
    }
    // output is of native asset type
    if fee_chg_output.payload.data[0] != crate::constants::NATIVE_ASSET_CODE {
        return Err(DPCApiError::InvalidParameter(
            "Cannot generate DPC transaction: fee change is not native asset type".to_string(),
        ));
    }
    // check fee amount is correct
    if fee_chg_output.payload.data[1] - fee_input.payload.data[1]
        != crate::types::InnerScalarField::from(fee as u128)
    {
        return Err(DPCApiError::InvalidParameter(
            "Cannot generate DPC transaction: wrong fee".to_string(),
        ));
    }
    Ok(())
}

fn check_non_dummy_inputs_witnesses(inputs: &[NoteInput]) -> Result<(), DPCApiError> {
    let dummy_witness = AccMemberWitness::dummy(TREE_DEPTH);
    if inputs
        .iter()
        .any(|input| input.ro.payload.is_dummy ^ (input.acc_member_witness == dummy_witness))
    {
        return Err(DPCApiError::InvalidParameter("Cannot generate DPC transaction: Non dummy records cannot have dummy acc member witness, but dummy records must".to_string()));
    }
    // assume inputs[0] already checked is non dummy (it is the fee input)
    let root = inputs[0].acc_member_witness.root;
    if inputs
        .iter()
        .any(|input| !input.ro.payload.is_dummy && input.acc_member_witness.root != root)
    {
        return Err(DPCApiError::InvalidParameter(
            "Cannot generate DPC transaction: input witnesses do not share same merkle root"
                .to_string(),
        ));
    }
    Ok(())
}
