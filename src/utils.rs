use crate::{
    constants::{PAYLOAD_DATA_LEN, TREE_DEPTH},
    errors::DPCApiError,
    predicates::PredicateTrait,
    proofs::predicates::Predicate,
    structs::{NoteInput, PolicyIdentifier, RecordOpening},
    types::NodeValue,
};
use ark_std::{format, string::ToString};
use jf_primitives::merkle_tree::AccMemberWitness;

pub(crate) fn txn_parameter_sanity_check(
    inputs: &[NoteInput],
    outputs: &[RecordOpening],
    input_death_predicates: &[Predicate],
    output_birth_predicates: &[Predicate],
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
    for (index, (note, predicate)) in inputs.iter().zip(input_death_predicates.iter()).enumerate() {
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

fn check_non_dummy_inputs_witnesses(inputs: &[NoteInput]) -> Result<(), DPCApiError> {
    let dummy_witness = AccMemberWitness::dummy(TREE_DEPTH);

    // check: dummy input must have dummy membership proof;
    // non-dummy input must have non-dummy membership proof.
    if inputs
        .iter()
        .any(|input| input.ro.payload.is_dummy ^ (input.acc_member_witness == dummy_witness))
    {
        return Err(DPCApiError::InvalidParameter("Cannot generate DPC transaction: Non dummy records cannot have dummy acc member witness, but dummy records must".to_string()));
    }

    let root = get_root_unchecked(inputs);

    // check: membership proofs of non-dummy inputs must share the same root
    if root != dummy_witness.root {
        if inputs
            .iter()
            .any(|input| !input.ro.payload.is_dummy && input.acc_member_witness.root != root)
        {
            return Err(DPCApiError::InvalidParameter(
                "Cannot generate DPC transaction: input witnesses do not share same merkle root"
                    .to_string(),
            ));
        }
    }
    Ok(())
}

// Retrieve the first non-dummy root if any, or return the dummy root,
// without checking consistency of all roots are equal for `note_inputs`.
pub(crate) fn get_root_unchecked(note_inputs: &[NoteInput]) -> NodeValue {
    let dummy_root = AccMemberWitness::dummy(TREE_DEPTH).root;

    for input in note_inputs {
        if input.acc_member_witness.root != dummy_root {
            return input.acc_member_witness.root;
        }
    }

    dummy_root
}
