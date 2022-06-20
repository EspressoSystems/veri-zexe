// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the VeriZexe library.

// This program is free software: you can redistribute it and/or modify it under
// the terms of the GNU General Public License as published by the Free Software
// Foundation, either version 3 of the License, or (at your option) any later
// version. This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
// details. You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>.

//! circuit to argue the correctness of local data commitment

use crate::{
    circuit::structs::{NoteInputVar, RecordOpeningVar},
    errors::DPCApiError,
    types::InnerScalarField,
};
use ark_std::vec::Vec;
use jf_plonk::circuit::{Circuit, PlonkCircuit, Variable};
use jf_primitives::circuit::commitment::CommitmentGadget;

/// This function takes the following inputs
/// - circuit
/// - inputs notes
/// - output records
/// - memo
/// - blinding factor
/// - commitment
/// The circuit constrains that the commitment is correct computed
/// w.r.t. notes, records and memo, with the given blinding factor
pub(crate) fn local_data_commitment_circuit(
    circuit: &mut PlonkCircuit<InnerScalarField>,
    entire_input_notes_vars: &[NoteInputVar],
    entire_output_records_vars: &[RecordOpeningVar],
    memo_vars: &[Variable],
    blinding_local_data_var: &Variable,
    comm_local_data_var: &Variable,
) -> Result<(), DPCApiError> {
    let input_records_commitments = entire_input_notes_vars
        .iter()
        .map(|x| x.record_opening_var.derive_record_commitment_var(circuit))
        .collect::<Result<Vec<_>, _>>()?;

    let output_records_commitments = entire_output_records_vars
        .iter()
        .map(|x| x.derive_record_commitment_var(circuit))
        .collect::<Result<Vec<_>, _>>()?;

    let commitment_inputs = [
        input_records_commitments.as_ref(),
        output_records_commitments.as_ref(),
        memo_vars,
    ]
    .concat();

    let derived_ldata_com_var = circuit.commit(&commitment_inputs, *blinding_local_data_var)?;
    circuit.equal_gate(derived_ldata_com_var, *comm_local_data_var)?;

    Ok(())
}
