use crate::{
    structs::{NoteInput, RecordOpening},
    types::{InnerEmbeddedGroup, InnerScalarField},
};
use ark_ec::ProjectiveCurve;
use ark_std::{vec, vec::Vec};
use jf_plonk::{
    circuit::{
        customized::ecc::{Point, PointVariable},
        Circuit, PlonkCircuit, Variable,
    },
    errors::PlonkError,
};
use jf_primitives::circuit::{
    commitment::CommitmentGadget, merkle_tree::AccMemberWitnessVar, prf::PrfGadget,
};

#[derive(Clone)]
pub(crate) struct RecordOpeningVar {
    pub(crate) addr: (Variable, PointVariable),
    pub(crate) payload: PayloadVariable,
    pub(crate) pid_birth: Variable,
    pub(crate) pid_death: Variable,
    pub(crate) nonce: Variable,
    pub(crate) blinding: Variable,
}

impl RecordOpeningVar {
    pub(crate) fn new(
        circuit: &mut PlonkCircuit<InnerScalarField>,
        ro: &RecordOpening,
    ) -> Result<Self, PlonkError> {
        let addr_diversifier = circuit.create_variable(ro.addr.d)?;
        let pk_d_point = Point::from(ro.addr.pk.into_affine());
        let pk_d_var = circuit.create_point_variable(pk_d_point)?;
        let payload_dummy =
            circuit.create_variable(InnerScalarField::from(ro.payload.is_dummy as u64))?;
        let payload_data: Result<Vec<_>, _> = ro
            .payload
            .data
            .iter()
            .map(|elem| circuit.create_variable(*elem))
            .collect();
        let payload = PayloadVariable {
            is_dummy: payload_dummy,
            data: payload_data?,
        };
        let pid_birth = circuit.create_variable(ro.pid_birth)?;
        let pid_death = circuit.create_variable(ro.pid_death)?;
        let nonce = circuit.create_variable(ro.nonce)?;
        let blinding = circuit.create_variable(ro.blinding)?;
        Ok(RecordOpeningVar {
            addr: (addr_diversifier, pk_d_var),
            payload,
            pid_birth,
            pid_death,
            nonce,
            blinding,
        })
    }

    pub(crate) fn derive_record_commitment_var(
        &self,
        circuit: &mut PlonkCircuit<InnerScalarField>,
    ) -> Result<Variable, PlonkError> {
        let mut msg = vec![
            self.addr.0,
            self.addr.1.get_x(),
            self.addr.1.get_y(),
            self.payload.is_dummy,
        ];
        msg.extend_from_slice(&self.payload.data);
        msg.push(self.pid_birth);
        msg.push(self.pid_death);
        msg.push(self.nonce);

        circuit.commit(&msg, self.blinding)
    }

    pub(crate) fn nullify(
        &self,
        circuit: &mut PlonkCircuit<InnerScalarField>,
        nullifier_key: &NullifierDerivingKeyVar,
    ) -> Result<Variable, PlonkError> {
        circuit.eval_prf(nullifier_key.0, &[self.nonce])
    }
}

#[derive(Clone)]
pub(crate) struct PayloadVariable {
    pub(crate) is_dummy: Variable,
    pub(crate) data: Vec<Variable>,
}
pub(crate) struct NoteInputVar {
    pub(crate) proof_generation_key_var: ProofGenerationKeyVar,
    pub(crate) record_opening_var: RecordOpeningVar,
    pub(crate) acc_member_witness_var: AccMemberWitnessVar,
    pub(crate) authorization_randomizer_var: PointVariable,
    pub(crate) diversifier_randomizer_var: Variable,
}

impl NoteInputVar {
    pub(crate) fn new(
        circuit: &mut PlonkCircuit<InnerScalarField>,
        input: &NoteInput,
    ) -> Result<Self, PlonkError> {
        let ak_point = Point::from(input.proof_gen_key.ak.0.to_affine());
        let proof_generation_key_var = ProofGenerationKeyVar {
            ak: AuthorizationPubKeyVar(circuit.create_point_variable(ak_point)?),
            nk: NullifierDerivingKeyVar(
                circuit.create_variable(input.proof_gen_key.nk.0.internal())?,
            ),
        };
        let record_opening_var = RecordOpeningVar::new(circuit, &input.ro)?;
        let acc_member_witness_var =
            AccMemberWitnessVar::new::<_, InnerEmbeddedGroup>(circuit, &input.acc_member_witness)?;
        let auth_randomizer_point = Point::from(input.authorization_randomizer.into_affine());
        let authorization_randomizer_var = circuit.create_point_variable(auth_randomizer_point)?;
        let diversifier_randomizer_var = circuit.create_variable(input.diversifier_randomizer.0)?;
        Ok(NoteInputVar {
            proof_generation_key_var,
            record_opening_var,
            acc_member_witness_var,
            authorization_randomizer_var,
            diversifier_randomizer_var,
        })
    }
}

#[derive(Clone)]
pub(crate) struct AuthorizationPubKeyVar(pub(crate) PointVariable);
#[derive(Clone)]
pub(crate) struct NullifierDerivingKeyVar(pub(crate) Variable);

#[derive(Clone)]
pub(crate) struct ProofGenerationKeyVar {
    pub(crate) ak: AuthorizationPubKeyVar,
    pub(crate) nk: NullifierDerivingKeyVar,
}

impl ProofGenerationKeyVar {
    pub(crate) fn derive_diversifier(
        &self,
        circuit: &mut PlonkCircuit<InnerScalarField>,
        diversifier_randomizer: Variable,
    ) -> Result<Variable, PlonkError> {
        let msg = vec![self.ak.0.get_x(), self.ak.0.get_y(), self.nk.0];
        circuit.commit(&msg, diversifier_randomizer)
    }
}
#[cfg(test)]
mod test {
    use crate::{
        circuit::structs::{NullifierDerivingKeyVar, RecordOpeningVar},
        keys::NullifierDerivingKey,
        structs::{Nullifier, RecordOpening},
        types::*,
    };
    use ark_ff::{One, UniformRand};
    use ark_std::rand::{CryptoRng, RngCore};
    use jf_plonk::circuit::{Circuit, PlonkCircuit};
    use jf_primitives::prf::PrfKey;

    fn sample_record<R: CryptoRng + RngCore>(rng: &mut R) -> RecordOpening {
        let pid_b = InnerScalarField::rand(rng);
        let pid_d = InnerScalarField::rand(rng);
        let first_nullifier = Nullifier(InnerScalarField::rand(rng));
        RecordOpening::new(
            rng,
            Default::default(),
            Default::default(),
            pid_b,
            pid_d,
            0,
            first_nullifier,
        )
    }

    #[test]
    fn test_nullify() {
        let rng = &mut ark_std::test_rng();
        let ro = sample_record(rng);
        let nullifier_key = NullifierDerivingKey(PrfKey::default());
        let nullifier = ro.nullify(&nullifier_key).unwrap();

        let mut circuit = PlonkCircuit::<InnerScalarField>::new_turbo_plonk();
        let nullifier_key_var =
            NullifierDerivingKeyVar(circuit.create_variable(nullifier_key.0.internal()).unwrap());

        let ro_var = RecordOpeningVar::new(&mut circuit, &ro).unwrap();
        let nullifier_var = ro_var.nullify(&mut circuit, &nullifier_key_var).unwrap();

        assert_eq!(nullifier.0, circuit.witness(nullifier_var).unwrap());
        // check constraints
        assert!(circuit.check_circuit_satisfiability(&[]).is_ok());
        *circuit.witness_mut(nullifier_var) = InnerScalarField::one();
        assert!(circuit.check_circuit_satisfiability(&[]).is_err());
    }

    #[test]
    fn test_derive_record_commitment() {
        let rng = &mut ark_std::test_rng();
        let ro = sample_record(rng);
        let rc = ro.derive_record_commitment().unwrap();

        let mut circuit = PlonkCircuit::<InnerScalarField>::new_turbo_plonk();
        let ro_var = RecordOpeningVar::new(&mut circuit, &ro).unwrap();
        let rc_var = ro_var.derive_record_commitment_var(&mut circuit).unwrap();

        assert_eq!(rc, circuit.witness(rc_var).unwrap());
        // check constraints
        assert!(circuit.check_circuit_satisfiability(&[]).is_ok());
        *circuit.witness_mut(rc_var) = InnerScalarField::one();
        assert!(circuit.check_circuit_satisfiability(&[]).is_err());
    }
}
