//! Core traits: Prover, Verifier, BatchProver

use crate::core::errors::{Result, ZKGuardError};
use crate::core::types::{Proof, PublicInputs, Witness};

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

/// Generates a ZK proof from a secret witness and public inputs.
pub trait Prover {
    fn prove(&self, witness: &Witness, public_inputs: &PublicInputs) -> Result<Proof>;
    fn min_witness_size(&self) -> usize;
    fn min_public_inputs_size(&self) -> usize;
}

/// Verifies a ZK proof against public inputs.
pub trait Verifier {
    fn verify(&self, proof: &Proof, public_inputs: &PublicInputs) -> Result<bool>;

    #[cfg(feature = "alloc")]
    fn verify_batch(&self, proofs: &[Proof], public_inputs: &[PublicInputs]) -> Result<Vec<bool>> {
        if proofs.len() != public_inputs.len() {
            return Err(ZKGuardError::InvalidPublicInputs {
                reason: alloc::format!(
                    "proof count {} != input count {}",
                    proofs.len(),
                    public_inputs.len()
                ),
            });
        }
        let mut results = Vec::with_capacity(proofs.len());
        for (proof, inputs) in proofs.iter().zip(public_inputs.iter()) {
            results.push(self.verify(proof, inputs)?);
        }
        Ok(results)
    }
}

/// Generates multiple proofs efficiently (optional optimisation).
#[cfg(feature = "alloc")]
pub trait BatchProver: Prover {
    fn prove_batch(
        &self,
        witnesses: &[Witness],
        public_inputs: &[PublicInputs],
    ) -> Result<Vec<Proof>>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[allow(dead_code)]
    struct DummyProver;
    impl Prover for DummyProver {
        fn prove(&self, _: &Witness, _: &PublicInputs) -> Result<Proof> {
            Ok(Proof::default())
        }
        fn min_witness_size(&self) -> usize {
            1
        }
        fn min_public_inputs_size(&self) -> usize {
            1
        }
    }

    struct DummyVerifier;
    impl Verifier for DummyVerifier {
        fn verify(&self, _: &Proof, _: &PublicInputs) -> Result<bool> {
            Ok(true)
        }
    }

    #[test]
    fn test_verify_batch_mismatch() {
        let v = DummyVerifier;
        let proofs = vec![Proof::default(), Proof::default()];
        let inputs = vec![PublicInputs::default()];
        assert!(v.verify_batch(&proofs, &inputs).is_err());
    }

    #[test]
    fn test_verify_batch_ok() {
        let v = DummyVerifier;
        let proofs = vec![Proof::default()];
        let inputs = vec![PublicInputs::default()];
        let results = v.verify_batch(&proofs, &inputs).unwrap();
        assert_eq!(results, vec![true]);
    }
}
