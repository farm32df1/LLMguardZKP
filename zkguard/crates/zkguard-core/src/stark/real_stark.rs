//! Plonky3 STARK prover / verifier (requires feature = "full-p3")

use crate::core::errors::{Result, ZKGuardError};
use crate::stark::air::SimpleAir;
use crate::stark::key_commit_air::KeyCommitAir;
use crate::stark::range_air::RangeAir;

#[cfg(feature = "alloc")]
use alloc::{vec, vec::Vec};

use p3_field::{extension::BinomialExtensionField, AbstractField, PrimeField64};
use p3_goldilocks::{DiffusionMatrixGoldilocks, Goldilocks};
use p3_matrix::{dense::RowMajorMatrix, Matrix};

use p3_challenger::DuplexChallenger;
use p3_commit::ExtensionMmcs;
use p3_fri::{FriConfig, TwoAdicFriPcs};
use p3_merkle_tree::FieldMerkleTreeMmcs;
use p3_poseidon2::{Poseidon2, Poseidon2ExternalMatrixGeneral};
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
use p3_uni_stark::{prove, verify, Proof, StarkConfig};

pub type Val = Goldilocks;
pub type Challenge = BinomialExtensionField<Val, 2>;
type Perm = Poseidon2<Val, Poseidon2ExternalMatrixGeneral, DiffusionMatrixGoldilocks, 16, 7>;
type MyHash = PaddingFreeSponge<Perm, 16, 8, 8>;
type MyCompress = TruncatedPermutation<Perm, 2, 8, 16>;
type ValMmcs = FieldMerkleTreeMmcs<
    <Val as p3_field::Field>::Packing,
    <Val as p3_field::Field>::Packing,
    MyHash,
    MyCompress,
    8,
>;
type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;
type Pcs = TwoAdicFriPcs<Val, p3_dft::Radix2DitParallel, ValMmcs, ChallengeMmcs>;
type MyChallenger = DuplexChallenger<Val, Perm, 16, 8>;
pub type MyStarkConfig = StarkConfig<Pcs, Challenge, MyChallenger>;

/// Which AIR circuit produced a proof — prevents cross-circuit forgeries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum ProofAirType {
    Fibonacci = 0,
    Sum = 1,
    Multiplication = 2,
    Range = 3,
    KeyCommit = 4,
}

impl ProofAirType {
    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

// ── Prover ────────────────────────────────────────────────────────────────────

pub struct StarkProver {
    air: SimpleAir,
    perm: Perm,
}

impl core::fmt::Debug for StarkProver {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("StarkProver")
            .field("air", &self.air)
            .field("perm", &"<Poseidon2>")
            .finish()
    }
}

impl Clone for StarkProver {
    fn clone(&self) -> Self {
        Self {
            air: self.air.clone(),
            perm: self.perm.clone(),
        }
    }
}

impl StarkProver {
    pub fn new(air: SimpleAir) -> Result<Self> {
        Ok(Self {
            air,
            perm: create_perm(),
        })
    }

    pub fn prove_fibonacci(&self, num_rows: usize) -> Result<StarkProof> {
        let trace = build_fibonacci_trace(num_rows)?;
        let pv = fibonacci_public_values(num_rows);
        let log_n = num_rows.trailing_zeros() as usize;
        let cfg = create_config(&self.perm, log_n);
        let mut ch = MyChallenger::new(self.perm.clone());
        let proof = prove(&cfg, &self.air, &mut ch, trace, &pv);
        Ok(StarkProof {
            num_rows,
            public_values: pv.iter().map(|v| v.as_canonical_u64()).collect(),
            air_type: ProofAirType::Fibonacci,
            inner: proof,
        })
    }

    pub fn prove_sum(&self, a: &[u64], b: &[u64]) -> Result<StarkProof> {
        let air = SimpleAir::sum();
        let trace = crate::stark::air::trace_builder::build_sum_trace_p3(a, b)?;
        let pv = sum_public_values(a, b);
        let log_n = trace.height().trailing_zeros() as usize;
        let cfg = create_config(&self.perm, log_n);
        let mut ch = MyChallenger::new(self.perm.clone());
        let proof = prove(&cfg, &air, &mut ch, trace, &pv);
        Ok(StarkProof {
            num_rows: proof_num_rows(a.len()),
            public_values: pv.iter().map(|v| v.as_canonical_u64()).collect(),
            air_type: ProofAirType::Sum,
            inner: proof,
        })
    }

    pub fn prove_multiplication(&self, a: &[u64], b: &[u64]) -> Result<StarkProof> {
        let air = SimpleAir::multiplication();
        let trace = crate::stark::air::trace_builder::build_mul_trace_p3(a, b)?;
        let pv = mul_public_values(a, b);
        let log_n = trace.height().trailing_zeros() as usize;
        let cfg = create_config(&self.perm, log_n);
        let mut ch = MyChallenger::new(self.perm.clone());
        let proof = prove(&cfg, &air, &mut ch, trace, &pv);
        Ok(StarkProof {
            num_rows: proof_num_rows(a.len()),
            public_values: pv.iter().map(|v| v.as_canonical_u64()).collect(),
            air_type: ProofAirType::Multiplication,
            inner: proof,
        })
    }

    pub fn prove_range(&self, value: u64, threshold: u64) -> Result<StarkProof> {
        let air = RangeAir::new();
        let trace =
            crate::stark::range_air::trace_builder::build_range_proof_trace(value, threshold)?;
        let pv = vec![Val::from_canonical_u64(threshold)];
        let num_rows = trace.height();
        let log_n = num_rows.trailing_zeros() as usize;
        let cfg = create_config(&self.perm, log_n);
        let mut ch = MyChallenger::new(self.perm.clone());
        let proof = prove(&cfg, &air, &mut ch, trace, &pv);
        Ok(StarkProof {
            num_rows,
            public_values: pv.iter().map(|v| v.as_canonical_u64()).collect(),
            air_type: ProofAirType::Range,
            inner: proof,
        })
    }

    /// Prove knowledge of field elements whose polynomial evaluation equals
    /// a known commitment value.
    ///
    /// `elements`: secret field elements (e.g. key bytes + salt via `bytes_to_fields`)
    ///
    /// Returns a STARK proof with public values `[eval_final, num_elements]`.
    /// The proof hides the individual elements (ZK property).
    pub fn prove_key_commit(&self, elements: &[u64]) -> Result<StarkProof> {
        let air = KeyCommitAir;
        let (trace, eval_final) =
            crate::stark::key_commit_air::trace_builder::build_key_commit_trace(elements)?;
        let pv = vec![
            Val::from_canonical_u64(eval_final),
            Val::from_canonical_u64(elements.len() as u64),
        ];
        let num_rows = trace.height();
        let log_n = num_rows.trailing_zeros() as usize;
        let cfg = create_config(&self.perm, log_n);
        let mut ch = MyChallenger::new(self.perm.clone());
        let proof = prove(&cfg, &air, &mut ch, trace, &pv);
        Ok(StarkProof {
            num_rows,
            public_values: pv.iter().map(|v| v.as_canonical_u64()).collect(),
            air_type: ProofAirType::KeyCommit,
            inner: proof,
        })
    }

    pub fn get_verifier(&self) -> StarkVerifier {
        StarkVerifier {
            air: self.air.clone(),
            perm: self.perm.clone(),
        }
    }
}

// ── Verifier ──────────────────────────────────────────────────────────────────

pub struct StarkVerifier {
    air: SimpleAir,
    perm: Perm,
}

impl core::fmt::Debug for StarkVerifier {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("StarkVerifier")
            .field("air", &self.air)
            .field("perm", &"<Poseidon2>")
            .finish()
    }
}

impl Clone for StarkVerifier {
    fn clone(&self) -> Self {
        Self {
            air: self.air.clone(),
            perm: self.perm.clone(),
        }
    }
}

impl StarkVerifier {
    pub fn new(air: SimpleAir) -> Result<Self> {
        Ok(Self {
            air,
            perm: create_perm(),
        })
    }

    pub fn verify_by_type(&self, proof: &StarkProof) -> Result<bool> {
        match proof.air_type {
            ProofAirType::Fibonacci => self.verify_fibonacci(proof),
            ProofAirType::Sum => self.verify_sum(proof),
            ProofAirType::Multiplication => self.verify_multiplication(proof),
            ProofAirType::Range => self.verify_range(proof),
            ProofAirType::KeyCommit => self.verify_key_commit(proof),
        }
    }

    pub fn verify_fibonacci(&self, proof: &StarkProof) -> Result<bool> {
        if !check_fibonacci_public_values(proof.num_rows, &proof.public_values) {
            return Ok(false);
        }
        let pv = safe_to_field_vec(&proof.public_values)?;
        let log_n = proof.num_rows.trailing_zeros() as usize;
        let cfg = create_config(&self.perm, log_n);
        let mut ch = MyChallenger::new(self.perm.clone());
        stark_verify_result(verify(&cfg, &self.air, &mut ch, &proof.inner, &pv))
    }

    pub fn verify_sum(&self, proof: &StarkProof) -> Result<bool> {
        if !proof.num_rows.is_power_of_two() || proof.num_rows < 2 {
            return Ok(false);
        }
        let air = SimpleAir::sum();
        let pv = safe_to_field_vec(&proof.public_values)?;
        let log_n = proof.num_rows.trailing_zeros() as usize;
        let cfg = create_config(&self.perm, log_n);
        let mut ch = MyChallenger::new(self.perm.clone());
        stark_verify_result(verify(&cfg, &air, &mut ch, &proof.inner, &pv))
    }

    pub fn verify_multiplication(&self, proof: &StarkProof) -> Result<bool> {
        if !proof.num_rows.is_power_of_two() || proof.num_rows < 2 {
            return Ok(false);
        }
        let air = SimpleAir::multiplication();
        let pv = safe_to_field_vec(&proof.public_values)?;
        let log_n = proof.num_rows.trailing_zeros() as usize;
        let cfg = create_config(&self.perm, log_n);
        let mut ch = MyChallenger::new(self.perm.clone());
        stark_verify_result(verify(&cfg, &air, &mut ch, &proof.inner, &pv))
    }

    pub fn verify_range(&self, proof: &StarkProof) -> Result<bool> {
        if !proof.num_rows.is_power_of_two() || proof.num_rows < 2 {
            return Ok(false);
        }
        let air = RangeAir::new();
        let pv = safe_to_field_vec(&proof.public_values)?;
        let log_n = proof.num_rows.trailing_zeros() as usize;
        let cfg = create_config(&self.perm, log_n);
        let mut ch = MyChallenger::new(self.perm.clone());
        stark_verify_result(verify(&cfg, &air, &mut ch, &proof.inner, &pv))
    }

    /// Verify a key commitment proof.
    ///
    /// Checks that the STARK proof is valid for the `KeyCommitAir` circuit.
    /// The public values contain `[eval_final, num_elements]`.
    pub fn verify_key_commit(&self, proof: &StarkProof) -> Result<bool> {
        if !proof.num_rows.is_power_of_two() || proof.num_rows < 2 {
            return Ok(false);
        }
        if proof.public_values.len() != 2 {
            return Ok(false);
        }
        let air = KeyCommitAir;
        let pv = safe_to_field_vec(&proof.public_values)?;
        let log_n = proof.num_rows.trailing_zeros() as usize;
        let cfg = create_config(&self.perm, log_n);
        let mut ch = MyChallenger::new(self.perm.clone());
        stark_verify_result(verify(&cfg, &air, &mut ch, &proof.inner, &pv))
    }
}

// ── StarkProof ────────────────────────────────────────────────────────────────

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct StarkProof {
    pub num_rows: usize,
    pub public_values: Vec<u64>,
    pub air_type: ProofAirType,
    pub(crate) inner: Proof<MyStarkConfig>,
}

#[allow(clippy::missing_fields_in_debug)]
impl core::fmt::Debug for StarkProof {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("StarkProof")
            .field("num_rows", &self.num_rows)
            .field("public_values", &self.public_values)
            .field("air_type", &self.air_type)
            .finish()
    }
}

// ── Serialization helpers ────────────────────────────────────────────────────

#[cfg(feature = "serde")]
impl StarkProof {
    /// Serialize to JSON bytes.
    pub fn to_json(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).map_err(|e| ZKGuardError::SerializationError {
            reason: alloc::format!("JSON serialize: {}", e),
        })
    }

    /// Deserialize from JSON bytes.
    pub fn from_json(data: &[u8]) -> Result<Self> {
        serde_json::from_slice(data).map_err(|e| ZKGuardError::SerializationError {
            reason: alloc::format!("JSON deserialize: {}", e),
        })
    }

    /// Serialize to bincode bytes (compact binary format).
    pub fn to_bincode(&self) -> Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| ZKGuardError::SerializationError {
            reason: alloc::format!("bincode serialize: {}", e),
        })
    }

    /// Deserialize from bincode bytes.
    pub fn from_bincode(data: &[u8]) -> Result<Self> {
        bincode::deserialize(data).map_err(|e| ZKGuardError::SerializationError {
            reason: alloc::format!("bincode deserialize: {}", e),
        })
    }

    /// Save proof to a file (bincode format).
    #[cfg(feature = "std")]
    pub fn save_to_file(&self, path: &std::path::Path) -> Result<()> {
        let data = self.to_bincode()?;
        std::fs::write(path, &data).map_err(|e| ZKGuardError::SerializationError {
            reason: alloc::format!("file write: {}", e),
        })
    }

    /// Load proof from a file (bincode format).
    #[cfg(feature = "std")]
    pub fn load_from_file(path: &std::path::Path) -> Result<Self> {
        let data = std::fs::read(path).map_err(|e| ZKGuardError::SerializationError {
            reason: alloc::format!("file read: {}", e),
        })?;
        Self::from_bincode(&data)
    }
}

// ── Private helpers ───────────────────────────────────────────────────────────

/// Convert public value u64s to Goldilocks field elements safely (no panic).
fn safe_to_field_vec(values: &[u64]) -> Result<Vec<Val>> {
    let order = <Val as PrimeField64>::ORDER_U64;
    let mut out = Vec::with_capacity(values.len());
    for &v in values {
        if v >= order {
            return Err(ZKGuardError::InvalidPublicInputs {
                reason: alloc::format!("public value {} exceeds Goldilocks order {}", v, order),
            });
        }
        out.push(Val::from_canonical_u64(v));
    }
    Ok(out)
}

/// Convert a Plonky3 verification result into our error type.
///
/// - `Ok(())` → `Ok(true)` — proof is valid
/// - `Err(e)` → `Err(VerificationFailed)` — proof is invalid, error detail preserved
///
/// This avoids silently swallowing the p3 error via `.is_ok()`.
fn stark_verify_result<E: core::fmt::Debug>(result: core::result::Result<(), E>) -> Result<bool> {
    match result {
        Ok(()) => Ok(true),
        Err(e) => Err(ZKGuardError::VerificationFailed {
            reason: alloc::format!("{:?}", e),
        }),
    }
}

fn create_perm() -> Perm {
    use crate::utils::constants::ZKGUARD_POSEIDON2_SEED;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    let mut rng = ChaCha20Rng::seed_from_u64(ZKGUARD_POSEIDON2_SEED);
    Perm::new_from_rng_128(
        Poseidon2ExternalMatrixGeneral,
        DiffusionMatrixGoldilocks,
        &mut rng,
    )
}

fn create_config(perm: &Perm, log_n: usize) -> MyStarkConfig {
    let hash = MyHash::new(perm.clone());
    let compress = MyCompress::new(perm.clone());
    let val_mmcs = ValMmcs::new(hash.clone(), compress.clone());
    let ch_mmcs = ChallengeMmcs::new(val_mmcs.clone());
    use crate::utils::constants::{FRI_LOG_BLOWUP, FRI_NUM_QUERIES, FRI_POW_BITS};
    let fri_cfg = FriConfig {
        log_blowup: FRI_LOG_BLOWUP,
        num_queries: FRI_NUM_QUERIES,
        proof_of_work_bits: FRI_POW_BITS,
        mmcs: ch_mmcs,
    };
    let dft = p3_dft::Radix2DitParallel;
    let pcs = Pcs::new(log_n, dft, val_mmcs, fri_cfg);
    StarkConfig::new(pcs)
}

fn build_fibonacci_trace(num_rows: usize) -> Result<RowMajorMatrix<Val>> {
    if !num_rows.is_power_of_two() || num_rows < 2 {
        return Err(ZKGuardError::InvalidWitness {
            reason: alloc::format!("num_rows must be power-of-two ≥ 2: {}", num_rows),
        });
    }
    let mut values = Vec::with_capacity(num_rows * 2);
    let mut a = Val::zero();
    let mut b = Val::one();
    for _ in 0..num_rows {
        values.push(a);
        values.push(b);
        let c = a + b;
        a = b;
        b = c;
    }
    Ok(RowMajorMatrix::new(values, 2))
}

fn fibonacci_public_values(num_rows: usize) -> Vec<Val> {
    let mut a = Val::zero();
    let mut b = Val::one();
    for _ in 0..(num_rows - 1) {
        let c = a + b;
        a = b;
        b = c;
    }
    vec![Val::zero(), Val::one(), a, b]
}

fn check_fibonacci_public_values(num_rows: usize, pv: &[u64]) -> bool {
    if pv.len() != 4 {
        return false;
    }
    if !num_rows.is_power_of_two() || num_rows < 2 {
        return false;
    }
    if pv[0] != 0 || pv[1] != 1 {
        return false;
    }
    let mut a = Val::zero();
    let mut b = Val::one();
    for _ in 0..(num_rows - 1) {
        let c = a + b;
        a = b;
        b = c;
    }
    pv[2] == a.as_canonical_u64() && pv[3] == b.as_canonical_u64()
}

fn proof_num_rows(len: usize) -> usize {
    len.next_power_of_two().max(2)
}

fn sum_public_values(a: &[u64], b: &[u64]) -> Vec<Val> {
    if a.is_empty() {
        return vec![];
    }
    let n = a.len() - 1;
    let vals = |i: usize| -> (Val, Val, Val) {
        let av = Val::from_canonical_u64(a[i]);
        let bv = Val::from_canonical_u64(b[i]);
        (av, bv, av + bv)
    };
    let (a0, b0, c0) = vals(0);
    let (an, bn, cn) = vals(n);
    vec![a0, b0, c0, an, bn, cn]
}

fn mul_public_values(a: &[u64], b: &[u64]) -> Vec<Val> {
    if a.is_empty() {
        return vec![];
    }
    let n = a.len() - 1;
    let vals = |i: usize| -> (Val, Val, Val) {
        let av = Val::from_canonical_u64(a[i]);
        let bv = Val::from_canonical_u64(b[i]);
        (av, bv, av * bv)
    };
    let (a0, b0, c0) = vals(0);
    let (an, bn, cn) = vals(n);
    vec![a0, b0, c0, an, bn, cn]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fibonacci_prove_verify() {
        let prover = StarkProver::new(SimpleAir::fibonacci()).unwrap();
        let proof = prover.prove_fibonacci(8).unwrap();
        let verifier = prover.get_verifier();
        assert!(verifier.verify_fibonacci(&proof).unwrap());
    }

    #[test]
    fn test_fibonacci_invalid_trace_size() {
        let prover = StarkProver::new(SimpleAir::fibonacci()).unwrap();
        assert!(prover.prove_fibonacci(7).is_err());
    }

    #[test]
    fn test_sum_prove_verify() {
        let prover = StarkProver::new(SimpleAir::sum()).unwrap();
        let a = alloc::vec![1u64, 2, 3, 4];
        let b = alloc::vec![10u64, 20, 30, 40];
        let proof = prover.prove_sum(&a, &b).unwrap();
        let verifier = prover.get_verifier();
        assert!(verifier.verify_sum(&proof).unwrap());
    }

    #[test]
    fn test_range_prove_verify() {
        let prover = StarkProver::new(SimpleAir::fibonacci()).unwrap();
        let proof = prover.prove_range(1000, 500).unwrap();
        let verifier = prover.get_verifier();
        assert!(verifier.verify_range(&proof).unwrap());
    }

    #[test]
    fn test_key_commit_prove_verify() {
        let prover = StarkProver::new(SimpleAir::fibonacci()).unwrap();
        // Simulate key bytes as field elements
        let key_elements = alloc::vec![115, 107, 45, 97, 110, 116]; // "sk-ant" in ASCII
        let proof = prover.prove_key_commit(&key_elements).unwrap();
        assert_eq!(proof.air_type, ProofAirType::KeyCommit);
        assert_eq!(proof.public_values.len(), 2); // [eval, num_elements]
        assert_eq!(proof.public_values[1], 6); // 6 elements

        let verifier = prover.get_verifier();
        assert!(verifier.verify_key_commit(&proof).unwrap());
    }

    #[test]
    fn test_key_commit_verify_by_type() {
        let prover = StarkProver::new(SimpleAir::fibonacci()).unwrap();
        let key_elements = alloc::vec![1u64, 2, 3, 4, 5, 6, 7, 8];
        let proof = prover.prove_key_commit(&key_elements).unwrap();
        let verifier = prover.get_verifier();
        assert!(verifier.verify_by_type(&proof).unwrap());
    }

    #[cfg(feature = "serde")]
    #[test]
    fn test_proof_json_round_trip() {
        let prover = StarkProver::new(SimpleAir::fibonacci()).unwrap();
        let proof = prover.prove_fibonacci(8).unwrap();

        let json = proof.to_json().unwrap();
        let restored = StarkProof::from_json(&json).unwrap();

        assert_eq!(restored.num_rows, proof.num_rows);
        assert_eq!(restored.public_values, proof.public_values);
        assert_eq!(restored.air_type, proof.air_type);

        // Verify the restored proof is still valid
        let verifier = prover.get_verifier();
        assert!(verifier.verify_fibonacci(&restored).unwrap());
    }

    #[cfg(feature = "serde")]
    #[test]
    fn test_proof_bincode_round_trip() {
        let prover = StarkProver::new(SimpleAir::fibonacci()).unwrap();
        let proof = prover.prove_fibonacci(8).unwrap();

        let bin = proof.to_bincode().unwrap();
        let restored = StarkProof::from_bincode(&bin).unwrap();

        assert_eq!(restored.num_rows, proof.num_rows);
        assert_eq!(restored.public_values, proof.public_values);
        assert_eq!(restored.air_type, proof.air_type);

        let verifier = prover.get_verifier();
        assert!(verifier.verify_fibonacci(&restored).unwrap());
    }

    #[cfg(all(feature = "serde", feature = "std"))]
    #[test]
    fn test_proof_file_round_trip() {
        let prover = StarkProver::new(SimpleAir::fibonacci()).unwrap();
        let proof = prover.prove_fibonacci(8).unwrap();

        let tmp = std::env::temp_dir().join("zkguard_test_proof.bin");
        proof.save_to_file(&tmp).unwrap();
        let restored = StarkProof::load_from_file(&tmp).unwrap();
        std::fs::remove_file(&tmp).ok();

        assert_eq!(restored.num_rows, proof.num_rows);
        assert_eq!(restored.public_values, proof.public_values);
        assert_eq!(restored.air_type, proof.air_type);

        let verifier = prover.get_verifier();
        assert!(verifier.verify_fibonacci(&restored).unwrap());
    }

    #[cfg(feature = "serde")]
    #[test]
    fn test_key_commit_proof_serialization() {
        let prover = StarkProver::new(SimpleAir::fibonacci()).unwrap();
        let elements = alloc::vec![115, 107, 45, 97, 110, 116];
        let proof = prover.prove_key_commit(&elements).unwrap();

        // bincode round-trip
        let bin = proof.to_bincode().unwrap();
        let restored = StarkProof::from_bincode(&bin).unwrap();

        let verifier = prover.get_verifier();
        assert!(verifier.verify_key_commit(&restored).unwrap());
    }
}
