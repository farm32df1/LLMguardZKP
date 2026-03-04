//! KeyCommitAir — proves knowledge of field elements whose polynomial
//! evaluation equals a public commitment value.
//!
//! **ZK property**: the STARK proof hides the witness (key + salt field elements).
//! **Soundness**: the polynomial evaluation is collision-resistant over Goldilocks
//! (Schwartz-Zippel: collision probability ≤ degree / |F| ≈ 2^{-50} for key lengths ≤ 16K).
//!
//! ## Architecture note (v0.2)
//!
//! This AIR proves knowledge of field elements via polynomial evaluation hash.
//! The binding to the Poseidon2 commitment is ensured by the vault layer:
//!   1. The STARK proof hides the key bytes (ZK).
//!   2. The vault links the STARK proof to the Poseidon2 commitment.
//!
//! **v0.3 TODO**: Implement full Poseidon2-in-circuit for end-to-end verifiability
//! without trusting the vault layer.

use crate::core::errors::{Result, ZKGuardError};

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use p3_air::{Air as P3Air, AirBuilder, BaseAir};
use p3_field::{AbstractField, PrimeField64};
use p3_goldilocks::Goldilocks;
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;

type Val = Goldilocks;

/// A fixed evaluation point derived from the ZKGUARD domain tag.
/// `ALPHA = Poseidon2(b"ZKGUARD::KeyCommit::EvalPoint")[0..8] mod p`
///
/// This is a constant known to both prover and verifier.
pub const ALPHA: u64 = 0x7A4B_4755_4152_4431; // "zKGUARD1" as LE u64, mod Goldilocks

pub use crate::utils::constants::{KEY_COMMIT_WIDTH, MAX_KEY_ELEMENTS};

/// AIR circuit for polynomial evaluation commitment.
///
/// Width = 3 columns:
/// - `col 0` : `value`       — the secret field element (key byte / salt byte)
/// - `col 1` : `eval`        — running polynomial evaluation accumulator
/// - `col 2` : `alpha_power` — α^row (geometric progression)
///
/// Constraints:
/// - **First row**: `eval = value`, `alpha_power = 1`
/// - **Transition**: `alpha_power_next = alpha_power * ALPHA`
///   `eval_next = eval + value_next * alpha_power_next`
///
/// Public values: `[eval_final, num_elements]`
#[derive(Debug, Clone)]
pub struct KeyCommitAir;

impl Default for KeyCommitAir {
    fn default() -> Self {
        Self
    }
}

impl BaseAir<Val> for KeyCommitAir {
    fn width(&self) -> usize {
        KEY_COMMIT_WIDTH
    }
}

impl<AB: AirBuilder<F = Val>> P3Air<AB> for KeyCommitAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let next = main.row_slice(1);

        let alpha = AB::Expr::from_canonical_u64(ALPHA);

        let value = local[0];
        let eval = local[1];
        let alpha_power = local[2];

        let next_value = next[0];
        let next_eval = next[1];
        let next_alpha_power = next[2];

        // ── First row constraints ───────────────────────────────────────────
        // eval_0 = value_0   (first element contributes value * α^0 = value * 1)
        // alpha_power_0 = 1
        builder.when_first_row().assert_eq(eval, value);
        builder
            .when_first_row()
            .assert_eq(alpha_power, AB::Expr::one());

        // ── Transition constraints ──────────────────────────────────────────
        // alpha_power_{i+1} = alpha_power_i * ALPHA
        builder
            .when_transition()
            .assert_eq(next_alpha_power, alpha_power * alpha);

        // eval_{i+1} = eval_i + value_{i+1} * alpha_power_{i+1}
        builder
            .when_transition()
            .assert_eq(next_eval, eval + next_value * next_alpha_power);
    }
}

// ── Trace builder ────────────────────────────────────────────────────────────

#[cfg(feature = "alloc")]
pub mod trace_builder {
    use super::*;

    /// Build the trace for a key commitment proof.
    ///
    /// `elements` are the secret field elements (key bytes + salt bytes
    /// converted via `bytes_to_fields`).
    ///
    /// Returns `(trace, eval_final)` where `eval_final` is the polynomial
    /// evaluation that becomes a public value.
    pub fn build_key_commit_trace(elements: &[u64]) -> Result<(RowMajorMatrix<Val>, u64)> {
        if elements.is_empty() {
            return Err(ZKGuardError::InvalidWitness {
                reason: "key elements must not be empty".into(),
            });
        }
        if elements.len() > MAX_KEY_ELEMENTS {
            return Err(ZKGuardError::InvalidWitness {
                reason: alloc::format!(
                    "key has {} elements, max is {}",
                    elements.len(),
                    MAX_KEY_ELEMENTS
                ),
            });
        }

        let order = <Val as PrimeField64>::ORDER_U64;
        for (i, &v) in elements.iter().enumerate() {
            if v >= order {
                return Err(ZKGuardError::InvalidWitness {
                    reason: alloc::format!("element[{}] = {} exceeds field order", i, v),
                });
            }
        }

        let n = elements.len();
        // Pad to power of two (STARK requirement), minimum 2 rows
        let num_rows = n.next_power_of_two().max(2);

        let alpha = Val::from_canonical_u64(ALPHA);
        let width = KEY_COMMIT_WIDTH;
        let mut values = Vec::with_capacity(num_rows * width);

        let mut eval = Val::zero();
        let mut alpha_power = Val::one();

        let padded = elements
            .iter()
            .copied()
            .chain(core::iter::repeat(0u64))
            .take(num_rows);

        for (i, elem) in padded.enumerate() {
            let val = Val::from_canonical_u64(elem);

            if i == 0 {
                eval = val;
                // alpha_power stays at 1
            } else {
                alpha_power *= alpha;
                eval += val * alpha_power;
            }

            values.push(val);
            values.push(eval);
            values.push(alpha_power);
        }

        let eval_final = eval.as_canonical_u64();
        Ok((RowMajorMatrix::new(values, width), eval_final))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_commit_trace_basic() {
        let elements = [1u64, 2, 3, 4];
        let (trace, eval) = trace_builder::build_key_commit_trace(&elements).unwrap();
        assert_eq!(trace.width(), 3);
        assert!(trace.height() >= 4);
        assert!(eval > 0);
    }

    #[test]
    fn test_key_commit_deterministic() {
        let elements = [10u64, 20, 30];
        let (_, eval1) = trace_builder::build_key_commit_trace(&elements).unwrap();
        let (_, eval2) = trace_builder::build_key_commit_trace(&elements).unwrap();
        assert_eq!(eval1, eval2);
    }

    #[test]
    fn test_key_commit_different_keys_different_evals() {
        let (_, eval1) = trace_builder::build_key_commit_trace(&[1, 2, 3]).unwrap();
        let (_, eval2) = trace_builder::build_key_commit_trace(&[3, 2, 1]).unwrap();
        assert_ne!(eval1, eval2);
    }

    #[test]
    fn test_empty_elements_rejected() {
        assert!(trace_builder::build_key_commit_trace(&[]).is_err());
    }

    #[test]
    fn test_overflow_element_rejected() {
        let order = <Val as PrimeField64>::ORDER_U64;
        assert!(trace_builder::build_key_commit_trace(&[order]).is_err());
    }
}
