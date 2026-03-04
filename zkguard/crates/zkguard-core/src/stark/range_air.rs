//! Range Proof AIR — proves `value >= threshold` without revealing `value`

use crate::core::errors::{Result, ZKGuardError};

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use p3_air::{Air as P3Air, AirBuilder, BaseAir};
use p3_field::AbstractField;
use p3_goldilocks::Goldilocks;
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;

pub const RANGE_BITS: usize = 32;
/// Both `value` and `threshold` must be < MAX_RANGE_VALUE to prevent
/// Goldilocks field-overflow attacks.
pub const MAX_RANGE_VALUE: u64 = 1u64 << RANGE_BITS;

#[derive(Debug, Clone)]
pub struct RangeAir {
    num_bits: usize,
}

impl RangeAir {
    pub fn new() -> Self {
        Self {
            num_bits: RANGE_BITS,
        }
    }
}

impl Default for RangeAir {
    fn default() -> Self {
        Self::new()
    }
}

impl BaseAir<Goldilocks> for RangeAir {
    fn width(&self) -> usize {
        self.num_bits + 3
    }
}

impl<AB: AirBuilder<F = Goldilocks>> P3Air<AB> for RangeAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);

        let bits_end = self.num_bits;
        let value_idx = bits_end;
        let thresh_idx = bits_end + 1;
        let diff_idx = bits_end + 2;

        // Each bit must be binary
        for i in 0..self.num_bits {
            let bit = local[i];
            builder.assert_zero(bit * (AB::Expr::one() - bit));
        }

        // diff = value − threshold
        builder.assert_eq(local[diff_idx], local[value_idx] - local[thresh_idx]);

        // bit decomposition of diff
        let mut recon = AB::Expr::zero();
        let mut pow = AB::Expr::one();
        for i in 0..self.num_bits {
            recon += local[i] * pow.clone();
            pow *= AB::Expr::from_canonical_u64(2);
        }
        builder.assert_eq(recon, local[diff_idx]);
    }
}

#[cfg(feature = "alloc")]
pub mod trace_builder {
    use super::*;

    pub fn build_range_proof_trace(
        value: u64,
        threshold: u64,
    ) -> Result<RowMajorMatrix<Goldilocks>> {
        if value >= MAX_RANGE_VALUE {
            return Err(ZKGuardError::InvalidWitness {
                reason: alloc::format!("value {} >= MAX_RANGE_VALUE {}", value, MAX_RANGE_VALUE),
            });
        }
        if threshold >= MAX_RANGE_VALUE {
            return Err(ZKGuardError::InvalidWitness {
                reason: alloc::format!(
                    "threshold {} >= MAX_RANGE_VALUE {}",
                    threshold,
                    MAX_RANGE_VALUE
                ),
            });
        }
        if value < threshold {
            return Err(ZKGuardError::InvalidWitness {
                reason: alloc::format!("value {} < threshold {}", value, threshold),
            });
        }
        let diff = value - threshold;

        let mut bits = Vec::with_capacity(RANGE_BITS);
        let mut rem = diff;
        for _ in 0..RANGE_BITS {
            bits.push(Goldilocks::from_canonical_u64(rem & 1));
            rem >>= 1;
        }

        let mut row = bits;
        row.push(Goldilocks::from_canonical_u64(value));
        row.push(Goldilocks::from_canonical_u64(threshold));
        row.push(Goldilocks::from_canonical_u64(diff));

        let width = RANGE_BITS + 3;
        let mut values = Vec::with_capacity(width * 2);
        values.extend_from_slice(&row);
        values.extend_from_slice(&row); // duplicate for 2 rows (STARK power-of-two req)

        Ok(RowMajorMatrix::new(values, width))
    }
}

#[cfg(test)]
mod tests {
    use super::trace_builder::*;

    #[test]
    fn test_valid_range() {
        assert!(build_range_proof_trace(25, 18).is_ok());
        assert!(build_range_proof_trace(0, 0).is_ok());
    }

    #[test]
    fn test_value_below_threshold() {
        assert!(build_range_proof_trace(5, 10).is_err());
    }

    #[test]
    fn test_overflow_guard() {
        assert!(build_range_proof_trace(super::MAX_RANGE_VALUE, 0).is_err());
        assert!(build_range_proof_trace(0, super::MAX_RANGE_VALUE).is_err());
    }
}
