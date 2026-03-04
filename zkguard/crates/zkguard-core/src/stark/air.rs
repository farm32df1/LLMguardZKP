//! AIR (Algebraic Intermediate Representation) — Fibonacci, Sum, Multiplication

use crate::core::types::FieldElement;

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use p3_air::{Air as P3Air, AirBuilder, BaseAir};
use p3_field::AbstractField;
use p3_goldilocks::Goldilocks;
use p3_matrix::{dense::RowMajorMatrix, Matrix};

#[derive(Debug, Clone)]
pub struct SimpleAir {
    num_columns: usize,
    air_type: AirType,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AirType {
    Fibonacci,
    Sum,
    Multiplication,
}

impl SimpleAir {
    pub fn fibonacci() -> Self {
        Self {
            num_columns: 2,
            air_type: AirType::Fibonacci,
        }
    }
    pub fn sum() -> Self {
        Self {
            num_columns: 3,
            air_type: AirType::Sum,
        }
    }
    pub fn multiplication() -> Self {
        Self {
            num_columns: 3,
            air_type: AirType::Multiplication,
        }
    }

    pub fn num_columns(&self) -> usize {
        self.num_columns
    }

    pub fn constraint_degree(&self) -> usize {
        match self.air_type {
            AirType::Fibonacci | AirType::Sum => 1,
            AirType::Multiplication => 2,
        }
    }
}

impl BaseAir<Goldilocks> for SimpleAir {
    fn width(&self) -> usize {
        self.num_columns
    }
}

impl<AB: AirBuilder<F = Goldilocks>> P3Air<AB> for SimpleAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let next = main.row_slice(1);

        match self.air_type {
            AirType::Fibonacci => {
                builder
                    .when_first_row()
                    .assert_eq(local[0], AB::Expr::zero());
                builder
                    .when_first_row()
                    .assert_eq(local[1], AB::Expr::one());
                builder.when_transition().assert_eq(next[0], local[1]);
                builder
                    .when_transition()
                    .assert_eq(next[1], local[0] + local[1]);
            }
            AirType::Sum => {
                builder.assert_eq(local[2], local[0] + local[1]);
            }
            AirType::Multiplication => {
                builder.assert_eq(local[2], local[0] * local[1]);
            }
        }
    }
}

/// Trace generation helpers
#[cfg(feature = "alloc")]
pub mod trace_builder {
    use super::*;
    use crate::core::errors::{Result, ZKGuardError};
    use alloc::vec;

    pub fn build_fibonacci_trace_p3(num_rows: usize) -> Result<RowMajorMatrix<Goldilocks>> {
        if !num_rows.is_power_of_two() {
            return Err(ZKGuardError::InvalidWitness {
                reason: alloc::format!("num_rows must be power of two: {}", num_rows),
            });
        }
        let mut values = Vec::with_capacity(num_rows * 2);
        let mut a = Goldilocks::zero();
        let mut b = Goldilocks::one();
        for _ in 0..num_rows {
            values.push(a);
            values.push(b);
            let c = a + b;
            a = b;
            b = c;
        }
        Ok(RowMajorMatrix::new(values, 2))
    }

    pub fn build_sum_trace_p3(a: &[u64], b: &[u64]) -> Result<RowMajorMatrix<Goldilocks>> {
        if a.len() != b.len() {
            return Err(ZKGuardError::InvalidWitness {
                reason: alloc::format!("length mismatch: a={} b={}", a.len(), b.len()),
            });
        }
        if a.is_empty() {
            return Err(ZKGuardError::InvalidWitness {
                reason: "empty input".into(),
            });
        }
        let len = a.len();
        let num_rows = len.next_power_of_two().max(2);
        let mut values = Vec::with_capacity(num_rows * 3);
        for i in 0..num_rows {
            let av = if i < len {
                Goldilocks::from_canonical_u64(a[i])
            } else {
                Goldilocks::zero()
            };
            let bv = if i < len {
                Goldilocks::from_canonical_u64(b[i])
            } else {
                Goldilocks::zero()
            };
            values.push(av);
            values.push(bv);
            values.push(av + bv);
        }
        Ok(RowMajorMatrix::new(values, 3))
    }

    pub fn build_mul_trace_p3(a: &[u64], b: &[u64]) -> Result<RowMajorMatrix<Goldilocks>> {
        if a.len() != b.len() {
            return Err(ZKGuardError::InvalidWitness {
                reason: alloc::format!("length mismatch: a={} b={}", a.len(), b.len()),
            });
        }
        if a.is_empty() {
            return Err(ZKGuardError::InvalidWitness {
                reason: "empty input".into(),
            });
        }
        let len = a.len();
        let num_rows = len.next_power_of_two().max(2);
        let mut values = Vec::with_capacity(num_rows * 3);
        for i in 0..num_rows {
            let av = if i < len {
                Goldilocks::from_canonical_u64(a[i])
            } else {
                Goldilocks::zero()
            };
            let bv = if i < len {
                Goldilocks::from_canonical_u64(b[i])
            } else {
                Goldilocks::zero()
            };
            values.push(av);
            values.push(bv);
            values.push(av * bv);
        }
        Ok(RowMajorMatrix::new(values, 3))
    }

    pub fn build_fibonacci_trace(length: usize) -> Result<Vec<Vec<FieldElement>>> {
        if !length.is_power_of_two() || length < 2 {
            return Err(ZKGuardError::InvalidWitness {
                reason: alloc::format!("length must be power-of-two ≥ 2: {}", length),
            });
        }
        let mut trace = vec![0u64, 1u64];
        for i in 2..length {
            let next = trace[i - 2].wrapping_add(trace[i - 1]);
            trace.push(next);
        }
        Ok(vec![trace])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use trace_builder::*;

    #[test]
    fn test_fibonacci_air_columns() {
        let air = SimpleAir::fibonacci();
        assert_eq!(air.num_columns(), 2);
    }

    #[test]
    fn test_fibonacci_trace_values() {
        let trace = build_fibonacci_trace(8).unwrap();
        assert_eq!(trace[0][..6], [0, 1, 1, 2, 3, 5]);
    }

    #[test]
    fn test_sum_trace_p3() {
        let a = alloc::vec![1u64, 2];
        let b = alloc::vec![3u64, 4];
        let m = build_sum_trace_p3(&a, &b).unwrap();
        assert_eq!(m.height(), 2);
        assert_eq!(m.width(), 3);
    }
}
