//! StarkConfig — STARK security parameters

use crate::core::errors::{Result, ZKGuardError};
use crate::utils::constants::{
    FRI_FOLDING_FACTOR, FRI_NUM_QUERIES, FRI_QUERIES_MAX, FRI_QUERIES_MIN, GRINDING_BITS_MAX,
    SECURITY_BITS_MAX, SECURITY_BITS_MIN, TRACE_HEIGHT_MIN,
};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct StarkConfig {
    pub security_bits: usize,
    pub fri_folding_factor: usize,
    pub fri_queries: usize,
    pub grinding_bits: usize,
    pub blowup_factor: usize,
    pub trace_height: usize,
}

impl Default for StarkConfig {
    fn default() -> Self {
        Self {
            security_bits: 100,
            fri_folding_factor: FRI_FOLDING_FACTOR,
            fri_queries: FRI_NUM_QUERIES,
            grinding_bits: 10,
            blowup_factor: 4,
            trace_height: 1024,
        }
    }
}

impl StarkConfig {
    pub fn for_testing() -> Self {
        Self {
            security_bits: 80,
            fri_folding_factor: 2,
            fri_queries: 50,
            grinding_bits: 0,
            blowup_factor: 2,
            trace_height: 256,
        }
    }

    pub fn high_security() -> Self {
        Self {
            security_bits: 128,
            fri_folding_factor: 8,
            fri_queries: 128,
            grinding_bits: 15,
            blowup_factor: 8,
            trace_height: 2048,
        }
    }

    pub fn builder() -> StarkConfigBuilder {
        StarkConfigBuilder::new()
    }

    pub fn validate(&self) -> Result<()> {
        if self.security_bits < SECURITY_BITS_MIN || self.security_bits > SECURITY_BITS_MAX {
            return Err(ZKGuardError::ConfigurationError {
                reason: alloc::format!(
                    "security_bits {} out of [{}, {}]",
                    self.security_bits,
                    SECURITY_BITS_MIN,
                    SECURITY_BITS_MAX
                ),
            });
        }
        if !matches!(self.fri_folding_factor, 2 | 4 | 8 | 16) {
            return Err(ZKGuardError::ConfigurationError {
                reason: alloc::format!(
                    "fri_folding_factor {} must be 2/4/8/16",
                    self.fri_folding_factor
                ),
            });
        }
        if self.fri_queries < FRI_QUERIES_MIN || self.fri_queries > FRI_QUERIES_MAX {
            return Err(ZKGuardError::ConfigurationError {
                reason: alloc::format!(
                    "fri_queries {} out of [{}, {}]",
                    self.fri_queries,
                    FRI_QUERIES_MIN,
                    FRI_QUERIES_MAX
                ),
            });
        }
        if self.grinding_bits > GRINDING_BITS_MAX {
            return Err(ZKGuardError::ConfigurationError {
                reason: alloc::format!(
                    "grinding_bits {} > {}",
                    self.grinding_bits,
                    GRINDING_BITS_MAX
                ),
            });
        }
        if !matches!(self.blowup_factor, 2 | 4 | 8 | 16) {
            return Err(ZKGuardError::ConfigurationError {
                reason: alloc::format!("blowup_factor {} must be 2/4/8/16", self.blowup_factor),
            });
        }
        if !self.trace_height.is_power_of_two() || self.trace_height < TRACE_HEIGHT_MIN {
            return Err(ZKGuardError::ConfigurationError {
                reason: alloc::format!(
                    "trace_height {} must be power-of-two ≥ {}",
                    self.trace_height,
                    TRACE_HEIGHT_MIN
                ),
            });
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Default)]
pub struct StarkConfigBuilder {
    config: StarkConfig,
}

impl StarkConfigBuilder {
    pub fn new() -> Self {
        Self {
            config: StarkConfig::default(),
        }
    }
    pub fn security_bits(mut self, v: usize) -> Self {
        self.config.security_bits = v;
        self
    }
    pub fn fri_folding_factor(mut self, v: usize) -> Self {
        self.config.fri_folding_factor = v;
        self
    }
    pub fn fri_queries(mut self, v: usize) -> Self {
        self.config.fri_queries = v;
        self
    }
    pub fn grinding_bits(mut self, v: usize) -> Self {
        self.config.grinding_bits = v;
        self
    }
    pub fn blowup_factor(mut self, v: usize) -> Self {
        self.config.blowup_factor = v;
        self
    }
    pub fn trace_height(mut self, v: usize) -> Self {
        self.config.trace_height = v;
        self
    }
    pub fn build(self) -> Result<StarkConfig> {
        self.config.validate()?;
        Ok(self.config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_valid() {
        assert!(StarkConfig::default().validate().is_ok());
    }
    #[test]
    fn test_builder() {
        let c = StarkConfig::builder()
            .security_bits(128)
            .fri_queries(80)
            .build()
            .unwrap();
        assert_eq!(c.security_bits, 128);
    }
    #[test]
    fn test_low_security_rejected() {
        assert!(StarkConfig::builder().security_bits(50).build().is_err());
    }
}
