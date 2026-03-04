//! Error types for zkguard

#[cfg(feature = "alloc")]
use alloc::string::String;

use core::fmt;

pub type Result<T> = core::result::Result<T, ZKGuardError>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ZKGuardError {
    ProofGenerationFailed {
        #[cfg(feature = "alloc")]
        reason: String,
        #[cfg(not(feature = "alloc"))]
        reason: &'static str,
    },
    VerificationFailed {
        #[cfg(feature = "alloc")]
        reason: String,
        #[cfg(not(feature = "alloc"))]
        reason: &'static str,
    },
    InvalidProof,
    InvalidWitness {
        #[cfg(feature = "alloc")]
        reason: String,
        #[cfg(not(feature = "alloc"))]
        reason: &'static str,
    },
    InvalidPublicInputs {
        #[cfg(feature = "alloc")]
        reason: String,
        #[cfg(not(feature = "alloc"))]
        reason: &'static str,
    },
    BatchError {
        #[cfg(feature = "alloc")]
        reason: String,
        #[cfg(not(feature = "alloc"))]
        reason: &'static str,
    },
    MerkleError {
        #[cfg(feature = "alloc")]
        reason: String,
        #[cfg(not(feature = "alloc"))]
        reason: &'static str,
    },
    ConfigurationError {
        #[cfg(feature = "alloc")]
        reason: String,
        #[cfg(not(feature = "alloc"))]
        reason: &'static str,
    },
    SerializationError {
        #[cfg(feature = "alloc")]
        reason: String,
        #[cfg(not(feature = "alloc"))]
        reason: &'static str,
    },
    ResourceLimitExceeded {
        #[cfg(feature = "alloc")]
        reason: String,
        #[cfg(not(feature = "alloc"))]
        reason: &'static str,
    },
    InternalError {
        #[cfg(feature = "alloc")]
        reason: String,
        #[cfg(not(feature = "alloc"))]
        reason: &'static str,
    },
    /// LLM guard specific errors
    #[cfg(feature = "llm-guard")]
    VaultError {
        reason: String,
    },
    #[cfg(feature = "llm-guard")]
    HandleExpired,
    #[cfg(feature = "llm-guard")]
    HandleNotFound,
}

impl fmt::Display for ZKGuardError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ZKGuardError::ProofGenerationFailed { reason } => {
                write!(f, "Proof generation failed: {}", reason)
            }
            ZKGuardError::VerificationFailed { reason } => {
                write!(f, "Proof verification failed: {}", reason)
            }
            ZKGuardError::InvalidProof => write!(f, "Invalid proof"),
            ZKGuardError::InvalidWitness { reason } => {
                write!(f, "Invalid witness: {}", reason)
            }
            ZKGuardError::InvalidPublicInputs { reason } => {
                write!(f, "Invalid public inputs: {}", reason)
            }
            ZKGuardError::BatchError { reason } => {
                write!(f, "Batch error: {}", reason)
            }
            ZKGuardError::MerkleError { reason } => {
                write!(f, "Merkle error: {}", reason)
            }
            ZKGuardError::ConfigurationError { reason } => {
                write!(f, "Configuration error: {}", reason)
            }
            ZKGuardError::SerializationError { reason } => {
                write!(f, "Serialization error: {}", reason)
            }
            ZKGuardError::ResourceLimitExceeded { reason } => {
                write!(f, "Resource limit exceeded: {}", reason)
            }
            ZKGuardError::InternalError { reason } => {
                write!(f, "Internal error: {}", reason)
            }
            #[cfg(feature = "llm-guard")]
            ZKGuardError::VaultError { reason } => write!(f, "Vault error: {}", reason),
            #[cfg(feature = "llm-guard")]
            ZKGuardError::HandleExpired => write!(f, "Key handle has expired"),
            #[cfg(feature = "llm-guard")]
            ZKGuardError::HandleNotFound => write!(f, "Key handle not found in vault"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ZKGuardError {}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::format;

    #[test]
    fn test_error_display() {
        assert_eq!(format!("{}", ZKGuardError::InvalidProof), "Invalid proof");
    }

    #[test]
    fn test_error_proof_generation() {
        let err = ZKGuardError::ProofGenerationFailed {
            reason: "test".into(),
        };
        assert!(format!("{}", err).contains("Proof generation failed"));
    }

    #[test]
    fn test_error_clone_eq() {
        let e1 = ZKGuardError::InvalidProof;
        assert_eq!(e1, e1.clone());
    }
}
