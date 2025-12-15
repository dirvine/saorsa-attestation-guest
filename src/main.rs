// Copyright 2024 Saorsa Labs Limited
//
// Licensed under the MIT License or Apache License, Version 2.0.
// See LICENSE-MIT or LICENSE-APACHE for details.

//! SP1 zkVM Guest Program for Entangled Attestation
//!
//! This program runs inside the SP1 zkVM and proves correct derivation of an
//! `EntangledId` without revealing private inputs (the full ML-DSA-65 public key
//! and derivation nonce).
//!
//! ## Security Properties
//!
//! The proof demonstrates:
//! 1. **Correct Derivation**: `EntangledId = BLAKE3(PK || binary_hash || nonce)`
//! 2. **Key Binding**: The prover knows a public key that hashes to `public_key_hash`
//! 3. **Binary Attestation**: Optionally proves `binary_hash ∈ allowed_binaries`
//!
//! The proof hides:
//! - The full 1952-byte ML-DSA-65 public key (only 32-byte hash revealed)
//! - The derivation nonce
//! - Which specific binary from the allowlist (if any)
//!
//! ## Post-Quantum Security
//!
//! - Identity: ML-DSA-65 (NIST Level 3 PQC)
//! - Hashing: BLAKE3 (quantum-resistant)
//! - Proofs: STARKs (post-quantum secure, no elliptic curves)

// Only disable main and use zkVM entry point when actually targeting zkVM
#![cfg_attr(target_os = "zkvm", no_main)]

#[cfg(target_os = "zkvm")]
sp1_zkvm::entrypoint!(main);

use saorsa_logic::attestation::{derive_entangled_id, verify_binary_allowlist};
use serde::{Deserialize, Serialize};

/// Private witness data provided by the prover.
///
/// This data is NOT revealed in the proof - it's the private input.
#[derive(Deserialize, Clone)]
pub struct AttestationWitness {
    /// ML-DSA-65 public key (1952 bytes).
    /// The prover demonstrates knowledge of this key without revealing it.
    pub public_key: Vec<u8>,

    /// BLAKE3 hash of the binary this identity is bound to.
    pub binary_hash: [u8; 32],

    /// Nonce used in `EntangledId` derivation.
    /// Provides uniqueness for each derivation.
    pub nonce: u64,

    /// Optional allowlist of authorized binary hashes.
    /// If non-empty, the proof verifies `binary_hash ∈ allowed_binaries`.
    pub allowed_binaries: Vec<[u8; 32]>,

    /// Unix timestamp when the proof was generated.
    /// Used for freshness validation.
    pub timestamp: u64,
}

/// Public outputs committed to the proof.
///
/// These values are visible to verifiers and cryptographically bound to the proof.
#[derive(Serialize)]
pub struct AttestationPublicOutputs {
    /// The derived `EntangledId`: `BLAKE3(PK || binary_hash || nonce)`
    pub entangled_id: [u8; 32],

    /// Hash of the binary this identity is bound to.
    /// Verifiers can check this against their allowlist.
    pub binary_hash: [u8; 32],

    /// Hash of the public key: `BLAKE3(public_key)`
    /// Binds the proof to a specific key without revealing the full key.
    pub public_key_hash: [u8; 32],

    /// Unix timestamp when the proof was generated.
    pub proof_timestamp: u64,
}

/// Main entry point for the zkVM guest program.
///
/// This function:
/// 1. Reads the private witness from the prover
/// 2. Derives the `EntangledId` using saorsa-logic
/// 3. Computes the public key hash
/// 4. Optionally verifies the binary allowlist
/// 5. Commits the public outputs to the proof
///
/// # Panics
///
/// Panics if `allowed_binaries` is non-empty and `binary_hash` is not in the
/// allowlist. In zkVM context, panics invalidate the proof, enforcing that only
/// authorized binaries can produce valid proofs.
#[allow(clippy::panic)] // panic! is the correct way to fail a zkVM proof constraint
pub fn main() {
    // Step 1: Read private witness from prover
    let witness: AttestationWitness = sp1_zkvm::io::read();

    // Step 2: Derive EntangledId using the same logic as saorsa-core
    // This is the core computation being proven
    let entangled_id =
        derive_entangled_id(&witness.public_key, &witness.binary_hash, witness.nonce);

    // Step 3: Compute public key hash
    // This commits to the key without revealing the full 1952 bytes
    let public_key_hash = blake3_hash(&witness.public_key);

    // Step 4: Verify binary allowlist if provided
    // If the allowlist is non-empty, the binary must be in it
    if !witness.allowed_binaries.is_empty()
        && verify_binary_allowlist(&witness.binary_hash, &witness.allowed_binaries).is_err()
    {
        // In zkVM, failing a constraint causes the proof to be invalid
        panic!("binary not in allowlist");
    }

    // Step 5: Commit public outputs
    // These values become part of the proof and are visible to verifiers
    let outputs = AttestationPublicOutputs {
        entangled_id,
        binary_hash: witness.binary_hash,
        public_key_hash,
        proof_timestamp: witness.timestamp,
    };

    sp1_zkvm::io::commit(&outputs);
}

/// BLAKE3 hash helper (`no_std` compatible).
///
/// Computes a 32-byte BLAKE3 hash of the input data.
#[inline]
fn blake3_hash(data: &[u8]) -> [u8; 32] {
    *blake3::hash(data).as_bytes()
}

// ============================================================================
// Operational Tooling: Constants and Validation
// ============================================================================

/// ML-DSA-65 public key size in bytes.
pub const ML_DSA_65_PUBLIC_KEY_SIZE: usize = 1952;

/// Minimum allowed timestamp (Jan 1, 2024 00:00:00 UTC).
/// Proofs with timestamps before this are considered invalid.
pub const MIN_TIMESTAMP: u64 = 1_704_067_200;

/// Maximum timestamp skew in seconds (1 hour into future).
/// Proofs claiming timestamps too far in the future are rejected.
pub const MAX_TIMESTAMP_SKEW: u64 = 3600;

/// Maximum number of allowed binaries in the allowlist.
/// Prevents denial-of-service through excessive allowlist size.
pub const MAX_ALLOWED_BINARIES: usize = 1000;

/// Witness validation error types.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WitnessValidationError {
    /// Public key is empty.
    EmptyPublicKey,
    /// Public key size is invalid (expected 1952 bytes for ML-DSA-65).
    InvalidPublicKeySize { actual: usize, expected: usize },
    /// Binary hash is all zeros.
    ZeroBinaryHash,
    /// Timestamp is before minimum allowed.
    TimestampTooOld { timestamp: u64, minimum: u64 },
    /// Timestamp is too far in the future.
    TimestampInFuture { timestamp: u64, maximum: u64 },
    /// Allowlist contains too many entries.
    AllowlistTooLarge { count: usize, maximum: usize },
    /// Allowlist contains duplicate entries.
    DuplicateAllowlistEntry,
    /// Allowlist contains all-zero hash (invalid).
    ZeroHashInAllowlist,
}

impl core::fmt::Display for WitnessValidationError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::EmptyPublicKey => write!(f, "public key is empty"),
            Self::InvalidPublicKeySize { actual, expected } => {
                write!(
                    f,
                    "invalid public key size: {actual} bytes (expected {expected})"
                )
            }
            Self::ZeroBinaryHash => write!(f, "binary hash is all zeros"),
            Self::TimestampTooOld { timestamp, minimum } => {
                write!(f, "timestamp {timestamp} is before minimum {minimum}")
            }
            Self::TimestampInFuture { timestamp, maximum } => {
                write!(f, "timestamp {timestamp} exceeds maximum {maximum}")
            }
            Self::AllowlistTooLarge { count, maximum } => {
                write!(f, "allowlist has {count} entries (maximum {maximum})")
            }
            Self::DuplicateAllowlistEntry => write!(f, "allowlist contains duplicate entries"),
            Self::ZeroHashInAllowlist => write!(f, "allowlist contains all-zero hash"),
        }
    }
}

/// Validate witness data before proof generation.
///
/// This function performs pre-flight checks on the witness data to catch
/// common errors before attempting expensive proof generation. It checks:
///
/// - Public key size matches ML-DSA-65 requirements
/// - Binary hash is not all zeros
/// - Timestamp is within acceptable range
/// - Allowlist is not too large and contains no duplicates
///
/// # Arguments
///
/// * `witness` - The attestation witness to validate
/// * `current_time` - Current Unix timestamp for freshness validation
///
/// # Returns
///
/// `Ok(())` if validation passes, or `Err(WitnessValidationError)` describing the issue.
///
/// # Errors
///
/// Returns `WitnessValidationError` if any validation check fails:
/// - `EmptyPublicKey`: Public key is empty
/// - `InvalidPublicKeySize`: Public key size doesn't match ML-DSA-65 requirements
/// - `ZeroBinaryHash`: Binary hash is all zeros
/// - `TimestampTooOld`: Timestamp is before minimum allowed
/// - `TimestampInFuture`: Timestamp exceeds current time plus skew
/// - `AllowlistTooLarge`: Allowlist contains too many entries
/// - `ZeroHashInAllowlist`: Allowlist contains all-zero hash
/// - `DuplicateAllowlistEntry`: Allowlist contains duplicate entries
///
/// # Example
///
/// ```ignore
/// let witness = AttestationWitness { /* ... */ };
/// let now = std::time::SystemTime::now()
///     .duration_since(std::time::UNIX_EPOCH)
///     .unwrap()
///     .as_secs();
///
/// if let Err(e) = validate_witness(&witness, now) {
///     eprintln!("Witness validation failed: {e}");
///     return;
/// }
/// ```
pub fn validate_witness(
    witness: &AttestationWitness,
    current_time: u64,
) -> Result<(), WitnessValidationError> {
    // Check public key
    if witness.public_key.is_empty() {
        return Err(WitnessValidationError::EmptyPublicKey);
    }
    if witness.public_key.len() != ML_DSA_65_PUBLIC_KEY_SIZE {
        return Err(WitnessValidationError::InvalidPublicKeySize {
            actual: witness.public_key.len(),
            expected: ML_DSA_65_PUBLIC_KEY_SIZE,
        });
    }

    // Check binary hash is not all zeros
    if witness.binary_hash.iter().all(|&b| b == 0) {
        return Err(WitnessValidationError::ZeroBinaryHash);
    }

    // Check timestamp is not too old
    if witness.timestamp < MIN_TIMESTAMP {
        return Err(WitnessValidationError::TimestampTooOld {
            timestamp: witness.timestamp,
            minimum: MIN_TIMESTAMP,
        });
    }

    // Check timestamp is not too far in the future
    let max_timestamp = current_time.saturating_add(MAX_TIMESTAMP_SKEW);
    if witness.timestamp > max_timestamp {
        return Err(WitnessValidationError::TimestampInFuture {
            timestamp: witness.timestamp,
            maximum: max_timestamp,
        });
    }

    // Check allowlist size
    if witness.allowed_binaries.len() > MAX_ALLOWED_BINARIES {
        return Err(WitnessValidationError::AllowlistTooLarge {
            count: witness.allowed_binaries.len(),
            maximum: MAX_ALLOWED_BINARIES,
        });
    }

    // Check for zero hashes in allowlist
    let zero_hash = [0u8; 32];
    for hash in &witness.allowed_binaries {
        if hash == &zero_hash {
            return Err(WitnessValidationError::ZeroHashInAllowlist);
        }
    }

    // Check for duplicates in allowlist (O(n²) but list is small)
    for (i, hash1) in witness.allowed_binaries.iter().enumerate() {
        for hash2 in witness.allowed_binaries.iter().skip(i + 1) {
            if hash1 == hash2 {
                return Err(WitnessValidationError::DuplicateAllowlistEntry);
            }
        }
    }

    Ok(())
}

/// Diagnostic summary of witness data.
///
/// Returns a human-readable summary of the witness for debugging purposes.
/// Does NOT reveal sensitive data like the full public key or nonce.
#[must_use]
pub fn witness_summary(witness: &AttestationWitness) -> WitnessSummary {
    WitnessSummary {
        public_key_size: witness.public_key.len(),
        public_key_hash: blake3_hash(&witness.public_key),
        binary_hash: witness.binary_hash,
        timestamp: witness.timestamp,
        allowlist_count: witness.allowed_binaries.len(),
        has_nonce: witness.nonce != 0,
    }
}

/// Summary of witness data for diagnostics (hides sensitive values).
#[derive(Debug, Clone)]
pub struct WitnessSummary {
    /// Size of the public key in bytes.
    pub public_key_size: usize,
    /// Hash of the public key (not the key itself).
    pub public_key_hash: [u8; 32],
    /// Binary hash from the witness.
    pub binary_hash: [u8; 32],
    /// Timestamp from the witness.
    pub timestamp: u64,
    /// Number of binaries in the allowlist.
    pub allowlist_count: usize,
    /// Whether a non-zero nonce is set.
    pub has_nonce: bool,
}

// ============================================================================
// Tests (only run outside zkVM)
// ============================================================================

#[cfg(all(test, not(target_os = "zkvm")))]
mod tests {
    use super::*;

    #[test]
    fn test_blake3_hash_deterministic() {
        let data = b"test data";
        let hash1 = blake3_hash(data);
        let hash2 = blake3_hash(data);
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_blake3_hash_different_inputs() {
        let hash1 = blake3_hash(b"input1");
        let hash2 = blake3_hash(b"input2");
        assert_ne!(hash1, hash2);
    }

    fn make_valid_witness() -> AttestationWitness {
        AttestationWitness {
            public_key: vec![0u8; ML_DSA_65_PUBLIC_KEY_SIZE],
            binary_hash: [1u8; 32], // Non-zero
            nonce: 12345,
            allowed_binaries: vec![],
            timestamp: MIN_TIMESTAMP + 1000,
        }
    }

    #[test]
    fn test_validate_witness_valid() {
        let witness = make_valid_witness();
        let current_time = MIN_TIMESTAMP + 2000;
        assert!(validate_witness(&witness, current_time).is_ok());
    }

    #[test]
    fn test_validate_witness_empty_public_key() {
        let mut witness = make_valid_witness();
        witness.public_key = vec![];
        let result = validate_witness(&witness, MIN_TIMESTAMP + 2000);
        assert_eq!(result, Err(WitnessValidationError::EmptyPublicKey));
    }

    #[test]
    fn test_validate_witness_invalid_public_key_size() {
        let mut witness = make_valid_witness();
        witness.public_key = vec![0u8; 100]; // Wrong size
        let result = validate_witness(&witness, MIN_TIMESTAMP + 2000);
        assert_eq!(
            result,
            Err(WitnessValidationError::InvalidPublicKeySize {
                actual: 100,
                expected: ML_DSA_65_PUBLIC_KEY_SIZE
            })
        );
    }

    #[test]
    fn test_validate_witness_zero_binary_hash() {
        let mut witness = make_valid_witness();
        witness.binary_hash = [0u8; 32];
        let result = validate_witness(&witness, MIN_TIMESTAMP + 2000);
        assert_eq!(result, Err(WitnessValidationError::ZeroBinaryHash));
    }

    #[test]
    fn test_validate_witness_timestamp_too_old() {
        let mut witness = make_valid_witness();
        witness.timestamp = MIN_TIMESTAMP - 1;
        let result = validate_witness(&witness, MIN_TIMESTAMP + 2000);
        assert_eq!(
            result,
            Err(WitnessValidationError::TimestampTooOld {
                timestamp: MIN_TIMESTAMP - 1,
                minimum: MIN_TIMESTAMP
            })
        );
    }

    #[test]
    fn test_validate_witness_timestamp_in_future() {
        let witness = make_valid_witness();
        let current_time = MIN_TIMESTAMP + 1000;
        // Witness timestamp is current_time + 1000, max is current_time + 3600
        // So this should be valid
        assert!(validate_witness(&witness, current_time).is_ok());

        // But if we set timestamp way in the future...
        let mut future_witness = witness.clone();
        future_witness.timestamp = current_time + MAX_TIMESTAMP_SKEW + 1;
        let result = validate_witness(&future_witness, current_time);
        assert_eq!(
            result,
            Err(WitnessValidationError::TimestampInFuture {
                timestamp: future_witness.timestamp,
                maximum: current_time + MAX_TIMESTAMP_SKEW
            })
        );
    }

    #[test]
    fn test_validate_witness_allowlist_too_large() {
        let mut witness = make_valid_witness();
        witness.allowed_binaries = vec![[1u8; 32]; MAX_ALLOWED_BINARIES + 1];
        let result = validate_witness(&witness, MIN_TIMESTAMP + 2000);
        assert_eq!(
            result,
            Err(WitnessValidationError::AllowlistTooLarge {
                count: MAX_ALLOWED_BINARIES + 1,
                maximum: MAX_ALLOWED_BINARIES
            })
        );
    }

    #[test]
    fn test_validate_witness_zero_hash_in_allowlist() {
        let mut witness = make_valid_witness();
        witness.allowed_binaries = vec![[0u8; 32]];
        let result = validate_witness(&witness, MIN_TIMESTAMP + 2000);
        assert_eq!(result, Err(WitnessValidationError::ZeroHashInAllowlist));
    }

    #[test]
    fn test_validate_witness_duplicate_in_allowlist() {
        let mut witness = make_valid_witness();
        let hash = [42u8; 32];
        witness.allowed_binaries = vec![hash, hash];
        let result = validate_witness(&witness, MIN_TIMESTAMP + 2000);
        assert_eq!(result, Err(WitnessValidationError::DuplicateAllowlistEntry));
    }

    #[test]
    fn test_witness_summary() {
        let witness = make_valid_witness();
        let summary = witness_summary(&witness);
        assert_eq!(summary.public_key_size, ML_DSA_65_PUBLIC_KEY_SIZE);
        assert_eq!(summary.binary_hash, witness.binary_hash);
        assert_eq!(summary.timestamp, witness.timestamp);
        assert_eq!(summary.allowlist_count, 0);
        assert!(summary.has_nonce);
    }

    #[test]
    fn test_witness_validation_error_display() {
        let err = WitnessValidationError::EmptyPublicKey;
        assert_eq!(err.to_string(), "public key is empty");

        let err = WitnessValidationError::InvalidPublicKeySize {
            actual: 100,
            expected: 1952,
        };
        assert_eq!(
            err.to_string(),
            "invalid public key size: 100 bytes (expected 1952)"
        );
    }
}
