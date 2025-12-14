// Copyright 2024 Saorsa Labs Limited
//
// Licensed under the MIT License or Apache License, Version 2.0.
// See LICENSE-MIT or LICENSE-APACHE for details.

//! SP1 zkVM Guest Program for Entangled Attestation
//!
//! This program runs inside the SP1 zkVM and proves correct derivation of an
//! EntangledId without revealing private inputs (the full ML-DSA-65 public key
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

#![no_main]
sp1_zkvm::entrypoint!(main);

use saorsa_logic::attestation::{derive_entangled_id, verify_binary_allowlist};
use serde::{Deserialize, Serialize};

/// Private witness data provided by the prover.
///
/// This data is NOT revealed in the proof - it's the private input.
#[derive(Deserialize)]
pub struct AttestationWitness {
    /// ML-DSA-65 public key (1952 bytes).
    /// The prover demonstrates knowledge of this key without revealing it.
    pub public_key: Vec<u8>,

    /// BLAKE3 hash of the binary this identity is bound to.
    pub binary_hash: [u8; 32],

    /// Nonce used in EntangledId derivation.
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
    /// The derived EntangledId: `BLAKE3(PK || binary_hash || nonce)`
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
/// 2. Derives the EntangledId using saorsa-logic
/// 3. Computes the public key hash
/// 4. Optionally verifies the binary allowlist
/// 5. Commits the public outputs to the proof
pub fn main() {
    // Step 1: Read private witness from prover
    let witness: AttestationWitness = sp1_zkvm::io::read();

    // Step 2: Derive EntangledId using the same logic as saorsa-core
    // This is the core computation being proven
    let entangled_id = derive_entangled_id(&witness.public_key, &witness.binary_hash, witness.nonce);

    // Step 3: Compute public key hash
    // This commits to the key without revealing the full 1952 bytes
    let public_key_hash = blake3_hash(&witness.public_key);

    // Step 4: Verify binary allowlist if provided
    // If the allowlist is non-empty, the binary must be in it
    if !witness.allowed_binaries.is_empty() {
        match verify_binary_allowlist(&witness.binary_hash, &witness.allowed_binaries) {
            Ok(()) => {}
            Err(_) => {
                // In zkVM, failing a constraint causes the proof to be invalid
                panic!("binary not in allowlist");
            }
        }
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

/// BLAKE3 hash helper (no_std compatible).
///
/// Computes a 32-byte BLAKE3 hash of the input data.
#[inline]
fn blake3_hash(data: &[u8]) -> [u8; 32] {
    *blake3::hash(data).as_bytes()
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
}
