# saorsa-attestation-guest

SP1 zkVM guest program for Saorsa Entangled Attestation proofs.

## Overview

This crate contains the guest program that runs inside the SP1 zkVM to generate
zero-knowledge proofs of correct EntangledId derivation. The proof demonstrates
that a node's identity was correctly derived from:

- An ML-DSA-65 public key (post-quantum secure)
- A binary hash (attesting to the running software)
- A nonce (ensuring uniqueness)

## Security Properties

### What the Proof Demonstrates

1. **Correct Derivation**: `EntangledId = BLAKE3(PK || binary_hash || nonce)`
2. **Key Binding**: The prover knows a public key that hashes to `public_key_hash`
3. **Binary Attestation**: Optionally proves `binary_hash ∈ allowed_binaries`

### What the Proof Hides (Zero-Knowledge)

- The full 1952-byte ML-DSA-65 public key (only 32-byte hash revealed)
- The derivation nonce
- Which specific binary from the allowlist (if any)

### Post-Quantum Security

| Component | Algorithm | PQ-Secure? |
|-----------|-----------|------------|
| Identity | ML-DSA-65 | Yes (NIST Level 3) |
| Hashing | BLAKE3 | Yes |
| Proofs | STARKs | Yes (no elliptic curves) |

## Building

```bash
# Install SP1 toolchain
cargo prove install

# Build the guest program
cd program && cargo prove build
```

This generates a RISC-V ELF binary in `target/elf-compilation/`.

## Usage

The guest program is used by `saorsa-core`'s `AttestationProver` to generate
proofs. See the [saorsa-core documentation](../saorsa-core/README.md) for
details on proof generation and verification.

## Operational Tooling

### Witness Validation

Before generating proofs, validate your witness data to catch common errors:

```rust
use saorsa_attestation_guest::{validate_witness, AttestationWitness};

let witness = AttestationWitness {
    public_key: vec![/* ML-DSA-65 public key, 1952 bytes */],
    binary_hash: [/* BLAKE3 hash of binary */],
    nonce: 12345,
    allowed_binaries: vec![],
    timestamp: current_unix_timestamp(),
};

// Validate before expensive proof generation
match validate_witness(&witness, current_unix_timestamp()) {
    Ok(()) => println!("Witness is valid"),
    Err(e) => eprintln!("Validation error: {e}"),
}
```

### Diagnostic Summary

Get a safe summary of witness data for debugging (hides sensitive values):

```rust
use saorsa_attestation_guest::{witness_summary, AttestationWitness};

let summary = witness_summary(&witness);
println!("Public key size: {} bytes", summary.public_key_size);
println!("Binary hash: {:?}", summary.binary_hash);
println!("Timestamp: {}", summary.timestamp);
```

### Validation Checks

The `validate_witness` function checks:

| Check | Error | Description |
|-------|-------|-------------|
| Public key empty | `EmptyPublicKey` | Public key must not be empty |
| Public key size | `InvalidPublicKeySize` | Must be exactly 1952 bytes (ML-DSA-65) |
| Binary hash | `ZeroBinaryHash` | Binary hash must not be all zeros |
| Timestamp (old) | `TimestampTooOld` | Must be after Jan 1, 2024 |
| Timestamp (future) | `TimestampInFuture` | Must not exceed current time + 1 hour |
| Allowlist size | `AllowlistTooLarge` | Max 1000 entries |
| Allowlist zeros | `ZeroHashInAllowlist` | No all-zero hashes allowed |
| Allowlist duplicates | `DuplicateAllowlistEntry` | No duplicate hashes allowed |

## License

Dual-licensed under MIT and Apache-2.0.
