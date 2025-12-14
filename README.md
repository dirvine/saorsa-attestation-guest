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

## License

Dual-licensed under MIT and Apache-2.0.
