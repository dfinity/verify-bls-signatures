Verify BLS signatures
=======================

This is a simple Rust crate which can be used to verify BLS signatures.
This follows the [IETF draft for BLS signatures](https://datatracker.ietf.org/doc/draft-irtf-cfrg-bls-signature/),
using the "short signature" variation where signatures are in G1 and
public keys are in G2.
