BLS signature utility crate
=============================

[![crates.io](https://img.shields.io/crates/v/ic-verify-bls-signature.svg)](https://crates.io/crates/ic-verify-bls-signature)
[![docs.rs](https://docs.rs/ic-verify-bls-signature/badge.svg)](https://docs.rs/ic-verify-bls-signature)

This is a simple Rust crate which can be used to create and verify BLS signatures
over the BLS12-381 curve. This follows the
[IETF draft for BLS signatures](https://datatracker.ietf.org/doc/draft-irtf-cfrg-bls-signature/),
using the "short signature" variation, where signatures are in G1 and
public keys are in G2.

For historical reasons, this crate is named `ic-verify-bls-signature`,
but it also supports signature generation.
