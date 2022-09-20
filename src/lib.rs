#![forbid(unsafe_code)]
#![forbid(missing_docs)]

//! Verify BLS signatures
//!
//! This verifies BLS signatures in a manner which is compatible with
//! the Internet Computer.

use bls12_381::hash_to_curve::{ExpandMsgXmd, HashToCurve};
use bls12_381::{multi_miller_loop, G1Affine, G1Projective, G2Affine, G2Prepared};
use pairing::group::{Curve, Group};
use std::ops::Neg;

lazy_static::lazy_static! {
    static ref G2PREPARED_NEG_G : G2Prepared = G2Affine::generator().neg().into();
}

/// Verify a BLS signature
///
/// The signature must be exactly 48 bytes (compressed G1 element)
/// The key must be exactly 96 bytes (compressed G2 element)
pub fn verify_bls_signature(sig: &[u8], msg: &[u8], key: &[u8]) -> Result<(), ()> {
    if sig.len() != 48 || key.len() != 96 {
        return Err(());
    }

    let sig: Option<G1Affine> =
        G1Affine::from_compressed(sig.try_into().expect("Checked length")).into();
    let key: Option<G2Affine> =
        G2Affine::from_compressed(key.try_into().expect("Checked length")).into();

    let domain_sep = b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_";

    let msg =
        <G1Projective as HashToCurve<ExpandMsgXmd<sha2::Sha256>>>::hash_to_curve(msg, domain_sep)
            .to_affine();

    match (sig, key) {
        (Some(sig), Some(key)) => {
            let g2_gen = &G2PREPARED_NEG_G;
            let pub_key = G2Prepared::from(key);

            let result =
                multi_miller_loop(&[(&sig, &g2_gen), (&msg, &pub_key)]).final_exponentiation();

            if bool::from(result.is_identity()) {
                Ok(())
            } else {
                Err(())
            }
        }
        (_, _) => Err(()),
    }
}
