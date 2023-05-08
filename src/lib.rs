#![forbid(unsafe_code)]
#![forbid(missing_docs)]

//! Verify BLS signatures
//!
//! This verifies BLS signatures in a manner which is compatible with
//! the Internet Computer.

use bls12_381::hash_to_curve::{ExpandMsgXmd, HashToCurve};
use bls12_381::{multi_miller_loop, G1Affine, G1Projective, G2Affine, G2Prepared, Scalar};
use pairing::group::{Curve, Group};
use std::ops::Neg;

lazy_static::lazy_static! {
    static ref G2PREPARED_NEG_G : G2Prepared = G2Affine::generator().neg().into();
}

const BLS_SIGNATURE_DOMAIN_SEP: [u8; 43] = *b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_";

fn hash_to_g1(msg: &[u8]) -> G1Affine {
    <G1Projective as HashToCurve<ExpandMsgXmd<sha2::Sha256>>>::hash_to_curve(
        msg,
        &BLS_SIGNATURE_DOMAIN_SEP,
    )
    .to_affine()
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

    let msg = hash_to_g1(msg);

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

/// Sign a message using BLS
///
/// The message can be of arbitrary length
///
/// The private key must be exactly 32 bytes (the big-endian encoding
/// of the secret scalar)
pub fn sign_message_with_bls(msg: &[u8], key: &[u8; 32]) -> Result<[u8; 48], ()> {
    let mut le_bytes = key.clone();
    le_bytes.reverse();
    let key: Option<Scalar> = Scalar::from_bytes(&le_bytes).into();

    if let Some(key) = key {
        let msg = hash_to_g1(msg);
        let sig = msg * key;
        Ok(sig.to_affine().to_compressed())
    } else {
        Err(())
    }
}
