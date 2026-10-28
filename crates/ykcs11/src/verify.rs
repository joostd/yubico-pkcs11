/*
 * Copyright 2026 Yubico AB
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

use crate::backend::PivBackend;
use crate::sign::{Accumulator, resolve_ml_dsa_context};
use pkcs11_common::backend::Slot;
use pkcs11_common::digest::DigestOp;
use pkcs11_common::mechanism::{MechanismKind, classify_mechanism, resolve_pss_params};
use pkcs11_common::verify::{verify_ecdsa, verify_eddsa, verify_rsa_pkcs1v15, verify_rsa_pss, verify_rsa_x509};
use pkcs11_sys::*;
use yubikit::keys::{EcCurve, MlDsaParameterSet, PublicKey};

pub struct VerifyState {
    algo: VerifyAlgorithm,
    acc: Accumulator,
}

enum VerifyAlgorithm {
    RsaX509 {
        n: Vec<u8>,
        e: Vec<u8>,
        modulus_len: usize,
    },
    RsaPkcs1 {
        n: Vec<u8>,
        e: Vec<u8>,
        modulus_len: usize,
        hash_mechanism: Option<CK_MECHANISM_TYPE>,
    },
    RsaPss {
        n: Vec<u8>,
        e: Vec<u8>,
        modulus_len: usize,
        modulus_bits: usize,
        hash_mechanism: CK_MECHANISM_TYPE,
        mgf_hash_mechanism: CK_MECHANISM_TYPE,
        salt_len: usize,
    },
    Ecdsa {
        curve_byte_len: usize,
        point: Vec<u8>,
    },
    Eddsa {
        key: Vec<u8>,
    },
    MlDsa {
        key: Vec<u8>,
        parameter_set: MlDsaParameterSet,
        context: Vec<u8>,
    },
}

fn curve_byte_len(curve: EcCurve) -> Result<usize, CK_RV> {
    Ok(match curve {
        EcCurve::P256 => 32,
        EcCurve::P384 => 48,
        _ => return Err(CKR_KEY_TYPE_INCONSISTENT.into()),
    })
}

pub fn verify_init(
    slot: &mut Slot<PivBackend>,
    h_session: CK_SESSION_HANDLE,
    mechanism: CK_MECHANISM_TYPE,
    parameter: &[u8],
    key_handle: CK_OBJECT_HANDLE,
) -> Result<(), CK_RV> {
    let Some((_, public_key)) = crate::objects::find_public_key(&slot.data.objects, key_handle) else {
        return Err(CKR_KEY_HANDLE_INVALID.into());
    };

    let Some(mech_kind) = classify_mechanism(mechanism) else {
        return Err(CKR_MECHANISM_INVALID.into());
    };

    let algo = match (&mech_kind, public_key) {
        (MechanismKind::RsaX509, PublicKey::Rsa(k)) => VerifyAlgorithm::RsaX509 {
            n: k.n.clone(),
            e: k.e.clone(),
            modulus_len: k.key_size.bit_len() / 8,
        },
        (MechanismKind::RsaPkcs1Raw, PublicKey::Rsa(k)) => VerifyAlgorithm::RsaPkcs1 {
            n: k.n.clone(),
            e: k.e.clone(),
            modulus_len: k.key_size.bit_len() / 8,
            hash_mechanism: None,
        },
        (MechanismKind::RsaPkcs1Hashed(h), PublicKey::Rsa(k)) => VerifyAlgorithm::RsaPkcs1 {
            n: k.n.clone(),
            e: k.e.clone(),
            modulus_len: k.key_size.bit_len() / 8,
            hash_mechanism: Some(*h),
        },
        (MechanismKind::RsaPssRaw, PublicKey::Rsa(k)) => {
            let (hash_mechanism, mgf_hash_mechanism, salt_len) = resolve_pss_params(parameter, None)?;
            VerifyAlgorithm::RsaPss {
                n: k.n.clone(),
                e: k.e.clone(),
                modulus_len: k.key_size.bit_len() / 8,
                modulus_bits: k.key_size.bit_len(),
                hash_mechanism,
                mgf_hash_mechanism,
                salt_len,
            }
        }
        (MechanismKind::RsaPssHashed(outer_hash), PublicKey::Rsa(k)) => {
            let (hash_mechanism, mgf_hash_mechanism, salt_len) =
                resolve_pss_params(parameter, Some(*outer_hash))?;
            VerifyAlgorithm::RsaPss {
                n: k.n.clone(),
                e: k.e.clone(),
                modulus_len: k.key_size.bit_len() / 8,
                modulus_bits: k.key_size.bit_len(),
                hash_mechanism,
                mgf_hash_mechanism,
                salt_len,
            }
        }
        (MechanismKind::EcdsaRaw | MechanismKind::EcdsaHashed(_), PublicKey::Ec(k)) => {
            VerifyAlgorithm::Ecdsa {
                curve_byte_len: curve_byte_len(k.curve.clone())?,
                point: k.point.clone(),
            }
        }
        (MechanismKind::Eddsa, PublicKey::Ed25519(k)) => VerifyAlgorithm::Eddsa { key: k.key.clone() },
        (MechanismKind::MlDsa, PublicKey::MlDsa(k)) => {
            let context = resolve_ml_dsa_context(parameter)?;
            VerifyAlgorithm::MlDsa {
                key: k.key.clone(),
                parameter_set: k.parameter_set,
                context,
            }
        }
        _ => return Err(CKR_KEY_TYPE_INCONSISTENT.into()),
    };

    let acc = match mech_kind {
        MechanismKind::RsaPkcs1Hashed(h)
        | MechanismKind::EcdsaHashed(h)
        | MechanismKind::RsaPssHashed(h) => {
            Accumulator::Hash(DigestOp::new(h).map_err(|_| CK_RV::from(CKR_MECHANISM_INVALID))?)
        }
        MechanismKind::RsaX509
        | MechanismKind::RsaPkcs1Raw
        | MechanismKind::RsaPssRaw
        | MechanismKind::EcdsaRaw
        | MechanismKind::Eddsa
        | MechanismKind::MlDsa => Accumulator::Raw(Vec::new()),
    };

    let session = slot
        .sessions
        .get_mut(&h_session)
        .ok_or(CK_RV::from(CKR_SESSION_HANDLE_INVALID))?;
    session.data.verify = Some(VerifyState { algo, acc });

    Ok(())
}

pub fn verify_update(
    slot: &mut Slot<PivBackend>,
    h_session: CK_SESSION_HANDLE,
    data: &[u8],
) -> Result<(), CK_RV> {
    let session = slot
        .sessions
        .get_mut(&h_session)
        .ok_or(CK_RV::from(CKR_SESSION_HANDLE_INVALID))?;
    let state = session
        .data
        .verify
        .as_mut()
        .ok_or(CK_RV::from(CKR_OPERATION_NOT_INITIALIZED))?;
    state.acc.update(data);
    Ok(())
}

pub fn verify_final(
    slot: &mut Slot<PivBackend>,
    h_session: CK_SESSION_HANDLE,
    signature: &[u8],
) -> Result<(), CK_RV> {
    let session = slot
        .sessions
        .get_mut(&h_session)
        .ok_or(CK_RV::from(CKR_SESSION_HANDLE_INVALID))?;
    let state = session
        .data
        .verify
        .take()
        .ok_or(CK_RV::from(CKR_OPERATION_NOT_INITIALIZED))?;

    let message = state.acc.finalize();

    match state.algo {
        VerifyAlgorithm::RsaX509 { n, e, modulus_len } => {
            verify_rsa_x509(&n, &e, modulus_len, &message, signature)
        }
        VerifyAlgorithm::RsaPkcs1 {
            n,
            e,
            modulus_len,
            hash_mechanism,
        } => verify_rsa_pkcs1v15(&n, &e, modulus_len, hash_mechanism, &message, signature),
        VerifyAlgorithm::RsaPss {
            n,
            e,
            modulus_len,
            modulus_bits,
            hash_mechanism,
            mgf_hash_mechanism,
            salt_len,
        } => verify_rsa_pss(
            &n,
            &e,
            modulus_len,
            modulus_bits,
            hash_mechanism,
            mgf_hash_mechanism,
            salt_len,
            &message,
            signature,
        ),
        VerifyAlgorithm::Ecdsa { curve_byte_len, point } => {
            verify_ecdsa(curve_byte_len, &point, &message, signature)
        }
        VerifyAlgorithm::Eddsa { key } => verify_eddsa(&key, &message, signature),
        VerifyAlgorithm::MlDsa { key, parameter_set, context } => {
            verify_ml_dsa(parameter_set, &key, &context, &message, signature)
        }
    }
}

fn verify_ml_dsa(
    parameter_set: MlDsaParameterSet,
    key: &[u8],
    context: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), CK_RV> {
    // `common::KeyInit` must be in scope for `VerifyingKey::new` to resolve
    // (confirmed against yubikit's own proven usage in
    // `test_piv_mldsa44_verify`, which imports the identical set).
    use ml_dsa::common::KeyInit;
    use ml_dsa::{MlDsa44, MlDsa65, MlDsa87, Signature, VerifyingKey};

    match parameter_set {
        MlDsaParameterSet::MlDsa44 => {
            let key: &[u8; 1312] = key.try_into().map_err(|_| CK_RV::from(CKR_KEY_HANDLE_INVALID))?;
            let vk = VerifyingKey::<MlDsa44>::new(key.into());
            let sig = Signature::<MlDsa44>::try_from(signature)
                .map_err(|_| CK_RV::from(CKR_SIGNATURE_LEN_RANGE))?;
            if vk.verify_with_context(message, context, &sig) {
                Ok(())
            } else {
                Err(CKR_SIGNATURE_INVALID.into())
            }
        }
        MlDsaParameterSet::MlDsa65 => {
            let key: &[u8; 1952] = key.try_into().map_err(|_| CK_RV::from(CKR_KEY_HANDLE_INVALID))?;
            let vk = VerifyingKey::<MlDsa65>::new(key.into());
            let sig = Signature::<MlDsa65>::try_from(signature)
                .map_err(|_| CK_RV::from(CKR_SIGNATURE_LEN_RANGE))?;
            if vk.verify_with_context(message, context, &sig) {
                Ok(())
            } else {
                Err(CKR_SIGNATURE_INVALID.into())
            }
        }
        MlDsaParameterSet::MlDsa87 => {
            let key: &[u8; 2592] = key.try_into().map_err(|_| CK_RV::from(CKR_KEY_HANDLE_INVALID))?;
            let vk = VerifyingKey::<MlDsa87>::new(key.into());
            let sig = Signature::<MlDsa87>::try_from(signature)
                .map_err(|_| CK_RV::from(CKR_SIGNATURE_LEN_RANGE))?;
            if vk.verify_with_context(message, context, &sig) {
                Ok(())
            } else {
                Err(CKR_SIGNATURE_INVALID.into())
            }
        }
        _ => Err(CKR_KEY_TYPE_INCONSISTENT.into()),
    }
}
