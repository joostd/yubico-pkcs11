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

use crate::backend::{PivBackend, piv_error_to_rv};
use pkcs11_common::backend::Slot;
use pkcs11_common::digest::DigestOp;
use pkcs11_common::mechanism::{MechanismKind, classify_mechanism, resolve_pss_params};
use pkcs11_common::session::LoginState;
use pkcs11_common::sign::{digest_info_prefix, emsa_pss_encode, pkcs1_v15_pad, zero_pad};
use pkcs11_sys::*;
use yubikit::keys::{EcCurve, MlDsaParameterSet, PublicKey, RsaKeySize};
use yubikit::piv::{KeyType, Slot as PivSlot};

pub struct SignState {
    slot: PivSlot,
    key_type: KeyType,
    algo: SignAlgorithm,
    acc: Accumulator,
}

/// Collects the data from `C_SignUpdate` before it reaches the device
pub(crate) enum Accumulator {
    Hash(DigestOp),
    Raw(Vec<u8>),
}

impl Accumulator {
    pub(crate) fn update(&mut self, data: &[u8]) {
        match self {
            Accumulator::Hash(h) => h.update(data),
            Accumulator::Raw(buf) => buf.extend_from_slice(data),
        }
    }

    pub(crate) fn finalize(self) -> Vec<u8> {
        match self {
            Accumulator::Hash(h) => h.finalize(),
            Accumulator::Raw(buf) => buf,
        }
    }
}

enum SignAlgorithm {
    /// `CKM_RSA_X_509`. No PKCS#1 structure, just left-zero-pad
    /// the bytes out to `modulus_len`.
    RsaX509 { modulus_len: usize },
    /// `CKM_RSA_PKCS`, raw, `hash_mechanism: None`
    RsaPkcs1 {
        hash_mechanism: Option<CK_MECHANISM_TYPE>,
        modulus_len: usize,
    },
    /// `CKM_ECDSA` (raw) and `CKM_ECDSA_SHAx` (hashed)
    Ecdsa { curve_byte_len: usize },
    /// `CKM_RSA_PKCS_PSS` (raw) or one of the `CKM_SHAx_RSA_PKCS_PSS`
    /// combined mechanisms
    RsaPss {
        hash_mechanism: CK_MECHANISM_TYPE,
        mgf_hash_mechanism: CK_MECHANISM_TYPE,
        salt_len: usize,
        modulus_len: usize,
        modulus_bits: usize,
    },
    /// `CKM_EDDSA`
    Eddsa,
    /// `CKM_ML_DSA`
    MlDsa { context: Vec<u8> },
    /// `CKM_YUBICO_ML_DSA_EXTERNAL_MU`
    MlDsaExternalMu,
}

/// Validates `CK_SIGN_ADDITIONAL_CONTEXT` for `CKM_ML_DSA`
pub(crate) fn resolve_ml_dsa_context(parameter: &[u8]) -> Result<Vec<u8>, CK_RV> {
    if parameter.is_empty() {
        return Ok(Vec::new());
    }
    if parameter.len() != std::mem::size_of::<CK_SIGN_ADDITIONAL_CONTEXT>() {
        return Err(CKR_MECHANISM_PARAM_INVALID.into());
    }
    // SAFETY: length checked above; read_unaligned since PKCS#11 callers are not
    // guaranteed to enter an aligned pointer).
    let ctx: CK_SIGN_ADDITIONAL_CONTEXT = unsafe {
        std::ptr::read_unaligned(parameter.as_ptr() as *const CK_SIGN_ADDITIONAL_CONTEXT)
    };
    if ctx.hedgeVariant == CKH_DETERMINISTIC_REQUIRED as CK_HEDGE_TYPE {
        return Err(CKR_MECHANISM_PARAM_INVALID.into());
    }
    if ctx.ulContextLen == 0 {
        return Ok(Vec::new());
    }
    if ctx.ulContextLen > 255 || ctx.pContext.is_null() {
        return Err(CKR_MECHANISM_PARAM_INVALID.into());
    }
    // SAFETY: pContext/ulContextLen are a second caller-supplied
    // pointer+length pair, out-of-line from `parameter` itself — same trust
    // boundary as `parameter` (valid for the duration of this call), same
    // pattern as `derive.rs`'s `resolve_ecdh1_derive_params`.
    Ok(unsafe {
        std::slice::from_raw_parts(ctx.pContext as *const u8, ctx.ulContextLen as usize).to_vec()
    })
}

fn ml_dsa_signature_len(parameter_set: MlDsaParameterSet) -> Result<CK_ULONG, CK_RV> {
    Ok(match parameter_set {
        MlDsaParameterSet::MlDsa44 => 2420,
        MlDsaParameterSet::MlDsa65 => 3309,
        MlDsaParameterSet::MlDsa87 => 4627,
        _ => return Err(CKR_KEY_TYPE_INCONSISTENT.into()),
    })
}

fn rsa_key_type(size: RsaKeySize) -> Result<KeyType, CK_RV> {
    Ok(match size {
        RsaKeySize::Rsa1024 => KeyType::Rsa1024,
        RsaKeySize::Rsa2048 => KeyType::Rsa2048,
        RsaKeySize::Rsa3072 => KeyType::Rsa3072,
        RsaKeySize::Rsa4096 => KeyType::Rsa4096,
        _ => return Err(CKR_KEY_TYPE_INCONSISTENT.into()),
    })
}

fn ec_key_type(curve: EcCurve) -> Result<(KeyType, usize), CK_RV> {
    Ok(match curve {
        EcCurve::P256 => (KeyType::EccP256, 32),
        EcCurve::P384 => (KeyType::EccP384, 48),
        _ => return Err(CKR_KEY_TYPE_INCONSISTENT.into()),
    })
}

pub fn sign_init(
    slot: &mut Slot<PivBackend>,
    h_session: CK_SESSION_HANDLE,
    mechanism: CK_MECHANISM_TYPE,
    parameter: &[u8],
    key_handle: CK_OBJECT_HANDLE,
) -> Result<CK_ULONG, CK_RV> {
    let Some((piv_slot, public_key)) =
        crate::objects::find_private_key(&slot.data.objects, key_handle)
    else {
        return Err(CKR_KEY_HANDLE_INVALID.into());
    };

    if slot.login_state == LoginState::Public {
        return Err(CKR_USER_NOT_LOGGED_IN.into());
    }

    // CKM_YUBICO_ML_DSA_EXTERNAL_MU is a Yubico vendor mechanism
    if mechanism as u32 == crate::mechanisms::CKM_YUBICO_ML_DSA_EXTERNAL_MU {
        let PublicKey::MlDsa(k) = public_key else {
            return Err(CKR_KEY_TYPE_INCONSISTENT.into());
        };
        // No standard or vendor-defined parameter exists for this
        // mechanism. The context (if any) is already folded into `mu`
        // by the caller
        if !parameter.is_empty() {
            return Err(CKR_MECHANISM_PARAM_INVALID.into());
        }
        let key_type = KeyType::try_from(&public_key.algorithm())
            .map_err(|_| CK_RV::from(CKR_KEY_TYPE_INCONSISTENT))?;
        let out_len = ml_dsa_signature_len(k.parameter_set)?;

        let session = slot
            .sessions
            .get_mut(&h_session)
            .ok_or(CK_RV::from(CKR_SESSION_HANDLE_INVALID))?;
        session.data.sign = Some(SignState {
            slot: piv_slot,
            key_type,
            algo: SignAlgorithm::MlDsaExternalMu,
            acc: Accumulator::Raw(Vec::new()),
        });
        return Ok(out_len);
    }

    let Some(mech_kind) = classify_mechanism(mechanism) else {
        return Err(CKR_MECHANISM_INVALID.into());
    };

    let (key_type, algo, out_len) = match (&mech_kind, public_key) {
        (MechanismKind::RsaX509, PublicKey::Rsa(k)) => {
            let modulus_len = k.key_size.bit_len() / 8;
            (
                rsa_key_type(k.key_size)?,
                SignAlgorithm::RsaX509 { modulus_len },
                modulus_len as CK_ULONG,
            )
        }
        (MechanismKind::RsaPkcs1Raw, PublicKey::Rsa(k)) => {
            let modulus_len = k.key_size.bit_len() / 8;
            (
                rsa_key_type(k.key_size)?,
                SignAlgorithm::RsaPkcs1 {
                    hash_mechanism: None,
                    modulus_len,
                },
                modulus_len as CK_ULONG,
            )
        }
        (MechanismKind::RsaPkcs1Hashed(hash_mechanism), PublicKey::Rsa(k)) => {
            let modulus_len = k.key_size.bit_len() / 8;
            (
                rsa_key_type(k.key_size)?,
                SignAlgorithm::RsaPkcs1 {
                    hash_mechanism: Some(*hash_mechanism),
                    modulus_len,
                },
                modulus_len as CK_ULONG,
            )
        }
        (MechanismKind::RsaPssRaw, PublicKey::Rsa(k)) => {
            let (hash_mechanism, mgf_hash_mechanism, salt_len) =
                resolve_pss_params(parameter, None)?;
            let modulus_len = k.key_size.bit_len() / 8;
            (
                rsa_key_type(k.key_size)?,
                SignAlgorithm::RsaPss {
                    hash_mechanism,
                    mgf_hash_mechanism,
                    salt_len,
                    modulus_len,
                    modulus_bits: k.key_size.bit_len(),
                },
                modulus_len as CK_ULONG,
            )
        }
        (MechanismKind::RsaPssHashed(outer_hash), PublicKey::Rsa(k)) => {
            let (hash_mechanism, mgf_hash_mechanism, salt_len) =
                resolve_pss_params(parameter, Some(*outer_hash))?;
            let modulus_len = k.key_size.bit_len() / 8;
            (
                rsa_key_type(k.key_size)?,
                SignAlgorithm::RsaPss {
                    hash_mechanism,
                    mgf_hash_mechanism,
                    salt_len,
                    modulus_len,
                    modulus_bits: k.key_size.bit_len(),
                },
                modulus_len as CK_ULONG,
            )
        }
        (MechanismKind::EcdsaRaw | MechanismKind::EcdsaHashed(_), PublicKey::Ec(k)) => {
            let (key_type, curve_byte_len) = ec_key_type(k.curve.clone())?;
            (
                key_type,
                SignAlgorithm::Ecdsa { curve_byte_len },
                (curve_byte_len * 2) as CK_ULONG,
            )
        }
        (MechanismKind::Eddsa, PublicKey::Ed25519(_)) => {
            (KeyType::Ed25519, SignAlgorithm::Eddsa, 64)
        }
        (MechanismKind::MlDsa, PublicKey::MlDsa(k)) => {
            let context = resolve_ml_dsa_context(parameter)?;
            let key_type = KeyType::try_from(&public_key.algorithm())
                .map_err(|_| CK_RV::from(CKR_KEY_TYPE_INCONSISTENT))?;
            (key_type, SignAlgorithm::MlDsa { context }, ml_dsa_signature_len(k.parameter_set)?)
        }
        _ => return Err(CKR_KEY_TYPE_INCONSISTENT.into()),
    };

    let acc = match mech_kind {
        MechanismKind::RsaPkcs1Hashed(h)
        | MechanismKind::EcdsaHashed(h)
        | MechanismKind::RsaPssHashed(h) => Accumulator::Hash(
            DigestOp::new(h).map_err(|_| CK_RV::from(CKR_MECHANISM_INVALID))?,
        ),
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
    session.data.sign = Some(SignState {
        slot: piv_slot,
        key_type,
        algo,
        acc,
    });

    Ok(out_len)
}

pub fn sign_update(
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
        .sign
        .as_mut()
        .ok_or(CK_RV::from(CKR_OPERATION_NOT_INITIALIZED))?;
    state.acc.update(data);
    Ok(())
}

pub fn sign_final(slot: &mut Slot<PivBackend>, h_session: CK_SESSION_HANDLE) -> Result<Vec<u8>, CK_RV> {
    let session = slot
        .sessions
        .get_mut(&h_session)
        .ok_or(CK_RV::from(CKR_SESSION_HANDLE_INVALID))?;
    let state = session
        .data
        .sign
        .take()
        .ok_or(CK_RV::from(CKR_OPERATION_NOT_INITIALIZED))?;

    let message = state.acc.finalize();
    let piv = slot
        .data
        .piv_session
        .as_mut()
        .ok_or(CK_RV::from(CKR_TOKEN_NOT_PRESENT))?;

    match state.algo {
        SignAlgorithm::RsaX509 { modulus_len } => {
            // No PKCS#1 structure, just left-zero-padding.
            let padded = zero_pad(&message, modulus_len)?;
            piv.sign(state.slot, state.key_type, &padded)
                .map_err(piv_error_to_rv)
        }
        SignAlgorithm::RsaPkcs1 {
            hash_mechanism,
            modulus_len,
        } => {
            let to_pad = match hash_mechanism {
                Some(h) => {
                    let prefix =
                        digest_info_prefix(h).ok_or(CK_RV::from(CKR_MECHANISM_INVALID))?;
                    let mut v = Vec::with_capacity(prefix.len() + message.len());
                    v.extend_from_slice(prefix);
                    v.extend_from_slice(&message);
                    v
                }
                // Raw CKM_RSA_PKCS
                None => message,
            };
            let padded = pkcs1_v15_pad(&to_pad, modulus_len)?;

            piv.sign(state.slot, state.key_type, &padded)
                .map_err(piv_error_to_rv)
        }
        SignAlgorithm::RsaPss {
            hash_mechanism,
            mgf_hash_mechanism,
            salt_len,
            modulus_len,
            modulus_bits,
        } => {
            let mut salt = vec![0u8; salt_len];
            getrandom::fill(&mut salt).map_err(|_| CK_RV::from(CKR_FUNCTION_FAILED))?;
            let em = emsa_pss_encode(
                &message,
                &salt,
                modulus_bits - 1,
                hash_mechanism,
                mgf_hash_mechanism,
            )?;

            piv.sign(state.slot, state.key_type, &em)
                .map_err(piv_error_to_rv)
        }
        SignAlgorithm::Ecdsa { curve_byte_len } => {
            // The device signs the accumulated bytes directly for ECDSA,
            // no DigestInfo wrapping
            let truncated = if message.len() > curve_byte_len {
                &message[..curve_byte_len]
            } else {
                &message[..]
            };
            let der_sig = piv
                .sign(state.slot, state.key_type, truncated)
                .map_err(piv_error_to_rv)?;
            strip_ecdsa_der(&der_sig, curve_byte_len)
        }
        SignAlgorithm::Eddsa => piv
            .sign(state.slot, state.key_type, &message)
            .map_err(piv_error_to_rv),
        SignAlgorithm::MlDsa { context } => piv
            .sign_with_context(state.slot, state.key_type, &message, &context)
            .map_err(piv_error_to_rv),
        SignAlgorithm::MlDsaExternalMu => {
            // FIPS 204's external-mu message representative is always
            // exactly 64 bytes, regardless of ML-DSA parameter set
            if message.len() != 64 {
                return Err(CKR_DATA_LEN_RANGE.into());
            }
            piv.sign_external_mu(state.slot, state.key_type, &message)
                .map_err(piv_error_to_rv)
        }
    }
}

/// Converts the device's DER-encoded ECDSA signature into PKCS#11's
/// fixed-width `r || s` format
fn strip_ecdsa_der(der_sig: &[u8], curve_byte_len: usize) -> Result<Vec<u8>, CK_RV> {
    match curve_byte_len {
        32 => Ok(p256::ecdsa::Signature::from_der(der_sig)
            .map_err(|_| CK_RV::from(CKR_DATA_INVALID))?
            .to_bytes()
            .to_vec()),
        48 => Ok(p384::ecdsa::Signature::from_der(der_sig)
            .map_err(|_| CK_RV::from(CKR_DATA_INVALID))?
            .to_bytes()
            .to_vec()),
        // ec_key_type only ever produces 32 (P-256) or 48 (P-384).
        _ => Err(CKR_KEY_TYPE_INCONSISTENT.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // A hand-built `ECDSA-Sig-Value ::= SEQUENCE { r, s }` where `s` has its
    // high bit set (DER requires an extra leading 0x00 byte for the INTEGER
    // to stay non-negative) and `r` is shorter than the curve's 32-byte
    // coordinate width (requires left-zero-padding on the way out) — the two
    // edge cases a byte-for-byte DER parser is most likely to get wrong.
    const DER_SIG: &[u8] = &[
        0x30, 0x16, 0x02, 0x09, 0x00, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0x02, 0x09,
        0x00, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    ];

    #[test]
    fn strip_ecdsa_der_pads_and_concatenates_r_and_s() {
        let raw = strip_ecdsa_der(DER_SIG, 32).unwrap();
        assert_eq!(raw.len(), 64);
        assert_eq!(
            hex(&raw[..32]),
            "000000000000000000000000000000000000000000000000abcdef0123456789"
        );
        assert_eq!(
            hex(&raw[32..]),
            "000000000000000000000000000000000000000000000000ff00000000000001"
        );
    }

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{:02x}", x)).collect()
    }
}
