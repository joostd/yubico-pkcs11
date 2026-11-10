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


use pkcs11_sys::*;

pub enum MechanismKind {
    RsaX509,
    RsaPkcs1Raw,
    RsaPkcs1Hashed(CK_MECHANISM_TYPE),
    RsaPssRaw,
    RsaPssHashed(CK_MECHANISM_TYPE),
    EcdsaRaw,
    EcdsaHashed(CK_MECHANISM_TYPE),
    Eddsa,
    MlDsa,
    /// `CKM_ML_DSA_EXTERNAL_MU` (PKCS#11 3.3): the data is the 64-byte
    /// message representative `mu`, computed by the caller, rather than the
    /// message itself.
    MlDsaExternalMu,
}

pub fn classify_mechanism(mechanism: CK_MECHANISM_TYPE) -> Option<MechanismKind> {
    Some(match mechanism as u32 {
        CKM_RSA_X_509 => MechanismKind::RsaX509,
        CKM_RSA_PKCS => MechanismKind::RsaPkcs1Raw,
        CKM_SHA1_RSA_PKCS => MechanismKind::RsaPkcs1Hashed(CKM_SHA_1 as CK_MECHANISM_TYPE),
        CKM_SHA256_RSA_PKCS => MechanismKind::RsaPkcs1Hashed(CKM_SHA256 as CK_MECHANISM_TYPE),
        CKM_SHA384_RSA_PKCS => MechanismKind::RsaPkcs1Hashed(CKM_SHA384 as CK_MECHANISM_TYPE),
        CKM_SHA512_RSA_PKCS => MechanismKind::RsaPkcs1Hashed(CKM_SHA512 as CK_MECHANISM_TYPE),
        CKM_RSA_PKCS_PSS => MechanismKind::RsaPssRaw,
        CKM_SHA1_RSA_PKCS_PSS => MechanismKind::RsaPssHashed(CKM_SHA_1 as CK_MECHANISM_TYPE),
        CKM_SHA256_RSA_PKCS_PSS => MechanismKind::RsaPssHashed(CKM_SHA256 as CK_MECHANISM_TYPE),
        CKM_SHA384_RSA_PKCS_PSS => MechanismKind::RsaPssHashed(CKM_SHA384 as CK_MECHANISM_TYPE),
        CKM_SHA512_RSA_PKCS_PSS => MechanismKind::RsaPssHashed(CKM_SHA512 as CK_MECHANISM_TYPE),
        CKM_ECDSA => MechanismKind::EcdsaRaw,
        CKM_ECDSA_SHA1 => MechanismKind::EcdsaHashed(CKM_SHA_1 as CK_MECHANISM_TYPE),
        CKM_ECDSA_SHA256 => MechanismKind::EcdsaHashed(CKM_SHA256 as CK_MECHANISM_TYPE),
        CKM_ECDSA_SHA384 => MechanismKind::EcdsaHashed(CKM_SHA384 as CK_MECHANISM_TYPE),
        CKM_ECDSA_SHA512 => MechanismKind::EcdsaHashed(CKM_SHA512 as CK_MECHANISM_TYPE),
        CKM_EDDSA => MechanismKind::Eddsa,
        CKM_ML_DSA => MechanismKind::MlDsa,
        CKM_ML_DSA_EXTERNAL_MU => MechanismKind::MlDsaExternalMu,
        _ => return None,
    })
}

fn is_supported_pss_hash(hash_mechanism: CK_MECHANISM_TYPE) -> bool {
    matches!(
        hash_mechanism as u32,
        CKM_SHA_1 | CKM_SHA256 | CKM_SHA384 | CKM_SHA512
    )
}

fn mgf_hash_mechanism(mgf: CK_RSA_PKCS_MGF_TYPE) -> Option<CK_MECHANISM_TYPE> {
    Some(match mgf as u32 {
        CKG_MGF1_SHA1 => CKM_SHA_1,
        CKG_MGF1_SHA256 => CKM_SHA256,
        CKG_MGF1_SHA384 => CKM_SHA384,
        CKG_MGF1_SHA512 => CKM_SHA512,
        _ => return None,
    } as CK_MECHANISM_TYPE)
}

/// Reads and validates `CK_RSA_PKCS_PSS_PARAMS` out of a mechanism's raw
/// `pParameter` bytes
pub fn resolve_pss_params(
    parameter: &[u8],
    required_hash: Option<CK_MECHANISM_TYPE>,
) -> Result<(CK_MECHANISM_TYPE, CK_MECHANISM_TYPE, usize), CK_RV> {
    if parameter.len() != std::mem::size_of::<CK_RSA_PKCS_PSS_PARAMS>() {
        return Err(CKR_MECHANISM_PARAM_INVALID.into());
    }
    // SAFETY: length checked above. CK_RSA_PKCS_PSS_PARAMS is a
    // `#[repr(C)]` data struct of three integers; PKCS#11 callers
    // aren't guaranteed to return a suitably aligned pointer, hence
    // `read_unaligned` rather than a direct reference/dereference.
    let pss: CK_RSA_PKCS_PSS_PARAMS =
        unsafe { std::ptr::read_unaligned(parameter.as_ptr() as *const CK_RSA_PKCS_PSS_PARAMS) };

    if !is_supported_pss_hash(pss.hashAlg) {
        return Err(CKR_ARGUMENTS_BAD.into());
    }
    let mgf_hash = mgf_hash_mechanism(pss.mgf).ok_or(CK_RV::from(CKR_ARGUMENTS_BAD))?;
    if let Some(required) = required_hash {
        if pss.hashAlg != required {
            return Err(CKR_ARGUMENTS_BAD.into());
        }
    }

    Ok((pss.hashAlg, mgf_hash, pss.sLen as usize))
}

pub enum CryptMechanismKind {
    RsaX509,
    RsaPkcs1,
    RsaOaep,
}

pub fn classify_crypt_mechanism(mechanism: CK_MECHANISM_TYPE) -> Option<CryptMechanismKind> {
    Some(match mechanism as u32 {
        CKM_RSA_X_509 => CryptMechanismKind::RsaX509,
        CKM_RSA_PKCS => CryptMechanismKind::RsaPkcs1,
        CKM_RSA_PKCS_OAEP => CryptMechanismKind::RsaOaep,
        _ => return None,
    })
}

pub fn resolve_oaep_params(parameter: &[u8]) -> Result<(CK_MECHANISM_TYPE, CK_MECHANISM_TYPE, Vec<u8>), CK_RV> {
    if parameter.len() != std::mem::size_of::<CK_RSA_PKCS_OAEP_PARAMS>() {
        return Err(CKR_MECHANISM_PARAM_INVALID.into());
    }
    // SAFETY: length checked above; read_unaligned for the same reason
    // as `resolve_pss_params` (PKCS#11 callers aren't guaranteed to return
    // an aligned pointer).
    let oaep: CK_RSA_PKCS_OAEP_PARAMS =
        unsafe { std::ptr::read_unaligned(parameter.as_ptr() as *const CK_RSA_PKCS_OAEP_PARAMS) };

    if !is_supported_pss_hash(oaep.hashAlg) {
        return Err(CKR_ARGUMENTS_BAD.into());
    }
    let mgf_hash = mgf_hash_mechanism(oaep.mgf).ok_or(CK_RV::from(CKR_ARGUMENTS_BAD))?;

    let label = if oaep.source == 0 || oaep.ulSourceDataLen == 0 {
        // `source == 0` ("empty"/unspecified) and an explicit
        // `CKZ_DATA_SPECIFIED` source with a zero-length label are
        // equivalent here
        Vec::new()
    } else if oaep.source == CKZ_DATA_SPECIFIED as CK_RSA_PKCS_OAEP_SOURCE_TYPE {
        if oaep.pSourceData.is_null() {
            return Err(CKR_MECHANISM_PARAM_INVALID.into());
        }
        // SAFETY: `pSourceData`/`ulSourceDataLen` are a second
        // caller-supplied pointer+length pair
        unsafe {
            std::slice::from_raw_parts(oaep.pSourceData as *const u8, oaep.ulSourceDataLen as usize)
                .to_vec()
        }
    } else {
        return Err(CKR_MECHANISM_PARAM_INVALID.into());
    };

    Ok((oaep.hashAlg, mgf_hash, label))
}
