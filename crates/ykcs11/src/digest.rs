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

//! `CKM_ML_DSA_EXTERNAL_MU_GEN` (PKCS#11 3.3): computes the FIPS 204 message
//! representative `mu` that `CKM_ML_DSA_EXTERNAL_MU` consumes.
//!
//! This is a digest mechanism, not a key operation. Everything happens on
//! the host -- the card is never involved -- so unlike raw signing the
//! message is not bounded by the APDU size limits, and a caller can stream a
//! document of any size through `C_DigestUpdate`.
//!
//! The point of offering it at all is that it saves every caller
//! reimplementing the FIPS 204 framing, and getting it wrong silently: a
//! botched `mu` produces a signature that simply fails to verify, with
//! nothing to say why. Taking a key handle also spares callers extracting
//! the raw public key out of a SubjectPublicKeyInfo themselves.
//!
//!     tr = SHAKE256(pk, 64)
//!     M' = 0x00 || len(ctx) || ctx || message
//!     mu = SHAKE256(tr || M', 64)

use crate::backend::PivBackend;
use pkcs11_common::backend::Slot;
use pkcs11_common::digest::DigestOp;
use pkcs11_sys::*;
use shake::digest::{ExtendableOutput, Update, XofReader};
use yubikit::keys::PublicKey;

/// FIPS 204's message representative is always 64 bytes, for every
/// parameter set.
pub(crate) const MU_LEN: usize = 64;

/// Length of `tr`, the hash of the encoded public key. Also always 64.
const TR_LEN: usize = 64;

/// Build `tr = SHAKE256(pk, 64)` from a raw FIPS 204 public key.
fn compute_tr(pk: &[u8]) -> Vec<u8> {
    let mut hasher = shake::Shake256::default();
    hasher.update(pk);
    let mut tr = vec![0u8; TR_LEN];
    hasher.finalize_xof().read(&mut tr);
    tr
}

/// Resolve `CK_MU_GEN_PARAMS` into the prefix SHAKE256 should absorb before
/// the message, namely `tr || 0x00 || len(ctx) || ctx`.
///
/// The parameter supplies either a key handle to take `tr` from, or a
/// precomputed `tr` directly. Exactly one is required: with neither there is
/// nothing to bind the signature to a key, and honouring both would leave
/// which one wins undefined.
pub(crate) fn resolve_mu_gen_params(
    slot: &Slot<PivBackend>,
    parameter: &[u8],
) -> Result<Vec<u8>, CK_RV> {
    if parameter.len() != std::mem::size_of::<CK_MU_GEN_PARAMS>() {
        return Err(CKR_MECHANISM_PARAM_INVALID.into());
    }
    // SAFETY: length checked above; read_unaligned for the same reason as
    // `sign.rs`'s `resolve_ml_dsa_context` -- PKCS#11 callers are not
    // guaranteed to hand us an aligned pointer.
    let params: CK_MU_GEN_PARAMS =
        unsafe { std::ptr::read_unaligned(parameter.as_ptr() as *const CK_MU_GEN_PARAMS) };

    let have_key = params.hKey != 0;
    let have_tr = !params.pTR.is_null() && params.ulTRLen != 0;

    let tr = match (have_key, have_tr) {
        (true, false) => {
            let Some((_, public_key)) =
                crate::objects::find_public_key(&slot.data.objects, params.hKey)
            else {
                return Err(CKR_KEY_HANDLE_INVALID.into());
            };
            let PublicKey::MlDsa(k) = public_key else {
                return Err(CKR_KEY_TYPE_INCONSISTENT.into());
            };
            compute_tr(&k.key)
        }
        (false, true) => {
            if params.ulTRLen as usize != TR_LEN {
                return Err(CKR_MECHANISM_PARAM_INVALID.into());
            }
            // SAFETY: a second caller-supplied pointer+length pair, valid
            // for the duration of this call -- same trust boundary as
            // `parameter` itself.
            unsafe {
                std::slice::from_raw_parts(params.pTR as *const u8, TR_LEN).to_vec()
            }
        }
        _ => return Err(CKR_MECHANISM_PARAM_INVALID.into()),
    };

    let ctx_len = params.ulctxLen as usize;
    if ctx_len > 255 {
        return Err(CKR_MECHANISM_PARAM_INVALID.into());
    }
    if ctx_len != 0 && params.pctx.is_null() {
        return Err(CKR_MECHANISM_PARAM_INVALID.into());
    }

    // M' is prefixed with the domain separator for pure ML-DSA (0x00) and a
    // single-byte context length, per FIPS 204.
    let mut prefix = tr;
    prefix.push(0x00);
    prefix.push(ctx_len as u8);
    if ctx_len != 0 {
        // SAFETY: as above, and the null case is excluded.
        prefix.extend_from_slice(unsafe {
            std::slice::from_raw_parts(params.pctx as *const u8, ctx_len)
        });
    }
    Ok(prefix)
}

/// `C_DigestInit` for `CKM_ML_DSA_EXTERNAL_MU_GEN`.
pub fn digest_init(
    slot: &mut Slot<PivBackend>,
    mechanism: CK_MECHANISM_TYPE,
    parameter: &[u8],
) -> Result<Option<DigestOp>, CK_RV> {
    if mechanism as u32 != CKM_ML_DSA_EXTERNAL_MU_GEN {
        return Ok(None);
    }
    let prefix = resolve_mu_gen_params(slot, parameter)?;
    Ok(Some(DigestOp::new_shake256(&prefix, MU_LEN)))
}
