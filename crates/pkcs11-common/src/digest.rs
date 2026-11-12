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


use digest::DynDigest;
use pkcs11_sys::*;
use shake::digest::{ExtendableOutput, Update, XofReader};

/// One in-progress digest operation.
pub enum DigestOp {
    /// A conventional fixed-output hash.
    Fixed(Box<dyn DynDigest + Send>),
    /// SHAKE256 used as an extendable-output function, squeezing a fixed
    /// number of bytes at the end. Unlike the fixed hashes this cannot go
    /// through `DynDigest`, whose output size is a property of the
    /// algorithm rather than of the operation.
    Shake256 {
        hasher: shake::Shake256,
        output_len: usize,
    },
}

impl DigestOp {

    pub fn new(mechanism: CK_MECHANISM_TYPE) -> Result<Self, CK_RV> {
        let hasher: Box<dyn DynDigest + Send> = match mechanism as u32 {
            CKM_SHA_1 => Box::new(sha1::Sha1::default()),
            CKM_SHA256 => Box::new(sha2::Sha256::default()),
            CKM_SHA384 => Box::new(sha2::Sha384::default()),
            CKM_SHA512 => Box::new(sha2::Sha512::default()),
            _ => return Err(CKR_MECHANISM_INVALID.into()),
        };
        Ok(Self::Fixed(hasher))
    }

    /// A SHAKE256 XOF operation that has already absorbed `prefix` and will
    /// squeeze `output_len` bytes. The caller supplies the prefix because
    /// the data it is derived from -- a key, say -- is backend-specific.
    pub fn new_shake256(prefix: &[u8], output_len: usize) -> Self {
        let mut hasher = shake::Shake256::default();
        hasher.update(prefix);
        Self::Shake256 { hasher, output_len }
    }

    pub fn update(&mut self, data: &[u8]) {
        match self {
            Self::Fixed(h) => h.update(data),
            Self::Shake256 { hasher, .. } => Update::update(hasher, data),
        }
    }

    /// The digest's fixed output length calculated from the hash algorithm
    pub fn output_len(&self) -> usize {
        match self {
            Self::Fixed(h) => h.output_size(),
            Self::Shake256 { output_len, .. } => *output_len,
        }
    }

    pub fn finalize(self) -> Vec<u8> {
        match self {
            Self::Fixed(h) => h.finalize().into_vec(),
            Self::Shake256 { hasher, output_len } => {
                let mut out = vec![0u8; output_len];
                hasher.finalize_xof().read(&mut out);
                out
            }
        }
    }
}
