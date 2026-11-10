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

const MIN_RSA_KEY_SIZE: CK_ULONG = 1024;
const MIN_RSA_KEY_SIZE_6_0: CK_ULONG = 2048;
const MAX_RSA_KEY_SIZE: CK_ULONG = 2048;
const MAX_RSA_KEY_SIZE_5_7: CK_ULONG = 4096;
const MIN_ECC_KEY_SIZE: CK_ULONG = 256;
const MAX_ECC_KEY_SIZE: CK_ULONG = 384;

fn min_rsa_key_size(fw: (u8, u8)) -> CK_ULONG {
    if fw >= (6, 0) {
        MIN_RSA_KEY_SIZE_6_0
    } else {
        MIN_RSA_KEY_SIZE
    }
}

fn max_rsa_key_size(fw: (u8, u8)) -> CK_ULONG {
    if fw >= (5, 7) {
        MAX_RSA_KEY_SIZE_5_7
    } else {
        MAX_RSA_KEY_SIZE
    }
}


pub struct MechanismEntry {
    pub mechanism: CK_MECHANISM_TYPE,
    pub min_key_size: CK_ULONG,
    pub max_key_size: CK_ULONG,
    pub flags: CK_FLAGS,
}

pub fn mechanism_table(firmware: (u8, u8)) -> Vec<MechanismEntry> {
    let rsa_min_key_size = min_rsa_key_size(firmware);
    let rsa_max_key_size = max_rsa_key_size(firmware);

    let mut table = vec![
        MechanismEntry {
            mechanism: CKM_RSA_PKCS_KEY_PAIR_GEN.into(),
            min_key_size: rsa_min_key_size,
            max_key_size: rsa_max_key_size,
            flags: CKF_HW as CK_FLAGS | CKF_GENERATE_KEY_PAIR as CK_FLAGS,
        },
        MechanismEntry {
            mechanism: CKM_RSA_PKCS.into(),
            min_key_size: rsa_min_key_size,
            max_key_size: rsa_max_key_size,
            flags: CKF_HW as CK_FLAGS
                | CKF_ENCRYPT as CK_FLAGS
                | CKF_DECRYPT as CK_FLAGS
                | CKF_SIGN as CK_FLAGS
                | CKF_VERIFY as CK_FLAGS,
        },
        MechanismEntry {
            mechanism: CKM_RSA_PKCS_PSS.into(),
            min_key_size: rsa_min_key_size,
            max_key_size: rsa_max_key_size,
            flags: CKF_HW as CK_FLAGS | CKF_SIGN as CK_FLAGS | CKF_VERIFY as CK_FLAGS,
        },
        MechanismEntry {
            mechanism: CKM_RSA_PKCS_OAEP.into(),
            min_key_size: rsa_min_key_size,
            max_key_size: rsa_max_key_size,
            flags: CKF_HW as CK_FLAGS | CKF_ENCRYPT as CK_FLAGS | CKF_DECRYPT as CK_FLAGS,
        },
        MechanismEntry {
            mechanism: CKM_RSA_X_509.into(),
            min_key_size: rsa_min_key_size,
            max_key_size: rsa_max_key_size,
            flags: CKF_HW as CK_FLAGS
                | CKF_ENCRYPT as CK_FLAGS
                | CKF_DECRYPT as CK_FLAGS
                | CKF_SIGN as CK_FLAGS
                | CKF_VERIFY as CK_FLAGS,
        },
        MechanismEntry {
            mechanism: CKM_SHA1_RSA_PKCS.into(),
            min_key_size: rsa_min_key_size,
            max_key_size: rsa_max_key_size,
            flags: CKF_HW as CK_FLAGS | CKF_SIGN as CK_FLAGS | CKF_VERIFY as CK_FLAGS,
        },
        MechanismEntry {
            mechanism: CKM_SHA256_RSA_PKCS.into(),
            min_key_size: rsa_min_key_size,
            max_key_size: rsa_max_key_size,
            flags: CKF_HW as CK_FLAGS | CKF_SIGN as CK_FLAGS | CKF_VERIFY as CK_FLAGS,
        },
        MechanismEntry {
            mechanism: CKM_SHA384_RSA_PKCS.into(),
            min_key_size: rsa_min_key_size,
            max_key_size: rsa_max_key_size,
            flags: CKF_HW as CK_FLAGS | CKF_SIGN as CK_FLAGS | CKF_VERIFY as CK_FLAGS,
        },
        MechanismEntry {
            mechanism: CKM_SHA512_RSA_PKCS.into(),
            min_key_size: rsa_min_key_size,
            max_key_size: rsa_max_key_size,
            flags: CKF_HW as CK_FLAGS | CKF_SIGN as CK_FLAGS | CKF_VERIFY as CK_FLAGS,
        },
        MechanismEntry {
            mechanism: CKM_SHA1_RSA_PKCS_PSS.into(),
            min_key_size: rsa_min_key_size,
            max_key_size: rsa_max_key_size,
            flags: CKF_HW as CK_FLAGS | CKF_SIGN as CK_FLAGS | CKF_VERIFY as CK_FLAGS,
        },
        MechanismEntry {
            mechanism: CKM_SHA256_RSA_PKCS_PSS.into(),
            min_key_size: rsa_min_key_size,
            max_key_size: rsa_max_key_size,
            flags: CKF_HW as CK_FLAGS | CKF_SIGN as CK_FLAGS | CKF_VERIFY as CK_FLAGS,
        },
        MechanismEntry {
            mechanism: CKM_SHA384_RSA_PKCS_PSS.into(),
            min_key_size: rsa_min_key_size,
            max_key_size: rsa_max_key_size,
            flags: CKF_HW as CK_FLAGS | CKF_SIGN as CK_FLAGS | CKF_VERIFY as CK_FLAGS,
        },
        MechanismEntry {
            mechanism: CKM_SHA512_RSA_PKCS_PSS.into(),
            min_key_size: rsa_min_key_size,
            max_key_size: rsa_max_key_size,
            flags: CKF_HW as CK_FLAGS | CKF_SIGN as CK_FLAGS | CKF_VERIFY as CK_FLAGS,
        },
        MechanismEntry {
            mechanism: CKM_EC_KEY_PAIR_GEN.into(),
            min_key_size: MIN_ECC_KEY_SIZE,
            max_key_size: MAX_ECC_KEY_SIZE,
            flags: CKF_HW as CK_FLAGS
                | CKF_GENERATE_KEY_PAIR as CK_FLAGS
                | CKF_EC_F_P as CK_FLAGS
                | CKF_EC_NAMEDCURVE as CK_FLAGS
                | CKF_EC_UNCOMPRESS as CK_FLAGS,
        },
        MechanismEntry {
            mechanism: CKM_ECDSA.into(),
            min_key_size: MIN_ECC_KEY_SIZE,
            max_key_size: MAX_ECC_KEY_SIZE,
            flags: CKF_HW as CK_FLAGS
                | CKF_SIGN as CK_FLAGS
                | CKF_VERIFY as CK_FLAGS
                | CKF_EC_F_P as CK_FLAGS
                | CKF_EC_NAMEDCURVE as CK_FLAGS
                | CKF_EC_UNCOMPRESS as CK_FLAGS,
        },
        MechanismEntry {
            mechanism: CKM_ECDSA_SHA1.into(),
            min_key_size: MIN_ECC_KEY_SIZE,
            max_key_size: MAX_ECC_KEY_SIZE,
            flags: CKF_HW as CK_FLAGS
                | CKF_SIGN as CK_FLAGS
                | CKF_VERIFY as CK_FLAGS
                | CKF_EC_F_P as CK_FLAGS
                | CKF_EC_NAMEDCURVE as CK_FLAGS
                | CKF_EC_UNCOMPRESS as CK_FLAGS,
        },
        MechanismEntry {
            mechanism: CKM_ECDSA_SHA224.into(),
            min_key_size: MIN_ECC_KEY_SIZE,
            max_key_size: MAX_ECC_KEY_SIZE,
            flags: CKF_HW as CK_FLAGS
                | CKF_SIGN as CK_FLAGS
                | CKF_VERIFY as CK_FLAGS
                | CKF_EC_F_P as CK_FLAGS
                | CKF_EC_NAMEDCURVE as CK_FLAGS
                | CKF_EC_UNCOMPRESS as CK_FLAGS,
        },
        MechanismEntry {
            mechanism: CKM_ECDSA_SHA256.into(),
            min_key_size: MIN_ECC_KEY_SIZE,
            max_key_size: MAX_ECC_KEY_SIZE,
            flags: CKF_HW as CK_FLAGS
                | CKF_SIGN as CK_FLAGS
                | CKF_VERIFY as CK_FLAGS
                | CKF_EC_F_P as CK_FLAGS
                | CKF_EC_NAMEDCURVE as CK_FLAGS
                | CKF_EC_UNCOMPRESS as CK_FLAGS,
        },
        MechanismEntry {
            mechanism: CKM_ECDSA_SHA384.into(),
            min_key_size: MIN_ECC_KEY_SIZE,
            max_key_size: MAX_ECC_KEY_SIZE,
            flags: CKF_HW as CK_FLAGS
                | CKF_SIGN as CK_FLAGS
                | CKF_VERIFY as CK_FLAGS
                | CKF_EC_F_P as CK_FLAGS
                | CKF_EC_NAMEDCURVE as CK_FLAGS
                | CKF_EC_UNCOMPRESS as CK_FLAGS,
        },
        MechanismEntry {
            mechanism: CKM_ECDSA_SHA512.into(),
            min_key_size: MIN_ECC_KEY_SIZE,
            max_key_size: MAX_ECC_KEY_SIZE,
            flags: CKF_HW as CK_FLAGS
                | CKF_SIGN as CK_FLAGS
                | CKF_VERIFY as CK_FLAGS
                | CKF_EC_F_P as CK_FLAGS
                | CKF_EC_NAMEDCURVE as CK_FLAGS
                | CKF_EC_UNCOMPRESS as CK_FLAGS,
        },
        MechanismEntry {
            mechanism: CKM_ECDH1_DERIVE.into(),
            min_key_size: MIN_ECC_KEY_SIZE,
            max_key_size: MAX_ECC_KEY_SIZE,
            flags: CKF_HW as CK_FLAGS
                | CKF_DERIVE as CK_FLAGS
                | CKF_EC_F_P as CK_FLAGS
                | CKF_EC_NAMEDCURVE as CK_FLAGS
                | CKF_EC_UNCOMPRESS as CK_FLAGS,
        },
        MechanismEntry {
            mechanism: CKM_SHA_1.into(),
            min_key_size: 0,
            max_key_size: 0,
            flags: CKF_DIGEST as CK_FLAGS,
        },
        MechanismEntry {
            mechanism: CKM_SHA256.into(),
            min_key_size: 0,
            max_key_size: 0,
            flags: CKF_DIGEST as CK_FLAGS,
        },
        MechanismEntry {
            mechanism: CKM_SHA384.into(),
            min_key_size: 0,
            max_key_size: 0,
            flags: CKF_DIGEST as CK_FLAGS,
        },
        MechanismEntry {
            mechanism: CKM_SHA512.into(),
            min_key_size: 0,
            max_key_size: 0,
            flags: CKF_DIGEST as CK_FLAGS,
        },
    ];

    // ED25519 and X25519 mechanisms
    if firmware >= (5,7) {
        table.push(MechanismEntry {
            mechanism: CKM_EC_EDWARDS_KEY_PAIR_GEN.into(),
            min_key_size: 255,
            max_key_size: 255,
            flags: CKF_HW as CK_FLAGS
                | CKF_GENERATE_KEY_PAIR as CK_FLAGS
                | CKF_EC_F_P as CK_FLAGS
                | CKF_EC_NAMEDCURVE as CK_FLAGS
                | CKF_EC_UNCOMPRESS as CK_FLAGS,
        });
        table.push(MechanismEntry {
            mechanism: CKM_EC_MONTGOMERY_KEY_PAIR_GEN.into(),
            min_key_size: 255,
            max_key_size: 255,
            flags: CKF_HW as CK_FLAGS
                | CKF_GENERATE_KEY_PAIR as CK_FLAGS
                | CKF_EC_F_P as CK_FLAGS
                | CKF_EC_NAMEDCURVE as CK_FLAGS
                | CKF_EC_UNCOMPRESS as CK_FLAGS,
        });
        table.push(MechanismEntry {
            mechanism: CKM_EDDSA.into(),
            min_key_size: 255,
            max_key_size: 255,
            flags: CKF_HW as CK_FLAGS
                | CKF_SIGN as CK_FLAGS
                | CKF_VERIFY as CK_FLAGS
                | CKF_EC_F_P as CK_FLAGS
                | CKF_EC_NAMEDCURVE as CK_FLAGS
                | CKF_EC_UNCOMPRESS as CK_FLAGS,
        });
    }

    // PQC mechanisms
    if firmware >= (6,0) {
        table.push(MechanismEntry {
            mechanism: CKM_ML_DSA_KEY_PAIR_GEN.into(),
            min_key_size: 0,
            max_key_size: 0,
            flags: CKF_HW as CK_FLAGS | CKF_GENERATE_KEY_PAIR as CK_FLAGS,
        });
        table.push(MechanismEntry {
            mechanism: CKM_ML_KEM_KEY_PAIR_GEN.into(),
            min_key_size: 0,
            max_key_size: 0,
            flags: CKF_HW as CK_FLAGS | CKF_GENERATE_KEY_PAIR as CK_FLAGS,
        });
        table.push(MechanismEntry {
            mechanism: CKM_ML_KEM.into(),
            min_key_size: 0,
            max_key_size: 0,
            flags: CKF_HW as CK_FLAGS | CKF_ENCAPSULATE as CK_FLAGS | CKF_DECAPSULATE as CK_FLAGS,
        });
        table.push(MechanismEntry {
            mechanism: CKM_ML_DSA.into(),
            min_key_size: 0,
            max_key_size: 0,
            flags: CKF_HW as CK_FLAGS | CKF_SIGN as CK_FLAGS | CKF_VERIFY as CK_FLAGS,
        });
        table.push(MechanismEntry {
            mechanism: CKM_ML_DSA_EXTERNAL_MU.into(),
            min_key_size: 0,
            max_key_size: 0,
            flags: CKF_HW as CK_FLAGS | CKF_SIGN as CK_FLAGS,
        });
    }

    table
}

pub fn token_mechanisms(firmware: (u8, u8)) -> Vec<CK_MECHANISM_TYPE> {
    mechanism_table(firmware).into_iter().map(|e| e.mechanism).collect()
}
