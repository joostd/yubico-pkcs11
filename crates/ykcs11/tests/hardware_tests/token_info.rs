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

use crate::util::*;
use pkcs11_sys::*;
use std::ptr;

const INTERFACE_NAME: &[u8] = b"PKCS 11\0";

fn expected_mechanisms(firmware: (u8, u8)) -> Vec<(CK_MECHANISM_TYPE, CK_ULONG, CK_ULONG, CK_FLAGS)> {
    let rsa_min = if firmware >= (6, 0) {
        2048
    } else {
        1024
    };

    let rsa_max = if firmware >= (5, 7) {
        4096
    } else {
        2048
    };

    let mut mechs = vec![
        (CKM_RSA_PKCS_KEY_PAIR_GEN as CK_MECHANISM_TYPE,
         rsa_min, rsa_max, (CKF_HW | CKF_GENERATE_KEY_PAIR) as CK_FLAGS),
        (CKM_RSA_PKCS as CK_MECHANISM_TYPE,
         rsa_min, rsa_max, (CKF_HW | CKF_ENCRYPT | CKF_DECRYPT | CKF_SIGN | CKF_VERIFY) as CK_FLAGS),
        (CKM_RSA_PKCS_PSS as CK_MECHANISM_TYPE,
         rsa_min, rsa_max, (CKF_HW | CKF_SIGN | CKF_VERIFY) as CK_FLAGS),
        (CKM_RSA_PKCS_OAEP as CK_MECHANISM_TYPE,
         rsa_min, rsa_max, (CKF_HW | CKF_ENCRYPT | CKF_DECRYPT) as CK_FLAGS),
        (CKM_RSA_X_509 as CK_MECHANISM_TYPE,
         rsa_min, rsa_max, (CKF_HW | CKF_ENCRYPT | CKF_DECRYPT | CKF_SIGN | CKF_VERIFY) as CK_FLAGS),
        (CKM_SHA1_RSA_PKCS as CK_MECHANISM_TYPE, rsa_min, rsa_max, (CKF_HW | CKF_SIGN | CKF_VERIFY) as CK_FLAGS),
        (CKM_SHA256_RSA_PKCS as CK_MECHANISM_TYPE, rsa_min, rsa_max, (CKF_HW | CKF_SIGN | CKF_VERIFY) as CK_FLAGS),
        (CKM_SHA384_RSA_PKCS as CK_MECHANISM_TYPE, rsa_min, rsa_max, (CKF_HW | CKF_SIGN | CKF_VERIFY) as CK_FLAGS),
        (CKM_SHA512_RSA_PKCS as CK_MECHANISM_TYPE, rsa_min, rsa_max, (CKF_HW | CKF_SIGN | CKF_VERIFY) as CK_FLAGS),
        (CKM_SHA1_RSA_PKCS_PSS as CK_MECHANISM_TYPE, rsa_min, rsa_max, (CKF_HW | CKF_SIGN | CKF_VERIFY) as CK_FLAGS),
        (CKM_SHA256_RSA_PKCS_PSS as CK_MECHANISM_TYPE, rsa_min, rsa_max, (CKF_HW | CKF_SIGN | CKF_VERIFY) as CK_FLAGS),
        (CKM_SHA384_RSA_PKCS_PSS as CK_MECHANISM_TYPE, rsa_min, rsa_max, (CKF_HW | CKF_SIGN | CKF_VERIFY) as CK_FLAGS),
        (CKM_SHA512_RSA_PKCS_PSS as CK_MECHANISM_TYPE, rsa_min, rsa_max, (CKF_HW | CKF_SIGN | CKF_VERIFY) as CK_FLAGS),
        (CKM_EC_KEY_PAIR_GEN as CK_MECHANISM_TYPE,
         256, 384, (CKF_HW | CKF_GENERATE_KEY_PAIR | CKF_EC_F_P | CKF_EC_NAMEDCURVE | CKF_EC_UNCOMPRESS) as CK_FLAGS),
        (CKM_ECDSA as CK_MECHANISM_TYPE,
         256, 384, (CKF_HW | CKF_SIGN | CKF_VERIFY | CKF_EC_F_P | CKF_EC_NAMEDCURVE | CKF_EC_UNCOMPRESS) as CK_FLAGS),
        (CKM_ECDSA_SHA1 as CK_MECHANISM_TYPE,
         256, 384, (CKF_HW | CKF_SIGN | CKF_VERIFY | CKF_EC_F_P | CKF_EC_NAMEDCURVE | CKF_EC_UNCOMPRESS) as CK_FLAGS),
        (CKM_ECDSA_SHA224 as CK_MECHANISM_TYPE,
         256, 384, (CKF_HW | CKF_SIGN | CKF_VERIFY | CKF_EC_F_P | CKF_EC_NAMEDCURVE | CKF_EC_UNCOMPRESS) as CK_FLAGS),
        (CKM_ECDSA_SHA256 as CK_MECHANISM_TYPE,
         256, 384, (CKF_HW | CKF_SIGN | CKF_VERIFY | CKF_EC_F_P | CKF_EC_NAMEDCURVE | CKF_EC_UNCOMPRESS) as CK_FLAGS),
        (CKM_ECDSA_SHA384 as CK_MECHANISM_TYPE,
         256, 384, (CKF_HW | CKF_SIGN | CKF_VERIFY | CKF_EC_F_P | CKF_EC_NAMEDCURVE | CKF_EC_UNCOMPRESS) as CK_FLAGS),
        (CKM_ECDSA_SHA512 as CK_MECHANISM_TYPE,
         256, 384, (CKF_HW | CKF_SIGN | CKF_VERIFY | CKF_EC_F_P | CKF_EC_NAMEDCURVE | CKF_EC_UNCOMPRESS) as CK_FLAGS),
        (CKM_ECDH1_DERIVE as CK_MECHANISM_TYPE,
         256, 384, (CKF_HW | CKF_DERIVE | CKF_EC_F_P | CKF_EC_NAMEDCURVE | CKF_EC_UNCOMPRESS) as CK_FLAGS),
        (CKM_SHA_1 as CK_MECHANISM_TYPE, 0, 0, CKF_DIGEST as CK_FLAGS),
        (CKM_SHA256 as CK_MECHANISM_TYPE, 0, 0, CKF_DIGEST as CK_FLAGS),
        (CKM_SHA384 as CK_MECHANISM_TYPE, 0, 0, CKF_DIGEST as CK_FLAGS),
        (CKM_SHA512 as CK_MECHANISM_TYPE, 0, 0, CKF_DIGEST as CK_FLAGS),
    ];

    if firmware >= (5, 4) {
        mechs.push(
        (CKM_EC_EDWARDS_KEY_PAIR_GEN as CK_MECHANISM_TYPE,
         255, 255, (CKF_HW | CKF_GENERATE_KEY_PAIR | CKF_EC_F_P | CKF_EC_NAMEDCURVE | CKF_EC_UNCOMPRESS) as CK_FLAGS));
        mechs.push (
        (CKM_EC_MONTGOMERY_KEY_PAIR_GEN as CK_MECHANISM_TYPE,
         255, 255, (CKF_HW | CKF_GENERATE_KEY_PAIR | CKF_EC_F_P | CKF_EC_NAMEDCURVE | CKF_EC_UNCOMPRESS) as CK_FLAGS));
        mechs.push(
        (CKM_EDDSA as CK_MECHANISM_TYPE, 255, 255, (CKF_HW | CKF_SIGN | CKF_VERIFY |  CKF_EC_F_P | CKF_EC_NAMEDCURVE | CKF_EC_UNCOMPRESS) as CK_FLAGS));
    }

    if firmware >= (6, 0) {
        mechs.push((CKM_ML_DSA_KEY_PAIR_GEN as CK_MECHANISM_TYPE, 0, 0, (CKF_HW | CKF_GENERATE_KEY_PAIR) as CK_FLAGS));
        mechs.push((CKM_ML_KEM_KEY_PAIR_GEN as CK_MECHANISM_TYPE, 0, 0, (CKF_HW | CKF_GENERATE_KEY_PAIR) as CK_FLAGS));
        mechs.push((CKM_ML_KEM as CK_MECHANISM_TYPE, 0, 0, (CKF_HW | CKF_ENCAPSULATE | CKF_DECAPSULATE) as CK_FLAGS));
        mechs.push((CKM_ML_DSA as CK_MECHANISM_TYPE, 0, 0, (CKF_HW | CKF_SIGN | CKF_VERIFY) as CK_FLAGS));
        mechs.push((CKM_ML_DSA_EXTERNAL_MU as CK_MECHANISM_TYPE, 0, 0, (CKF_HW | CKF_SIGN | CKF_VERIFY) as CK_FLAGS));
    }
    mechs
}

fn get_interface(label: &str, name: Option<&[u8]>, cyproki_version: Option<(CK_BYTE, CK_BYTE)>, expected_rv: CK_RV) -> CK_INTERFACE_PTR {
    let name_ptr = name.map_or(ptr::null_mut(), |n| n.as_ptr() as CK_UTF8CHAR_PTR);

    let mut version_storage = cyproki_version.map(|(major, minor)| CK_VERSION { major, minor });
    let version_ptr = version_storage.as_mut().map_or(ptr::null_mut(), |v| v as *mut CK_VERSION);

    let mut p_interface: CK_INTERFACE_PTR = ptr::null_mut();
    let rv = unsafe { ykcs11::C_GetInterface(name_ptr, version_ptr, &mut p_interface, 0) };
    assert_eq!(rv, expected_rv, "C_GetInterface ({label})");
    if expected_rv == CKR_OK as CK_RV {
        assert!(!p_interface.is_null(), "C_GetInterface ({label}) returned a null interface");
    }
    p_interface
}

fn assert_prefix(field: &[CK_CHAR], expected: &[u8], what: &str) {
    assert!(
        field.len() >= expected.len(),
        "{what}: field shorter than expected prefix"
    );
    assert_eq!(
        &field[..expected.len()],
        expected,
        "{what}: expected prefix {:?}, got {:?}",
        String::from_utf8_lossy(expected),
        String::from_utf8_lossy(&field[..expected.len()])
    );
}

fn assert_3_2_interface(p_interface: CK_INTERFACE_PTR) {
    let function_list = unsafe { (*p_interface).pFunctionList as *const CK_FUNCTION_LIST_3_2 };
    assert!(!function_list.is_null(), "C_GetInterface returned a null function list");
    let cryptoki_version = unsafe { (*function_list).version };
    assert_eq!((cryptoki_version.major, cryptoki_version.minor), (3, 2), "Interface version not 3.2");

    let mut info: CK_INFO = unsafe { std::mem::zeroed() };
    let c_get_info = unsafe { (*function_list).C_GetInfo }.expect("C_GetInfo not wired into the 3.2 interface");
    let rv = unsafe { c_get_info(&mut info) };
    assert_eq!(rv, CKR_OK as CK_RV, "C_GetInfo (3.2)");
    assert_lib_info(&info, 3, 2);

    // C_SignMessage (a PKCS#11 3.x message-based function) only exists on
    // the 3.2 function list. Explicitly returns CKR_FUNCTION_NOT_SUPPORTED as opposed
    // to unrecognized function
    let c_sign_message = unsafe { (*function_list).C_SignMessage }.expect("C_SignMessage not wired into the 3.2 interface");
    let rv = unsafe {
        c_sign_message(
            0,
            ptr::null_mut(),
            0,
            ptr::null_mut(),
            0,
            ptr::null_mut(),
            ptr::null_mut(),
        )
    };
    assert_eq!(rv, CKR_FUNCTION_NOT_SUPPORTED as CK_RV, "C_SignMessage");
}


/// `CK_INFO.manufacturerID`/`libraryDescription` are blank-padded fixed
/// buffers, and `libraryVersion` is hardcoded in `ykcs11`'s own
/// `PivBackend::library_info()` regardless of which interface version
/// reported it -- only `cryptokiVersion` varies by call path.
fn assert_lib_info(info: &CK_INFO, cryptoki_major: u8, cryptoki_minor: u8) {
    assert_prefix(&info.manufacturerID, b"Yubico (www.yubico.com)", "CK_INFO.manufacturerID");
    assert_prefix(&info.libraryDescription, b"PKCS#11 PIV Library (SP-800-73)", "CK_INFO.libraryDescription");

    let cryptoki_version = info.cryptokiVersion;
    let library_version = info.libraryVersion;
    assert_eq!(
        (cryptoki_version.major, cryptoki_version.minor),
        (cryptoki_major, cryptoki_minor),
        "CK_INFO.cryptokiVersion"
    );
    assert_eq!((library_version.major, library_version.minor), (1, 0), "CK_INFO.libraryVersion");
}

#[test]
fn test_token_info() {
    if !hardware_tests_enabled() {
        eprintln!(
            "skipping hardware_token_info: set {RUN_ENV_VAR}=1 to run \
             (destructive -- see this crate's module doc comment)"
        );
        return;
    }
    let _guard = HARDWARE_LOCK.lock().unwrap();

    ensure_initialized();

    let slot_id = first_populated_slot();

    // No session is opened before calling C_GetTokenInfo, so ulSessionCount/ulRwSessionCount
    // below are expected to be exactly 0.
    let info = token_info(slot_id);
    assert_prefix(&info.label, b"YubiKey PIV", "CK_TOKEN_INFO.label");
    assert_prefix(&info.model, b"YubiKey", "CK_TOKEN_INFO.model");

    // CK_TOKEN_INFO is `#[repr(packed)]` on Windows so its
    // multi-byte fields can't be referenced in place
    let flags = info.flags;
    let max_session_count = info.ulMaxSessionCount;
    let session_count = info.ulSessionCount;
    let max_rw_session_count = info.ulMaxRwSessionCount;
    let rw_session_count = info.ulRwSessionCount;
    let min_pin_len = info.ulMinPinLen;
    let max_pin_len = info.ulMaxPinLen;
    let total_public_memory = info.ulTotalPublicMemory;
    let free_public_memory = info.ulFreePublicMemory;
    let total_private_memory = info.ulTotalPrivateMemory;
    let free_private_memory = info.ulFreePrivateMemory;

    let expected_flags = (CKF_RNG | CKF_LOGIN_REQUIRED | CKF_USER_PIN_INITIALIZED | CKF_TOKEN_INITIALIZED)
        as CK_FLAGS;
    assert_eq!(flags, expected_flags, "CK_TOKEN_INFO.flags");

    assert_eq!(max_session_count, 16, "ulMaxSessionCount");
    assert_eq!(session_count, 0, "ulSessionCount");
    assert_eq!(max_rw_session_count, 16, "ulMaxRwSessionCount");
    assert_eq!(rw_session_count, 0, "ulRwSessionCount");

    assert_eq!(min_pin_len, 6, "ulMinPinLen");
    assert_eq!(max_pin_len, 64, "ulMaxPinLen");

    let unavailable = CK_UNAVAILABLE_INFORMATION as CK_ULONG;
    assert_eq!(total_public_memory, unavailable, "ulTotalPublicMemory");
    assert_eq!(free_public_memory, unavailable, "ulFreePublicMemory");
    assert_eq!(total_private_memory, unavailable, "ulTotalPrivateMemory");
    assert_eq!(free_private_memory, unavailable, "ulFreePrivateMemory");

    assert_eq!(info.hardwareVersion.major, 1, "hardwareVersion.major");
    assert_eq!(info.hardwareVersion.minor, 0, "hardwareVersion.minor");

    assert_eq!(info.utcTime, [b' '; 16], "CK_TOKEN_INFO.utcTime");

    eprintln!(
        "detected firmware {}.{}",
        info.firmwareVersion.major, info.firmwareVersion.minor
    );
}

#[test]
fn test_mechanism_list() {
    if !hardware_tests_enabled() {
        eprintln!("skipping hardware_mechanism_list_and_info: set {RUN_ENV_VAR}=1 to run");
        return;
    }
    let _guard = HARDWARE_LOCK.lock().unwrap();

    ensure_initialized();

    let slot_id = first_populated_slot();

    // Matches ykcs11_tests.c's ed25519_supported gate (firmware >= 5.7):
    // RSA key sizes above 2048 bits need firmware 5.7+ (backend.rs's own
    // mechanism_info()).
    let info = token_info(slot_id);
    let expected = expected_mechanisms((info.firmwareVersion.major, info.firmwareVersion.minor));

    let mut count: CK_ULONG = 0;
    let rv = unsafe { ykcs11::C_GetMechanismList(slot_id, ptr::null_mut(), &mut count) };
    assert_eq!(rv, CKR_OK as CK_RV, "C_GetMechanismList (count)");
    assert_eq!(count as usize, expected.len(), "unexpected mechanism count");

    let mut mechs = vec![0 as CK_MECHANISM_TYPE; count as usize];
    let rv = unsafe { ykcs11::C_GetMechanismList(slot_id, mechs.as_mut_ptr(), &mut count) };
    assert_eq!(rv, CKR_OK as CK_RV, "C_GetMechanismList (fill)");

    // Order isn't part of the PKCS#11 contract for C_GetMechanismList --
    // unlike ykcs11_tests.c's memcmp (which only works because it controls
    // the array layout on both sides), compare as sets.
    let mut mechs_sorted = mechs.clone();
    mechs_sorted.sort();
    let mut expected_types: Vec<CK_MECHANISM_TYPE> = expected.iter().map(|e| e.0).collect();
    expected_types.sort();
    assert_eq!(mechs_sorted, expected_types, "mechanism set mismatch");

    for (mechanism, min, max, flags) in expected {
        let mut mech_info: CK_MECHANISM_INFO = unsafe { std::mem::zeroed() };
        let rv = unsafe { ykcs11::C_GetMechanismInfo(slot_id, mechanism, &mut mech_info) };
        assert_eq!(rv, CKR_OK as CK_RV, "{}", &format!("C_GetMechanismInfo(0x{mechanism:x})"));

        let min_key_size = mech_info.ulMinKeySize;
        let max_key_size = mech_info.ulMaxKeySize;
        let mech_flags = mech_info.flags;
        assert_eq!(min_key_size, min, "0x{mechanism:x}: ulMinKeySize");
        assert_eq!(max_key_size, max, "0x{mechanism:x}: ulMaxKeySize");
        assert_eq!(mech_flags, flags, "0x{mechanism:x}: flags");
    }
}

#[test]
fn test_interfaces() {

    let _guard = HARDWARE_LOCK.lock().unwrap();
    ensure_initialized();

    // No name, no Cryptoki version interface (Default)
    let p_interface: CK_INTERFACE_PTR = get_interface("Default, no name no version", None, None, CKR_OK as CK_RV);
    assert_3_2_interface(p_interface);

    // Name, no Cryptoki version interface
    let p_interface: CK_INTERFACE_PTR = get_interface("Named, no version", Some(INTERFACE_NAME), None, CKR_OK as CK_RV);
    assert_3_2_interface(p_interface);

    // Cryptoki version: 3.2
    let p_interface: CK_INTERFACE_PTR = get_interface("versioned 3.2", None, Some((3, 2)), CKR_OK as CK_RV);
    assert_3_2_interface(p_interface);

    // Cryptoki version: 3.0
    get_interface("versioned 3.0", None, Some((3, 0)), CKR_ARGUMENTS_BAD as CK_RV);

    // Cryptoki version: 2.4
    get_interface("versioned 3.2", None, Some((2, 4)), CKR_ARGUMENTS_BAD as CK_RV);


    // The legacy 2.40-shaped function list is reachable only via the
    // original C_GetFunctionList entry point in this backend, not via
    // C_GetInterface
    let mut legacy_functions: CK_FUNCTION_LIST_PTR = ptr::null_mut();
    let rv = unsafe { ykcs11::C_GetFunctionList(&mut legacy_functions) };
    assert_eq!(rv, CKR_OK as CK_RV, "C_GetFunctionList");
    assert!(!legacy_functions.is_null(), "C_GetFunctionList returned a null function list");
    let legacy_version = unsafe { (*legacy_functions).version };
    assert_eq!((legacy_version.major, legacy_version.minor), (2, 40), "C_GetFunctionList version");

    let mut legacy_info: CK_INFO = unsafe { std::mem::zeroed() };
    let c_get_info = unsafe { (*legacy_functions).C_GetInfo }.expect("C_GetInfo not wired into the legacy function list");
    let rv = unsafe { c_get_info(&mut legacy_info) };
    assert_eq!(rv, CKR_OK as CK_RV, "C_GetInfo (legacy)");
    assert_lib_info(&legacy_info, 2, 40);

}