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

use crate::digest::DigestOp;
use crate::session::{LoginState, compute_state};
use crate::str_pad;
use parking_lot::Mutex;
use pkcs11_sys::*;
use std::collections::HashMap;
use std::sync::Arc;

/// Fixed library identity reported by `C_GetInfo`.
pub struct LibraryInfo {
    pub manufacturer_id: &'static str,
    pub library_description: &'static str,
    pub library_version: (u8, u8),
    pub cryptoki_version: (u8, u8),
}

/// Hardware-level info reported by `C_GetSlotInfo`.
pub struct SlotInfo {
    pub description: String,
    pub manufacturer_id: String,
    pub hardware_version: (u8, u8),
    pub firmware_version: (u8, u8),
}

/// Token-level info reported by `C_GetTokenInfo`, when a token is present.
pub struct TokenInfo {
    pub label: String,
    pub manufacturer_id: String,
    pub model: String,
    pub serial_number: String,
    pub min_pin_len: CK_ULONG,
    pub max_pin_len: CK_ULONG,
    pub hardware_version: (u8, u8),
    pub firmware_version: (u8, u8),
    pub extra_flags: CK_FLAGS,
}

/// Per-mechanism info reported by `C_GetMechanismInfo`.
pub struct MechanismInfo {
    pub min_key_size: CK_ULONG,
    pub max_key_size: CK_ULONG,
    pub flags: CK_FLAGS,
}

/// `C_FindObjectsInit`/`C_FindObjects`/`C_FindObjectsFinal` state for one session.
#[derive(Default)]
pub struct FindOp {
    pub active: bool,
    pub matches: Vec<CK_OBJECT_HANDLE>,
    pub returned_offset: usize,
}

/// `C_SignInit`/`C_Sign`/`C_SignUpdate`/`C_SignFinal` state for one session
#[derive(Default)]
pub struct SignOp {
    pub active: bool,
    pub out_len: CK_ULONG,
}

/// `C_VerifyInit`/`C_Verify`/`C_VerifyUpdate`/`C_VerifyFinal` state for one session
#[derive(Default)]
pub struct VerifyOp {
    pub active: bool,
}

/// `C_EncryptInit`/`C_Encrypt`/`C_EncryptUpdate`/`C_EncryptFinal` state for one session
#[derive(Default)]
pub struct EncryptOp {
    pub active: bool,
    pub out_len: CK_ULONG,
}

/// `C_DecryptInit`/`C_Decrypt`/`C_DecryptUpdate`/`C_DecryptFinal` state for one session.
#[derive(Default)]
pub struct DecryptOp {
    pub active: bool,
    pub pending: Option<Vec<u8>>,
}

/// A single open session on a slot.
pub struct Session<S> {
    pub handle: CK_SESSION_HANDLE,
    pub flags: CK_FLAGS,
    pub find_op: FindOp,
    pub digest_op: Option<DigestOp>,
    pub sign_op: SignOp,
    pub verify_op: VerifyOp,
    pub encrypt_op: EncryptOp,
    pub decrypt_op: DecryptOp,
    pub data: S,
}

/// Backend-specific slot data including its open sessions
pub struct Slot<B: Backend> {
    pub login_state: LoginState,
    pub sessions: HashMap<CK_SESSION_HANDLE, Session<B::SessionData>>,
    pub data: B::SlotData,
}

impl<B: Backend> Slot<B> {
    pub fn new(data: B::SlotData) -> Self {
        Self {
            login_state: LoginState::Public,
            sessions: HashMap::new(),
            data,
        }
    }
}

/// Everything that exists between `C_Initialize` and `C_Finalize`.
pub struct ModuleState<B: Backend> {
    pub slots: Vec<Arc<Mutex<Slot<B>>>>,
    pub session_to_slot: HashMap<CK_SESSION_HANDLE, CK_SLOT_ID>,
    pub next_session_handle: CK_SESSION_HANDLE,
    pub data: B::ModuleData,
}

/// Backend-specific policy plugged into the shared Cryptoki engine.
pub trait Backend: Sized + 'static {
    /// Extra per-slot state (e.g. the live PC/SC connection or HSM handle).
    type SlotData: Send;
    /// Extra per-session state (e.g. an established HSM session).
    type SessionData: Send;
    /// Extra module-wide state (e.g. parsed config).
    type ModuleData: Send;

    fn library_info() -> LibraryInfo;

    /// Parse the already-extracted `pReserved` string from
    /// `C_Initialize` and build the initial module/slot state.
    fn initialize(reserved: Option<&str>)
    -> Result<(Self::ModuleData, Vec<Self::SlotData>), CK_RV>;

    /// Backend-specific cleanup run during `C_Finalize`, before the module
    /// state is dropped
    fn finalize(_data: &mut Self::ModuleData) {}

    /// Re-scan for slots/tokens. Called at the start of every
    /// `C_GetSlotList`. Backends with a fixed, config-driven slot list can
    /// leave this at the default no-op.
    fn refresh_slots(_state: &mut ModuleState<Self>) -> Result<(), CK_RV> {
        Ok(())
    }

    fn is_present(data: &Self::SlotData) -> bool;

    fn slot_info(slot_id: CK_SLOT_ID, data: &Self::SlotData) -> SlotInfo;

    /// Returns `None` if no token present (translates to `CKR_TOKEN_NOT_PRESENT`).
    fn token_info(data: &mut Self::SlotData) -> Option<TokenInfo>;

    /// The `CKM_*` mechanisms this token supports
    fn mechanism_list(data: &Self::SlotData) -> Vec<CK_MECHANISM_TYPE>;

    /// Details for one mechanism.
    /// Returns `None` if the mechanism is not supported (translates to `CKR_MECHANISM_INVALID`)
    fn mechanism_info(data: &Self::SlotData, mechanism: CK_MECHANISM_TYPE)
    -> Option<MechanismInfo>;

    /// Maximum concurrent sessions per slot, or `None` for unbounded (`CK_EFFECTIVELY_INFINITE`).
    fn max_sessions(_data: &Self::SlotData) -> Option<usize> {
        None
    }

    fn new_session_data(
        slot: &mut Self::SlotData,
        handle: CK_SESSION_HANDLE,
        flags: CK_FLAGS,
    ) -> Self::SessionData;

    /// `username` is the PKCS#11 3.0 `C_LoginUser` identity string, empty
    /// when called from the base `C_Login` (which has no such concept) —
    /// backends that don't distinguish users (e.g. ykcs11) can ignore it.
    fn login(
        slot: &mut Slot<Self>,
        h_session: CK_SESSION_HANDLE,
        user_type: CK_USER_TYPE,
        pin: &[u8],
        username: &[u8],
    ) -> Result<(), CK_RV>;
    fn logout(slot: &mut Slot<Self>) -> Result<(), CK_RV>;

    /// Fill `buf` with random bytes.
    fn generate_random(slot: &Slot<Self>, buf: &mut [u8]) -> Result<(), CK_RV>;

    /// Seed the token's RNG
    fn seed_random(_slot: &Slot<Self>, _seed: &[u8]) -> Result<(), CK_RV> {
        Err(CKR_RANDOM_SEED_NOT_SUPPORTED.into())
    }

    /// Every object handle currently visible on this token,
    /// filtered for login state (e.g. private-key objects omitted while
    /// `slot.login_state == LoginState::Public`)
    fn object_handles(slot: &Slot<Self>) -> Vec<CK_OBJECT_HANDLE>;

    /// One attribute's raw value for a given object handle.
    /// Returns `None` if the attribute does not apply to this object (translates to
    /// `CKR_ATTRIBUTE_TYPE_INVALID`)
    /// Object-handle validity itself is checked separately, against `object_handles`.
    fn get_one_attribute_value(
        data: &Self::SlotData,
        handle: CK_OBJECT_HANDLE,
        attr_type: CK_ATTRIBUTE_TYPE,
    ) -> Option<Vec<u8>>;

    /// Begin a signing operation
    fn sign_init(
        _slot: &mut Slot<Self>,
        _h_session: CK_SESSION_HANDLE,
        _mechanism: CK_MECHANISM_TYPE,
        _parameter: &[u8],
        _key_handle: CK_OBJECT_HANDLE,
    ) -> Result<CK_ULONG, CK_RV> {
        Err(CKR_FUNCTION_NOT_SUPPORTED.into())
    }

    /// Give the backend first refusal on `C_DigestInit`, for digest
    /// mechanisms that need a mechanism parameter or access to objects on
    /// the token -- neither of which the generic `DigestOp::new` path has.
    /// Returning `Ok(None)` means "not mine", and the generic mechanisms
    /// are tried instead, so a backend that does not override this behaves
    /// exactly as before.
    fn digest_init(
        _slot: &mut Slot<Self>,
        _h_session: CK_SESSION_HANDLE,
        _mechanism: CK_MECHANISM_TYPE,
        _parameter: &[u8],
    ) -> Result<Option<DigestOp>, CK_RV> {
        Ok(None)
    }

    /// Feed more data into the signing operation started by `sign_init`.
    fn sign_update(
        _slot: &mut Slot<Self>,
        _h_session: CK_SESSION_HANDLE,
        _data: &[u8],
    ) -> Result<(), CK_RV> {
        Err(CKR_FUNCTION_NOT_SUPPORTED.into())
    }

    /// Finalize the signing operation started by `sign_init`
    fn sign_final(_slot: &mut Slot<Self>, _h_session: CK_SESSION_HANDLE) -> Result<Vec<u8>, CK_RV> {
        Err(CKR_FUNCTION_NOT_SUPPORTED.into())
    }

    /// Begin a verify operation. Not performed on the token
    fn verify_init(
        _slot: &mut Slot<Self>,
        _h_session: CK_SESSION_HANDLE,
        _mechanism: CK_MECHANISM_TYPE,
        _parameter: &[u8],
        _key_handle: CK_OBJECT_HANDLE,
    ) -> Result<(), CK_RV> {
        Err(CKR_FUNCTION_NOT_SUPPORTED.into())
    }

    /// Feed more data into the verify operation started by `verify_init`.
    fn verify_update(
        _slot: &mut Slot<Self>,
        _h_session: CK_SESSION_HANDLE,
        _data: &[u8],
    ) -> Result<(), CK_RV> {
        Err(CKR_FUNCTION_NOT_SUPPORTED.into())
    }

    /// Finalize the verify operation started by `verify_init`
    fn verify_final(
        _slot: &mut Slot<Self>,
        _h_session: CK_SESSION_HANDLE,
        _signature: &[u8],
    ) -> Result<(), CK_RV> {
        Err(CKR_FUNCTION_NOT_SUPPORTED.into())
    }

    /// Begin an encrypt operation
    fn encrypt_init(
        _slot: &mut Slot<Self>,
        _h_session: CK_SESSION_HANDLE,
        _mechanism: CK_MECHANISM_TYPE,
        _parameter: &[u8],
        _key_handle: CK_OBJECT_HANDLE,
    ) -> Result<CK_ULONG, CK_RV> {
        Err(CKR_FUNCTION_NOT_SUPPORTED.into())
    }

    /// Feed more plaintext into the encrypt operation started by
    /// `encrypt_init`.
    fn encrypt_update(
        _slot: &mut Slot<Self>,
        _h_session: CK_SESSION_HANDLE,
        _data: &[u8],
    ) -> Result<(), CK_RV> {
        Err(CKR_FUNCTION_NOT_SUPPORTED.into())
    }

    /// Finalize the encrypt operation started by `encrypt_init`
    fn encrypt_final(_slot: &mut Slot<Self>, _h_session: CK_SESSION_HANDLE) -> Result<Vec<u8>, CK_RV> {
        Err(CKR_FUNCTION_NOT_SUPPORTED.into())
    }

    /// Begin a decrypt operation
    fn decrypt_init(
        _slot: &mut Slot<Self>,
        _h_session: CK_SESSION_HANDLE,
        _mechanism: CK_MECHANISM_TYPE,
        _parameter: &[u8],
        _key_handle: CK_OBJECT_HANDLE,
    ) -> Result<(), CK_RV> {
        Err(CKR_FUNCTION_NOT_SUPPORTED.into())
    }

    /// Feed more ciphertext into the decrypt operation started by
    /// `decrypt_init`
    fn decrypt_update(
        _slot: &mut Slot<Self>,
        _h_session: CK_SESSION_HANDLE,
        _data: &[u8],
    ) -> Result<(), CK_RV> {
        Err(CKR_FUNCTION_NOT_SUPPORTED.into())
    }

    /// Finalize the decrypt operation started by `decrypt_init`
    fn decrypt_final(_slot: &mut Slot<Self>, _h_session: CK_SESSION_HANDLE) -> Result<Vec<u8>, CK_RV> {
        Err(CKR_FUNCTION_NOT_SUPPORTED.into())
    }

    /// Generate a key pair and returning `(public_key_handle, private_key_handle)`
    fn generate_key_pair(
        _slot: &mut Slot<Self>,
        _h_session: CK_SESSION_HANDLE,
        _mechanism: CK_MECHANISM_TYPE,
        _public_key_template: &[(CK_ATTRIBUTE_TYPE, Vec<u8>)],
        _private_key_template: &[(CK_ATTRIBUTE_TYPE, Vec<u8>)],
    ) -> Result<(CK_OBJECT_HANDLE, CK_OBJECT_HANDLE), CK_RV> {
        Err(CKR_FUNCTION_NOT_SUPPORTED.into())
    }

    /// Create (import) an object from a single template, returning its
    /// handle
    fn create_object(
        _slot: &mut Slot<Self>,
        _h_session: CK_SESSION_HANDLE,
        _template: &[(CK_ATTRIBUTE_TYPE, Vec<u8>)],
    ) -> Result<CK_OBJECT_HANDLE, CK_RV> {
        Err(CKR_FUNCTION_NOT_SUPPORTED.into())
    }

    /// Derive ECDH key
    fn derive_key(
        _slot: &mut Slot<Self>,
        _h_session: CK_SESSION_HANDLE,
        _mechanism: CK_MECHANISM_TYPE,
        _parameter: &[u8],
        _base_key_handle: CK_OBJECT_HANDLE,
        _template: &[(CK_ATTRIBUTE_TYPE, Vec<u8>)],
    ) -> Result<CK_OBJECT_HANDLE, CK_RV> {
        Err(CKR_FUNCTION_NOT_SUPPORTED.into())
    }

    /// Destroy an object
    fn destroy_object(
        _slot: &mut Slot<Self>,
        _h_session: CK_SESSION_HANDLE,
        _handle: CK_OBJECT_HANDLE,
    ) -> Result<(), CK_RV> {
        Err(CKR_FUNCTION_NOT_SUPPORTED.into())
    }

    /// Change the PIN/PUK/management key
    fn set_pin(
        _slot: &mut Slot<Self>,
        _h_session: CK_SESSION_HANDLE,
        _old_pin: &[u8],
        _new_pin: &[u8],
    ) -> Result<(), CK_RV> {
        Err(CKR_FUNCTION_NOT_SUPPORTED.into())
    }

    /// Re-initialize a token by performing a factory reset
    fn init_token(_slot: &mut Slot<Self>, _pin: &[u8]) -> Result<(), CK_RV> {
        Err(CKR_FUNCTION_NOT_SUPPORTED.into())
    }

    /// Return the ciphertext length `encapsulate_key` will produce for this public
    /// key without actually performing the (randomized) encapsulation
    fn encapsulate_key_len(
        _slot: &mut Slot<Self>,
        _h_public_key: CK_OBJECT_HANDLE,
    ) -> Result<usize, CK_RV> {
        Err(CKR_FUNCTION_NOT_SUPPORTED.into())
    }

    /// Encapsulate a fresh shared secret against `h_public_key`, returning
    /// `(ciphertext, new secret-key object handle)`
    fn encapsulate_key(
        _slot: &mut Slot<Self>,
        _h_session: CK_SESSION_HANDLE,
        _mechanism: CK_MECHANISM_TYPE,
        _parameter: &[u8],
        _h_public_key: CK_OBJECT_HANDLE,
        _template: &[(CK_ATTRIBUTE_TYPE, Vec<u8>)],
    ) -> Result<(Vec<u8>, CK_OBJECT_HANDLE), CK_RV> {
        Err(CKR_FUNCTION_NOT_SUPPORTED.into())
    }

    /// Decapsulate `ciphertext` with `h_private_key`, returning the new
    /// secret-key object's handle
    fn decapsulate_key(
        _slot: &mut Slot<Self>,
        _h_session: CK_SESSION_HANDLE,
        _mechanism: CK_MECHANISM_TYPE,
        _parameter: &[u8],
        _h_private_key: CK_OBJECT_HANDLE,
        _ciphertext: &[u8],
        _template: &[(CK_ATTRIBUTE_TYPE, Vec<u8>)],
    ) -> Result<CK_OBJECT_HANDLE, CK_RV> {
        Err(CKR_FUNCTION_NOT_SUPPORTED.into())
    }
}

/// Parse  a `CK_ATTRIBUTE` array into `(type, value bytes)` pair
unsafe fn extract_attribute_template(
    p: CK_ATTRIBUTE_PTR,
    count: CK_ULONG,
) -> Vec<(CK_ATTRIBUTE_TYPE, Vec<u8>)> {
    unsafe {
        if count == 0 {
            return Vec::new();
        }
        let attrs = std::slice::from_raw_parts(p, count as usize);
        attrs
            .iter()
            .map(|a| {
                let value = if a.pValue.is_null() || a.ulValueLen == 0 {
                    Vec::new()
                } else {
                    std::slice::from_raw_parts(a.pValue as *const u8, a.ulValueLen as usize).to_vec()
                };
                (a.type_, value)
            })
            .collect()
    }
}

/// The shared Cryptoki engine. One `static` instance per module, generic
/// over a module's [`Backend`] impl.
pub struct Engine<B: Backend> {
    state: Mutex<Option<ModuleState<B>>>,
}

impl<B: Backend> Engine<B> {
    pub const fn new() -> Self {
        Self {
            state: Mutex::new(None),
        }
    }

    /// Extract the `pReserved` C string from `CK_C_INITIALIZE_ARGS*`,
    /// shared by every module's `C_Initialize`.
    unsafe fn extract_reserved(p_init_args: CK_VOID_PTR) -> Option<String> {
        unsafe {
            if p_init_args.is_null() {
                return None;
            }
            let args = &*(p_init_args as *const CK_C_INITIALIZE_ARGS);
            if args.pReserved.is_null() {
                return None;
            }
            let c_str = std::ffi::CStr::from_ptr(args.pReserved as *const std::os::raw::c_char);
            Some(c_str.to_string_lossy().into_owned())
        }
    }

    fn slot_arc(state: &ModuleState<B>, slot_id: CK_SLOT_ID) -> Result<Arc<Mutex<Slot<B>>>, CK_RV> {
        state
            .slots
            .get(slot_id as usize)
            .cloned()
            .ok_or_else(|| CKR_SLOT_ID_INVALID.into())
    }

    pub unsafe fn initialize(&self, p_init_args: CK_VOID_PTR) -> CK_RV {
        unsafe {
            let mut guard = self.state.lock();
            if guard.is_some() {
                return CKR_CRYPTOKI_ALREADY_INITIALIZED.into();
            }

            let reserved = Self::extract_reserved(p_init_args);
            let (data, slot_data) = match B::initialize(reserved.as_deref()) {
                Ok(v) => v,
                Err(rv) => return rv,
            };

            let slots = slot_data
                .into_iter()
                .map(|d| Arc::new(Mutex::new(Slot::new(d))))
                .collect();

            *guard = Some(ModuleState {
                slots,
                session_to_slot: HashMap::new(),
                next_session_handle: 1,
                data,
            });

            CKR_OK.into()
        }
    }

    pub unsafe fn finalize(&self, p_reserved: CK_VOID_PTR) -> CK_RV {
        if !p_reserved.is_null() {
            return CKR_ARGUMENTS_BAD.into();
        }
        let mut guard = self.state.lock();
        let mut state = match guard.take() {
            Some(s) => s,
            None => return CKR_CRYPTOKI_NOT_INITIALIZED.into(),
        };
        B::finalize(&mut state.data);
        CKR_OK.into()
    }

    pub unsafe fn get_info(&self, p_info: CK_INFO_PTR) -> CK_RV {
        let cryptoki_version = B::library_info().cryptoki_version;
        unsafe { self.get_info_with_cryptoki_version(p_info, cryptoki_version) }
    }

    /// Same as [`Engine::get_info`], but reports `cryptoki_version` instead
    /// of what [`Backend::library_info`] specifies.
    pub unsafe fn get_info_with_cryptoki_version(
        &self,
        p_info: CK_INFO_PTR,
        cryptoki_version: (u8, u8),
    ) -> CK_RV {
        unsafe {
            let guard = self.state.lock();
            if guard.is_none() {
                return CKR_CRYPTOKI_NOT_INITIALIZED.into();
            }
            if p_info.is_null() {
                return CKR_ARGUMENTS_BAD.into();
            }

            let lib = B::library_info();
            let info = &mut *p_info;
            info.cryptokiVersion.major = cryptoki_version.0;
            info.cryptokiVersion.minor = cryptoki_version.1;
            str_pad(&mut info.manufacturerID, lib.manufacturer_id);
            info.flags = 0;
            str_pad(&mut info.libraryDescription, lib.library_description);
            info.libraryVersion.major = lib.library_version.0;
            info.libraryVersion.minor = lib.library_version.1;

            CKR_OK.into()
        }
    }

    /// Shared body for `C_GetFunctionList`: every module points at its
    /// own `static CK_FUNCTION_LIST`.
    pub unsafe fn get_function_list(
        &self,
        pp_function_list: *mut CK_FUNCTION_LIST_PTR,
        table: &'static CK_FUNCTION_LIST,
    ) -> CK_RV {
        unsafe {
            if pp_function_list.is_null() {
                return CKR_ARGUMENTS_BAD.into();
            }
            *pp_function_list = table as *const CK_FUNCTION_LIST as CK_FUNCTION_LIST_PTR;
            CKR_OK.into()
        }
    }

    /// PKCS#11 3.0's `C_GetInterfaceList` — generic over the fixed set
    /// of interfaces a module exposes
    pub unsafe fn get_interface_list(
        &self,
        p_interfaces_list: CK_INTERFACE_PTR,
        pul_count: CK_ULONG_PTR,
        interfaces: &'static [CK_INTERFACE],
    ) -> CK_RV {
        unsafe {
            if pul_count.is_null() {
                return CKR_ARGUMENTS_BAD.into();
            }
            let count = interfaces.len() as CK_ULONG;
            if p_interfaces_list.is_null() {
                *pul_count = count;
                return CKR_OK.into();
            }
            if *pul_count < count {
                *pul_count = count;
                return CKR_BUFFER_TOO_SMALL.into();
            }
            for (i, iface) in interfaces.iter().enumerate() {
                *p_interfaces_list.add(i) = *iface;
            }
            *pul_count = count;
            CKR_OK.into()
        }
    }

    /// PKCS#11 3.0's `C_GetInterface` — finds the first entry in
    /// `interfaces` matching `p_interface_name`
    pub unsafe fn get_interface(
        &self,
        p_interface_name: CK_UTF8CHAR_PTR,
        p_version: CK_VERSION_PTR,
        pp_interface: CK_INTERFACE_PTR_PTR,
        interfaces: &'static [CK_INTERFACE],
    ) -> CK_RV {
        unsafe {
            if pp_interface.is_null() {
                return CKR_ARGUMENTS_BAD.into();
            }
            for iface in interfaces {
                if !p_interface_name.is_null() {
                    let requested = std::ffi::CStr::from_ptr(p_interface_name as *const std::ffi::c_char);
                    let this_name =
                        std::ffi::CStr::from_ptr(iface.pInterfaceName as *const std::ffi::c_char);
                    if requested != this_name {
                        continue;
                    }
                }
                if !p_version.is_null() {
                    let actual: CK_VERSION = std::ptr::read(iface.pFunctionList as *const CK_VERSION);
                    let requested = &*p_version;
                    if actual.major != requested.major || actual.minor != requested.minor {
                        continue;
                    }
                }
                *pp_interface = iface as *const CK_INTERFACE as CK_INTERFACE_PTR;
                return CKR_OK.into();
            }
            CKR_ARGUMENTS_BAD.into()
        }
    }

    pub unsafe fn get_slot_list(
        &self,
        token_present: CK_BBOOL,
        p_slot_list: CK_SLOT_ID_PTR,
        pul_count: CK_ULONG_PTR,
    ) -> CK_RV {
        unsafe {
            let mut guard = self.state.lock();
            let state = match guard.as_mut() {
                Some(s) => s,
                None => return CKR_CRYPTOKI_NOT_INITIALIZED.into(),
            };
            if pul_count.is_null() {
                return CKR_ARGUMENTS_BAD.into();
            }
            if let Err(rv) = B::refresh_slots(state) {
                return rv;
            }

            let mut slot_ids: Vec<CK_SLOT_ID> = Vec::new();
            for (i, slot_arc) in state.slots.iter().enumerate() {
                if token_present != 0 {
                    let slot = slot_arc.lock();
                    if !B::is_present(&slot.data) {
                        continue;
                    }
                }
                slot_ids.push(i as CK_SLOT_ID);
            }

            let count = slot_ids.len() as CK_ULONG;
            if p_slot_list.is_null() {
                *pul_count = count;
                return CKR_OK.into();
            }
            if *pul_count < count {
                *pul_count = count;
                return CKR_BUFFER_TOO_SMALL.into();
            }
            for (i, id) in slot_ids.iter().enumerate() {
                *p_slot_list.add(i) = *id;
            }
            *pul_count = count;
            CKR_OK.into()
        }
    }

    pub unsafe fn get_slot_info(&self, slot_id: CK_SLOT_ID, p_info: CK_SLOT_INFO_PTR) -> CK_RV {
        unsafe {
            let guard = self.state.lock();
            let state = match guard.as_ref() {
                Some(s) => s,
                None => return CKR_CRYPTOKI_NOT_INITIALIZED.into(),
            };
            if p_info.is_null() {
                return CKR_ARGUMENTS_BAD.into();
            }
            let slot = match Self::slot_arc(state, slot_id) {
                Ok(s) => s,
                Err(rv) => return rv,
            };
            let slot = slot.lock();
            let sinfo = B::slot_info(slot_id, &slot.data);

            let info = &mut *p_info;
            str_pad(&mut info.slotDescription, &sinfo.description);
            str_pad(&mut info.manufacturerID, &sinfo.manufacturer_id);
            info.hardwareVersion.major = sinfo.hardware_version.0;
            info.hardwareVersion.minor = sinfo.hardware_version.1;
            info.firmwareVersion.major = sinfo.firmware_version.0;
            info.firmwareVersion.minor = sinfo.firmware_version.1;
            info.flags = CKF_HW_SLOT as CK_FLAGS | CKF_REMOVABLE_DEVICE as CK_FLAGS;
            if B::is_present(&slot.data) {
                info.flags |= CKF_TOKEN_PRESENT as CK_FLAGS;
            }
            CKR_OK.into()
        }
    }

    pub unsafe fn get_mechanism_list(
        &self,
        slot_id: CK_SLOT_ID,
        p_mechanism_list: CK_MECHANISM_TYPE_PTR,
        pul_count: CK_ULONG_PTR,
    ) -> CK_RV {
        unsafe {
            let guard = self.state.lock();
            let state = match guard.as_ref() {
                Some(s) => s,
                None => return CKR_CRYPTOKI_NOT_INITIALIZED.into(),
            };
            if pul_count.is_null() {
                return CKR_ARGUMENTS_BAD.into();
            }
            let slot = match Self::slot_arc(state, slot_id) {
                Ok(s) => s,
                Err(rv) => return rv,
            };
            let slot = slot.lock();
            if !B::is_present(&slot.data) {
                return CKR_TOKEN_NOT_PRESENT.into();
            }
            let mechanisms = B::mechanism_list(&slot.data);

            let count = mechanisms.len() as CK_ULONG;
            if p_mechanism_list.is_null() {
                *pul_count = count;
                return CKR_OK.into();
            }
            if *pul_count < count {
                *pul_count = count;
                return CKR_BUFFER_TOO_SMALL.into();
            }
            for (i, m) in mechanisms.iter().enumerate() {
                *p_mechanism_list.add(i) = *m;
            }
            *pul_count = count;
            CKR_OK.into()
        }
    }

    pub unsafe fn get_mechanism_info(
        &self,
        slot_id: CK_SLOT_ID,
        mechanism_type: CK_MECHANISM_TYPE,
        p_info: CK_MECHANISM_INFO_PTR,
    ) -> CK_RV {
        unsafe {
            let guard = self.state.lock();
            let state = match guard.as_ref() {
                Some(s) => s,
                None => return CKR_CRYPTOKI_NOT_INITIALIZED.into(),
            };
            if p_info.is_null() {
                return CKR_ARGUMENTS_BAD.into();
            }
            let slot = match Self::slot_arc(state, slot_id) {
                Ok(s) => s,
                Err(rv) => return rv,
            };
            let slot = slot.lock();
            if !B::is_present(&slot.data) {
                return CKR_TOKEN_NOT_PRESENT.into();
            }
            let info = match B::mechanism_info(&slot.data, mechanism_type) {
                Some(i) => i,
                None => return CKR_MECHANISM_INVALID.into(),
            };

            let out = &mut *p_info;
            out.ulMinKeySize = info.min_key_size;
            out.ulMaxKeySize = info.max_key_size;
            out.flags = info.flags;
            CKR_OK.into()
        }
    }

    pub unsafe fn get_token_info(&self, slot_id: CK_SLOT_ID, p_info: CK_TOKEN_INFO_PTR) -> CK_RV {
        unsafe {
            let guard = self.state.lock();
            let state = match guard.as_ref() {
                Some(s) => s,
                None => return CKR_CRYPTOKI_NOT_INITIALIZED.into(),
            };
            if p_info.is_null() {
                return CKR_ARGUMENTS_BAD.into();
            }
            let slot = match Self::slot_arc(state, slot_id) {
                Ok(s) => s,
                Err(rv) => return rv,
            };
            drop(guard);

            let mut slot = slot.lock();
            let max_sessions = B::max_sessions(&slot.data);
            let tinfo = match B::token_info(&mut slot.data) {
                Some(t) => t,
                None => return CKR_TOKEN_NOT_PRESENT.into(),
            };

            let info = &mut *p_info;
            *info = std::mem::zeroed();
            str_pad(&mut info.label, &tinfo.label);
            str_pad(&mut info.manufacturerID, &tinfo.manufacturer_id);
            str_pad(&mut info.model, &tinfo.model);
            str_pad(&mut info.serialNumber, &tinfo.serial_number);
            str_pad(&mut info.utcTime, "");

            info.flags = CKF_RNG as CK_FLAGS
                | CKF_LOGIN_REQUIRED as CK_FLAGS
                | CKF_USER_PIN_INITIALIZED as CK_FLAGS
                | CKF_TOKEN_INITIALIZED as CK_FLAGS
                | tinfo.extra_flags;

            let max = max_sessions
                .map(|n| n as CK_ULONG)
                .unwrap_or(CK_EFFECTIVELY_INFINITE.into());
            info.ulMaxSessionCount = max;
            info.ulMaxRwSessionCount = max;
            for session in slot.sessions.values() {
                if (session.flags & CKF_RW_SESSION as CK_FLAGS) != 0 {
                    info.ulRwSessionCount += 1;
                } else {
                    info.ulSessionCount += 1;
                }
            }
            info.ulMinPinLen = tinfo.min_pin_len;
            info.ulMaxPinLen = tinfo.max_pin_len;
            info.ulTotalPublicMemory = CK_UNAVAILABLE_INFORMATION as CK_ULONG;
            info.ulFreePublicMemory = CK_UNAVAILABLE_INFORMATION as CK_ULONG;
            info.ulTotalPrivateMemory = CK_UNAVAILABLE_INFORMATION as CK_ULONG;
            info.ulFreePrivateMemory = CK_UNAVAILABLE_INFORMATION as CK_ULONG;
            info.hardwareVersion.major = tinfo.hardware_version.0;
            info.hardwareVersion.minor = tinfo.hardware_version.1;
            info.firmwareVersion.major = tinfo.firmware_version.0;
            info.firmwareVersion.minor = tinfo.firmware_version.1;

            CKR_OK.into()
        }
    }

    pub unsafe fn open_session(
        &self,
        slot_id: CK_SLOT_ID,
        flags: CK_FLAGS,
        _p_application: CK_VOID_PTR,
        _notify: CK_NOTIFY,
        p_session: CK_SESSION_HANDLE_PTR,
    ) -> CK_RV {
        unsafe {
            let mut guard = self.state.lock();
            let state = match guard.as_mut() {
                Some(s) => s,
                None => return CKR_CRYPTOKI_NOT_INITIALIZED.into(),
            };
            if p_session.is_null() {
                return CKR_ARGUMENTS_BAD.into();
            }
            if (flags & CKF_SERIAL_SESSION as CK_FLAGS) == 0 {
                return CKR_SESSION_PARALLEL_NOT_SUPPORTED.into();
            }
            let slot = match Self::slot_arc(state, slot_id) {
                Ok(s) => s,
                Err(rv) => return rv,
            };
            let mut slot_guard = slot.lock();
            if !B::is_present(&slot_guard.data) {
                return CKR_TOKEN_NOT_PRESENT.into();
            }
            if let Some(max) = B::max_sessions(&slot_guard.data) {
                if slot_guard.sessions.len() >= max {
                    return CKR_SESSION_COUNT.into();
                }
            }

            let handle = state.next_session_handle;
            state.next_session_handle += 1;
            state.session_to_slot.insert(handle, slot_id);

            let data = B::new_session_data(&mut slot_guard.data, handle, flags);
            slot_guard.sessions.insert(
                handle,
                Session {
                    handle,
                    flags,
                    find_op: FindOp::default(),
                    digest_op: None,
                    sign_op: SignOp::default(),
                    verify_op: VerifyOp::default(),
                    encrypt_op: EncryptOp::default(),
                    decrypt_op: DecryptOp::default(),
                    data,
                },
            );

            *p_session = handle;
            CKR_OK.into()
        }
    }

    pub unsafe fn close_session(&self, h_session: CK_SESSION_HANDLE) -> CK_RV {
        let mut guard = self.state.lock();
        let state = match guard.as_mut() {
            Some(s) => s,
            None => return CKR_CRYPTOKI_NOT_INITIALIZED.into(),
        };
        let slot_id = match state.session_to_slot.remove(&h_session) {
            Some(id) => id,
            None => return CKR_SESSION_HANDLE_INVALID.into(),
        };
        let slot = state.slots[slot_id as usize].clone();
        let mut slot_guard = slot.lock();
        slot_guard.sessions.remove(&h_session);
        if slot_guard.sessions.is_empty() {
            let _ = B::logout(&mut slot_guard);
            slot_guard.login_state = LoginState::Public;
        }
        CKR_OK.into()
    }

    pub unsafe fn close_all_sessions(&self, slot_id: CK_SLOT_ID) -> CK_RV {
        let mut guard = self.state.lock();
        let state = match guard.as_mut() {
            Some(s) => s,
            None => return CKR_CRYPTOKI_NOT_INITIALIZED.into(),
        };
        let slot = match Self::slot_arc(state, slot_id) {
            Ok(s) => s,
            Err(rv) => return rv,
        };
        let mut slot_guard = slot.lock();
        let handles: Vec<CK_SESSION_HANDLE> = slot_guard.sessions.keys().copied().collect();
        for h in &handles {
            state.session_to_slot.remove(h);
        }
        slot_guard.sessions.clear();
        let _ = B::logout(&mut slot_guard);
        slot_guard.login_state = LoginState::Public;
        CKR_OK.into()
    }

    pub unsafe fn get_session_info(
        &self,
        h_session: CK_SESSION_HANDLE,
        p_info: CK_SESSION_INFO_PTR,
    ) -> CK_RV {
        unsafe {
            let guard = self.state.lock();
            let state = match guard.as_ref() {
                Some(s) => s,
                None => return CKR_CRYPTOKI_NOT_INITIALIZED.into(),
            };
            if p_info.is_null() {
                return CKR_ARGUMENTS_BAD.into();
            }
            let slot_id = match state.session_to_slot.get(&h_session) {
                Some(id) => *id,
                None => return CKR_SESSION_HANDLE_INVALID.into(),
            };
            let slot = state.slots[slot_id as usize].lock();
            let session = match slot.sessions.get(&h_session) {
                Some(s) => s,
                None => return CKR_SESSION_HANDLE_INVALID.into(),
            };
            let info = &mut *p_info;
            info.slotID = slot_id;
            info.flags = session.flags;
            info.state = compute_state(slot.login_state, session.flags);
            info.ulDeviceError = 0;
            CKR_OK.into()
        }
    }

    pub unsafe fn login(
        &self,
        h_session: CK_SESSION_HANDLE,
        user_type: CK_USER_TYPE,
        p_pin: CK_UTF8CHAR_PTR,
        ul_pin_len: CK_ULONG,
        p_username: CK_UTF8CHAR_PTR,
        ul_username_len: CK_ULONG,
    ) -> CK_RV {
        unsafe {
            let mut guard = self.state.lock();
            let state = match guard.as_mut() {
                Some(s) => s,
                None => return CKR_CRYPTOKI_NOT_INITIALIZED.into(),
            };
            let slot_id = match state.session_to_slot.get(&h_session) {
                Some(id) => *id,
                None => return CKR_SESSION_HANDLE_INVALID.into(),
            };
            let slot = state.slots[slot_id as usize].clone();
            let mut slot_guard = slot.lock();
            if !B::is_present(&slot_guard.data) {
                return CKR_TOKEN_NOT_PRESENT.into();
            }

            let pin: &[u8] = if p_pin.is_null() || ul_pin_len == 0 {
                &[]
            } else {
                std::slice::from_raw_parts(p_pin as *const u8, ul_pin_len as usize)
            };
            let username: &[u8] = if p_username.is_null() || ul_username_len == 0 {
                &[]
            } else {
                std::slice::from_raw_parts(p_username as *const u8, ul_username_len as usize)
            };

            match B::login(&mut slot_guard, h_session, user_type, pin, username) {
                Ok(()) => CKR_OK.into(),
                Err(rv) => rv,
            }
        }
    }

    pub unsafe fn logout(&self, h_session: CK_SESSION_HANDLE) -> CK_RV {
        let mut guard = self.state.lock();
        let state = match guard.as_mut() {
            Some(s) => s,
            None => return CKR_CRYPTOKI_NOT_INITIALIZED.into(),
        };
        let slot_id = match state.session_to_slot.get(&h_session) {
            Some(id) => *id,
            None => return CKR_SESSION_HANDLE_INVALID.into(),
        };
        let slot = state.slots[slot_id as usize].clone();
        let mut slot_guard = slot.lock();
        if !B::is_present(&slot_guard.data) {
            return CKR_TOKEN_NOT_PRESENT.into();
        }
        match B::logout(&mut slot_guard) {
            Ok(()) => CKR_OK.into(),
            Err(rv) => rv,
        }
    }

    pub unsafe fn generate_random(
        &self,
        h_session: CK_SESSION_HANDLE,
        p_random_data: CK_BYTE_PTR,
        ul_random_len: CK_ULONG,
    ) -> CK_RV {
        unsafe {
            let guard = self.state.lock();
            let state = match guard.as_ref() {
                Some(s) => s,
                None => return CKR_CRYPTOKI_NOT_INITIALIZED.into(),
            };
            let slot_id = match state.session_to_slot.get(&h_session) {
                Some(id) => *id,
                None => return CKR_SESSION_HANDLE_INVALID.into(),
            };
            let slot = state.slots[slot_id as usize].clone();
            let slot_guard = slot.lock();

            if ul_random_len == 0 {
                return CKR_OK.into();
            }
            if p_random_data.is_null() {
                return CKR_ARGUMENTS_BAD.into();
            }
            let buf =
                std::slice::from_raw_parts_mut(p_random_data as *mut u8, ul_random_len as usize);

            match B::generate_random(&slot_guard, buf) {
                Ok(()) => CKR_OK.into(),
                Err(rv) => rv,
            }
        }
    }

    pub unsafe fn seed_random(
        &self,
        h_session: CK_SESSION_HANDLE,
        p_seed: CK_BYTE_PTR,
        ul_seed_len: CK_ULONG,
    ) -> CK_RV {
        unsafe {
            let guard = self.state.lock();
            let state = match guard.as_ref() {
                Some(s) => s,
                None => return CKR_CRYPTOKI_NOT_INITIALIZED.into(),
            };
            let slot_id = match state.session_to_slot.get(&h_session) {
                Some(id) => *id,
                None => return CKR_SESSION_HANDLE_INVALID.into(),
            };
            let slot = state.slots[slot_id as usize].clone();
            let slot_guard = slot.lock();

            if p_seed.is_null() && ul_seed_len != 0 {
                return CKR_ARGUMENTS_BAD.into();
            }
            let seed: &[u8] = if p_seed.is_null() || ul_seed_len == 0 {
                &[]
            } else {
                std::slice::from_raw_parts(p_seed as *const u8, ul_seed_len as usize)
            };

            match B::seed_random(&slot_guard, seed) {
                Ok(()) => CKR_OK.into(),
                Err(rv) => rv,
            }
        }
    }

    pub unsafe fn find_objects_init(
        &self,
        h_session: CK_SESSION_HANDLE,
        p_template: CK_ATTRIBUTE_PTR,
        ul_count: CK_ULONG,
    ) -> CK_RV {
        unsafe {
            let mut guard = self.state.lock();
            let state = match guard.as_mut() {
                Some(s) => s,
                None => return CKR_CRYPTOKI_NOT_INITIALIZED.into(),
            };
            let slot_id = match state.session_to_slot.get(&h_session) {
                Some(id) => *id,
                None => return CKR_SESSION_HANDLE_INVALID.into(),
            };
            let slot = state.slots[slot_id as usize].clone();
            let mut slot_guard = slot.lock();
            if !slot_guard.sessions.contains_key(&h_session) {
                return CKR_SESSION_HANDLE_INVALID.into();
            }
            if slot_guard.sessions[&h_session].find_op.active {
                return CKR_OPERATION_ACTIVE.into();
            }
            if ul_count > 0 && p_template.is_null() {
                return CKR_ARGUMENTS_BAD.into();
            }

            let template: &[CK_ATTRIBUTE] = if ul_count == 0 {
                &[]
            } else {
                std::slice::from_raw_parts(p_template, ul_count as usize)
            };

            let handles = B::object_handles(&slot_guard);
            let mut matches = Vec::new();
            'outer: for h in handles {
                for attr in template {
                    let value: &[u8] = if attr.pValue.is_null() || attr.ulValueLen == 0 {
                        &[]
                    } else {
                        std::slice::from_raw_parts(
                            attr.pValue as *const u8,
                            attr.ulValueLen as usize,
                        )
                    };

                    match B::get_one_attribute_value(&slot_guard.data, h, attr.type_) {
                        Some(actual) if actual == value => {}
                        _ => continue 'outer,
                    }
                }
                matches.push(h);
            }

            let session = slot_guard.sessions.get_mut(&h_session).unwrap();
            session.find_op = FindOp {
                active: true,
                matches,
                returned_offset: 0,
            };
            CKR_OK.into()
        }
    }

    pub unsafe fn find_objects(
        &self,
        h_session: CK_SESSION_HANDLE,
        p_object: CK_OBJECT_HANDLE_PTR,
        ul_max_object_count: CK_ULONG,
        pul_object_count: CK_ULONG_PTR,
    ) -> CK_RV {
        unsafe {
            let mut guard = self.state.lock();
            let state = match guard.as_mut() {
                Some(s) => s,
                None => return CKR_CRYPTOKI_NOT_INITIALIZED.into(),
            };
            let slot_id = match state.session_to_slot.get(&h_session) {
                Some(id) => *id,
                None => return CKR_SESSION_HANDLE_INVALID.into(),
            };
            let slot = state.slots[slot_id as usize].clone();
            let mut slot_guard = slot.lock();
            let session = match slot_guard.sessions.get_mut(&h_session) {
                Some(s) => s,
                None => return CKR_SESSION_HANDLE_INVALID.into(),
            };
            if !session.find_op.active {
                return CKR_OPERATION_NOT_INITIALIZED.into();
            }
            if p_object.is_null() || pul_object_count.is_null() {
                return CKR_ARGUMENTS_BAD.into();
            }

            let remaining = &session.find_op.matches[session.find_op.returned_offset..];
            let n = remaining.len().min(ul_max_object_count as usize);
            for (i, h) in remaining[..n].iter().enumerate() {
                *p_object.add(i) = *h;
            }
            session.find_op.returned_offset += n;
            *pul_object_count = n as CK_ULONG;
            CKR_OK.into()
        }
    }

    pub unsafe fn find_objects_final(&self, h_session: CK_SESSION_HANDLE) -> CK_RV {
        let mut guard = self.state.lock();
        let state = match guard.as_mut() {
            Some(s) => s,
            None => return CKR_CRYPTOKI_NOT_INITIALIZED.into(),
        };
        let slot_id = match state.session_to_slot.get(&h_session) {
            Some(id) => *id,
            None => return CKR_SESSION_HANDLE_INVALID.into(),
        };
        let slot = state.slots[slot_id as usize].clone();
        let mut slot_guard = slot.lock();
        let session = match slot_guard.sessions.get_mut(&h_session) {
            Some(s) => s,
            None => return CKR_SESSION_HANDLE_INVALID.into(),
        };
        if !session.find_op.active {
            return CKR_OPERATION_NOT_INITIALIZED.into();
        }
        session.find_op = FindOp::default();
        CKR_OK.into()
    }

    pub unsafe fn get_attribute_value(
        &self,
        h_session: CK_SESSION_HANDLE,
        h_object: CK_OBJECT_HANDLE,
        p_template: CK_ATTRIBUTE_PTR,
        ul_count: CK_ULONG,
    ) -> CK_RV {
        unsafe {
            let guard = self.state.lock();
            let state = match guard.as_ref() {
                Some(s) => s,
                None => return CKR_CRYPTOKI_NOT_INITIALIZED.into(),
            };
            let slot_id = match state.session_to_slot.get(&h_session) {
                Some(id) => *id,
                None => return CKR_SESSION_HANDLE_INVALID.into(),
            };
            let slot = state.slots[slot_id as usize].clone();
            let slot_guard = slot.lock();
            if !slot_guard.sessions.contains_key(&h_session) {
                return CKR_SESSION_HANDLE_INVALID.into();
            }
            if p_template.is_null() {
                return CKR_ARGUMENTS_BAD.into();
            }
            if !B::object_handles(&slot_guard).contains(&h_object) {
                return CKR_OBJECT_HANDLE_INVALID.into();
            }

            let template = std::slice::from_raw_parts_mut(p_template, ul_count as usize);
            let mut any_invalid = false;
            let mut any_too_small = false;
            for attr in template.iter_mut() {
                match B::get_one_attribute_value(&slot_guard.data, h_object, attr.type_) {
                    None => {
                        attr.ulValueLen = CK_UNAVAILABLE_INFORMATION as CK_ULONG;
                        any_invalid = true;
                    }
                    Some(value) => {
                        if attr.pValue.is_null() {
                            attr.ulValueLen = value.len() as CK_ULONG;
                        } else if (attr.ulValueLen as usize) < value.len() {
                            attr.ulValueLen = CKR_BUFFER_TOO_SMALL as CK_ULONG;
                            any_too_small = true;
                        } else {
                            std::ptr::copy_nonoverlapping(
                                value.as_ptr(),
                                attr.pValue as *mut u8,
                                value.len(),
                            );
                            attr.ulValueLen = value.len() as CK_ULONG;
                        }
                    }
                }
            }

            if any_invalid {
                CKR_ATTRIBUTE_TYPE_INVALID.into()
            } else if any_too_small {
                CKR_BUFFER_TOO_SMALL.into()
            } else {
                CKR_OK.into()
            }
        }
    }

    /// Returns the byte length of this object's underlying raw storage,
    /// equivalent to `get_data_len`
    ///
    /// No per-backend logic needed, since it calls `object_handles`/
    /// `get_one_attribute_value` which are implemented in the backend
      pub unsafe fn get_object_size(
        &self,
        h_session: CK_SESSION_HANDLE,
        h_object: CK_OBJECT_HANDLE,
        pul_size: CK_ULONG_PTR,
    ) -> CK_RV {
        unsafe {
            let guard = self.state.lock();
            let state = match guard.as_ref() {
                Some(s) => s,
                None => return CKR_CRYPTOKI_NOT_INITIALIZED.into(),
            };
            let slot_id = match state.session_to_slot.get(&h_session) {
                Some(id) => *id,
                None => return CKR_SESSION_HANDLE_INVALID.into(),
            };
            let slot = state.slots[slot_id as usize].clone();
            let slot_guard = slot.lock();
            if !slot_guard.sessions.contains_key(&h_session) {
                return CKR_SESSION_HANDLE_INVALID.into();
            }
            if pul_size.is_null() {
                return CKR_ARGUMENTS_BAD.into();
            }
            if !B::object_handles(&slot_guard).contains(&h_object) {
                return CKR_OBJECT_HANDLE_INVALID.into();
            }

            let attr = |attr_type: u32| {
                B::get_one_attribute_value(&slot_guard.data, h_object, attr_type as CK_ATTRIBUTE_TYPE)
            };

            let size = attr(CKA_VALUE).map(|v| v.len()).or_else(|| {
                let key_type = CK_ULONG::from_ne_bytes(attr(CKA_KEY_TYPE)?.try_into().ok()?);
                match key_type as u32 {
                    CKK_RSA => attr(CKA_MODULUS).map(|v| v.len()),
                    CKK_EC | CKK_EC_EDWARDS | CKK_EC_MONTGOMERY => attr(CKA_EC_POINT).map(|v| v.len()),
                    _ => None,
                }
            });
            *pul_size = size.unwrap_or(0) as CK_ULONG;
            CKR_OK.into()
        }
    }

    pub unsafe fn digest_init(
        &self,
        h_session: CK_SESSION_HANDLE,
        p_mechanism: CK_MECHANISM_PTR,
    ) -> CK_RV {
        unsafe {
            let mut guard = self.state.lock();
            let state = match guard.as_mut() {
                Some(s) => s,
                None => return CKR_CRYPTOKI_NOT_INITIALIZED.into(),
            };
            let slot_id = match state.session_to_slot.get(&h_session) {
                Some(id) => *id,
                None => return CKR_SESSION_HANDLE_INVALID.into(),
            };
            let slot = state.slots[slot_id as usize].clone();
            let mut slot_guard = slot.lock();
            let session = match slot_guard.sessions.get_mut(&h_session) {
                Some(s) => s,
                None => return CKR_SESSION_HANDLE_INVALID.into(),
            };
            if session.digest_op.is_some() {
                return CKR_OPERATION_ACTIVE.into();
            }
            if p_mechanism.is_null() {
                return CKR_ARGUMENTS_BAD.into();
            }

            let mechanism = (*p_mechanism).mechanism;
            let parameter = if (*p_mechanism).pParameter.is_null() {
                &[][..]
            } else {
                std::slice::from_raw_parts(
                    (*p_mechanism).pParameter as *const u8,
                    (*p_mechanism).ulParameterLen as usize,
                )
            };

            // The backend gets first refusal; only if it declines do we fall
            // back to the generic fixed-output mechanisms.
            let op = match B::digest_init(&mut slot_guard, h_session, mechanism, parameter) {
                Ok(Some(op)) => op,
                Ok(None) => match DigestOp::new(mechanism) {
                    Ok(op) => op,
                    Err(rv) => return rv,
                },
                Err(rv) => return rv,
            };
            let session = slot_guard.sessions.get_mut(&h_session).unwrap();
            session.digest_op = Some(op);
            CKR_OK.into()
        }
    }

    /// Performs digest, equivalent to `C_DigestUpdate` immediately followed by
    /// `C_DigestFinal`
    pub unsafe fn digest(
        &self,
        h_session: CK_SESSION_HANDLE,
        p_data: CK_BYTE_PTR,
        ul_data_len: CK_ULONG,
        p_digest: CK_BYTE_PTR,
        pul_digest_len: CK_ULONG_PTR,
    ) -> CK_RV {
        unsafe {
            let mut guard = self.state.lock();
            let state = match guard.as_mut() {
                Some(s) => s,
                None => return CKR_CRYPTOKI_NOT_INITIALIZED.into(),
            };
            let slot_id = match state.session_to_slot.get(&h_session) {
                Some(id) => *id,
                None => return CKR_SESSION_HANDLE_INVALID.into(),
            };
            let slot = state.slots[slot_id as usize].clone();
            let mut slot_guard = slot.lock();
            let session = match slot_guard.sessions.get_mut(&h_session) {
                Some(s) => s,
                None => return CKR_SESSION_HANDLE_INVALID.into(),
            };
            if session.digest_op.is_none() {
                return CKR_OPERATION_NOT_INITIALIZED.into();
            }
            if pul_digest_len.is_null() {
                return CKR_ARGUMENTS_BAD.into();
            }

            let out_len = session.digest_op.as_ref().unwrap().output_len();

            if p_digest.is_null() {
                *pul_digest_len = out_len as CK_ULONG;
                return CKR_OK.into();
            }
            if (*pul_digest_len as usize) < out_len {
                *pul_digest_len = out_len as CK_ULONG;
                return CKR_BUFFER_TOO_SMALL.into();
            }
            if ul_data_len > 0 && p_data.is_null() {
                return CKR_ARGUMENTS_BAD.into();
            }

            let data: &[u8] = if ul_data_len == 0 {
                &[]
            } else {
                std::slice::from_raw_parts(p_data as *const u8, ul_data_len as usize)
            };
            let mut op = session.digest_op.take().unwrap();
            op.update(data);
            let digest = op.finalize();
            std::ptr::copy_nonoverlapping(digest.as_ptr(), p_digest, digest.len());
            *pul_digest_len = digest.len() as CK_ULONG;
            CKR_OK.into()
        }
    }

    pub unsafe fn digest_update(
        &self,
        h_session: CK_SESSION_HANDLE,
        p_part: CK_BYTE_PTR,
        ul_part_len: CK_ULONG,
    ) -> CK_RV {
        unsafe {
            let mut guard = self.state.lock();
            let state = match guard.as_mut() {
                Some(s) => s,
                None => return CKR_CRYPTOKI_NOT_INITIALIZED.into(),
            };
            let slot_id = match state.session_to_slot.get(&h_session) {
                Some(id) => *id,
                None => return CKR_SESSION_HANDLE_INVALID.into(),
            };
            let slot = state.slots[slot_id as usize].clone();
            let mut slot_guard = slot.lock();
            let session = match slot_guard.sessions.get_mut(&h_session) {
                Some(s) => s,
                None => return CKR_SESSION_HANDLE_INVALID.into(),
            };
            let Some(digest_op) = session.digest_op.as_mut() else {
                return CKR_OPERATION_NOT_INITIALIZED.into();
            };
            if ul_part_len > 0 && p_part.is_null() {
                return CKR_ARGUMENTS_BAD.into();
            }

            let data: &[u8] = if ul_part_len == 0 {
                &[]
            } else {
                std::slice::from_raw_parts(p_part as *const u8, ul_part_len as usize)
            };
            digest_op.update(data);
            CKR_OK.into()
        }
    }

    pub unsafe fn digest_final(
        &self,
        h_session: CK_SESSION_HANDLE,
        p_digest: CK_BYTE_PTR,
        pul_digest_len: CK_ULONG_PTR,
    ) -> CK_RV {
        unsafe {
            let mut guard = self.state.lock();
            let state = match guard.as_mut() {
                Some(s) => s,
                None => return CKR_CRYPTOKI_NOT_INITIALIZED.into(),
            };
            let slot_id = match state.session_to_slot.get(&h_session) {
                Some(id) => *id,
                None => return CKR_SESSION_HANDLE_INVALID.into(),
            };
            let slot = state.slots[slot_id as usize].clone();
            let mut slot_guard = slot.lock();
            let session = match slot_guard.sessions.get_mut(&h_session) {
                Some(s) => s,
                None => return CKR_SESSION_HANDLE_INVALID.into(),
            };
            if session.digest_op.is_none() {
                return CKR_OPERATION_NOT_INITIALIZED.into();
            }
            if pul_digest_len.is_null() {
                return CKR_ARGUMENTS_BAD.into();
            }

            let out_len = session.digest_op.as_ref().unwrap().output_len();

            if p_digest.is_null() {
                *pul_digest_len = out_len as CK_ULONG;
                return CKR_OK.into();
            }
            if (*pul_digest_len as usize) < out_len {
                *pul_digest_len = out_len as CK_ULONG;
                return CKR_BUFFER_TOO_SMALL.into();
            }

            let op = session.digest_op.take().unwrap();
            let digest = op.finalize();
            std::ptr::copy_nonoverlapping(digest.as_ptr(), p_digest, digest.len());
            *pul_digest_len = digest.len() as CK_ULONG;
            CKR_OK.into()
        }
    }

    pub unsafe fn sign_init(
        &self,
        h_session: CK_SESSION_HANDLE,
        p_mechanism: CK_MECHANISM_PTR,
        h_key: CK_OBJECT_HANDLE,
    ) -> CK_RV {
        unsafe {
            let mut guard = self.state.lock();
            let state = match guard.as_mut() {
                Some(s) => s,
                None => return CKR_CRYPTOKI_NOT_INITIALIZED.into(),
            };
            let slot_id = match state.session_to_slot.get(&h_session) {
                Some(id) => *id,
                None => return CKR_SESSION_HANDLE_INVALID.into(),
            };
            let slot = state.slots[slot_id as usize].clone();
            let mut slot_guard = slot.lock();
            let session = match slot_guard.sessions.get(&h_session) {
                Some(s) => s,
                None => return CKR_SESSION_HANDLE_INVALID.into(),
            };
            if session.sign_op.active {
                return CKR_OPERATION_ACTIVE.into();
            }
            if p_mechanism.is_null() {
                return CKR_ARGUMENTS_BAD.into();
            }

            let mechanism = (*p_mechanism).mechanism;
            let parameter: &[u8] = if (*p_mechanism).pParameter.is_null()
                || (*p_mechanism).ulParameterLen == 0
            {
                &[]
            } else {
                std::slice::from_raw_parts(
                    (*p_mechanism).pParameter as *const u8,
                    (*p_mechanism).ulParameterLen as usize,
                )
            };
            match B::sign_init(&mut slot_guard, h_session, mechanism, parameter, h_key) {
                Ok(out_len) => {
                    let session = slot_guard.sessions.get_mut(&h_session).unwrap();
                    session.sign_op = SignOp {
                        active: true,
                        out_len,
                    };
                    CKR_OK.into()
                }
                Err(rv) => rv,
            }
        }
    }

    /// Performs signing, equivalent to `C_SignUpdate` immediately followed
    /// by `C_SignFinal`
    pub unsafe fn sign(
        &self,
        h_session: CK_SESSION_HANDLE,
        p_data: CK_BYTE_PTR,
        ul_data_len: CK_ULONG,
        p_signature: CK_BYTE_PTR,
        pul_signature_len: CK_ULONG_PTR,
    ) -> CK_RV {
        unsafe {
            let mut guard = self.state.lock();
            let state = match guard.as_mut() {
                Some(s) => s,
                None => return CKR_CRYPTOKI_NOT_INITIALIZED.into(),
            };
            let slot_id = match state.session_to_slot.get(&h_session) {
                Some(id) => *id,
                None => return CKR_SESSION_HANDLE_INVALID.into(),
            };
            let slot = state.slots[slot_id as usize].clone();
            let mut slot_guard = slot.lock();
            let session = match slot_guard.sessions.get(&h_session) {
                Some(s) => s,
                None => return CKR_SESSION_HANDLE_INVALID.into(),
            };
            if !session.sign_op.active {
                return CKR_OPERATION_NOT_INITIALIZED.into();
            }
            if p_data.is_null() || pul_signature_len.is_null() {
                return CKR_ARGUMENTS_BAD.into();
            }

            let out_len = session.sign_op.out_len;

            if p_signature.is_null() {
                *pul_signature_len = out_len;
                return CKR_OK.into();
            }
            if *pul_signature_len < out_len {
                *pul_signature_len = out_len;
                return CKR_BUFFER_TOO_SMALL.into();
            }
            if slot_guard.login_state == LoginState::Public {
                slot_guard.sessions.get_mut(&h_session).unwrap().sign_op = SignOp::default();
                return CKR_USER_NOT_LOGGED_IN.into();
            }

            let data: &[u8] = if ul_data_len == 0 {
                &[]
            } else {
                std::slice::from_raw_parts(p_data as *const u8, ul_data_len as usize)
            };
            let result = B::sign_update(&mut slot_guard, h_session, data)
                .and_then(|()| B::sign_final(&mut slot_guard, h_session));
            slot_guard.sessions.get_mut(&h_session).unwrap().sign_op = SignOp::default();

            match result {
                Ok(signature) => {
                    std::ptr::copy_nonoverlapping(
                        signature.as_ptr(),
                        p_signature,
                        signature.len(),
                    );
                    *pul_signature_len = signature.len() as CK_ULONG;
                    CKR_OK.into()
                }
                Err(rv) => rv,
            }
        }
    }

    pub unsafe fn sign_update(
        &self,
        h_session: CK_SESSION_HANDLE,
        p_part: CK_BYTE_PTR,
        ul_part_len: CK_ULONG,
    ) -> CK_RV {
        unsafe {
            let mut guard = self.state.lock();
            let state = match guard.as_mut() {
                Some(s) => s,
                None => return CKR_CRYPTOKI_NOT_INITIALIZED.into(),
            };
            let slot_id = match state.session_to_slot.get(&h_session) {
                Some(id) => *id,
                None => return CKR_SESSION_HANDLE_INVALID.into(),
            };
            let slot = state.slots[slot_id as usize].clone();
            let mut slot_guard = slot.lock();
            let session = match slot_guard.sessions.get(&h_session) {
                Some(s) => s,
                None => return CKR_SESSION_HANDLE_INVALID.into(),
            };
            if !session.sign_op.active {
                return CKR_OPERATION_NOT_INITIALIZED.into();
            }
            if p_part.is_null() {
                slot_guard.sessions.get_mut(&h_session).unwrap().sign_op = SignOp::default();
                return CKR_ARGUMENTS_BAD.into();
            }

            let data: &[u8] = if ul_part_len == 0 {
                &[]
            } else {
                std::slice::from_raw_parts(p_part as *const u8, ul_part_len as usize)
            };
            match B::sign_update(&mut slot_guard, h_session, data) {
                Ok(()) => CKR_OK.into(),
                Err(rv) => {
                    slot_guard.sessions.get_mut(&h_session).unwrap().sign_op = SignOp::default();
                    rv
                }
            }
        }
    }

    pub unsafe fn sign_final(
        &self,
        h_session: CK_SESSION_HANDLE,
        p_signature: CK_BYTE_PTR,
        pul_signature_len: CK_ULONG_PTR,
    ) -> CK_RV {
        unsafe {
            let mut guard = self.state.lock();
            let state = match guard.as_mut() {
                Some(s) => s,
                None => return CKR_CRYPTOKI_NOT_INITIALIZED.into(),
            };
            let slot_id = match state.session_to_slot.get(&h_session) {
                Some(id) => *id,
                None => return CKR_SESSION_HANDLE_INVALID.into(),
            };
            let slot = state.slots[slot_id as usize].clone();
            let mut slot_guard = slot.lock();
            let session = match slot_guard.sessions.get(&h_session) {
                Some(s) => s,
                None => return CKR_SESSION_HANDLE_INVALID.into(),
            };
            if !session.sign_op.active {
                return CKR_OPERATION_NOT_INITIALIZED.into();
            }
            if pul_signature_len.is_null() {
                return CKR_ARGUMENTS_BAD.into();
            }

            let out_len = session.sign_op.out_len;

            if p_signature.is_null() {
                *pul_signature_len = out_len;
                return CKR_OK.into();
            }
            if *pul_signature_len < out_len {
                *pul_signature_len = out_len;
                return CKR_BUFFER_TOO_SMALL.into();
            }
            if slot_guard.login_state == LoginState::Public {
                slot_guard.sessions.get_mut(&h_session).unwrap().sign_op = SignOp::default();
                return CKR_USER_NOT_LOGGED_IN.into();
            }

            let result = B::sign_final(&mut slot_guard, h_session);
            slot_guard.sessions.get_mut(&h_session).unwrap().sign_op = SignOp::default();

            match result {
                Ok(signature) => {
                    std::ptr::copy_nonoverlapping(
                        signature.as_ptr(),
                        p_signature,
                        signature.len(),
                    );
                    *pul_signature_len = signature.len() as CK_ULONG;
                    CKR_OK.into()
                }
                Err(rv) => rv,
            }
        }
    }

    pub unsafe fn verify_init(
        &self,
        h_session: CK_SESSION_HANDLE,
        p_mechanism: CK_MECHANISM_PTR,
        h_key: CK_OBJECT_HANDLE,
    ) -> CK_RV {
        unsafe {
            let mut guard = self.state.lock();
            let state = match guard.as_mut() {
                Some(s) => s,
                None => return CKR_CRYPTOKI_NOT_INITIALIZED.into(),
            };
            let slot_id = match state.session_to_slot.get(&h_session) {
                Some(id) => *id,
                None => return CKR_SESSION_HANDLE_INVALID.into(),
            };
            let slot = state.slots[slot_id as usize].clone();
            let mut slot_guard = slot.lock();
            let session = match slot_guard.sessions.get(&h_session) {
                Some(s) => s,
                None => return CKR_SESSION_HANDLE_INVALID.into(),
            };
            if session.verify_op.active {
                return CKR_OPERATION_ACTIVE.into();
            }
            if p_mechanism.is_null() {
                return CKR_ARGUMENTS_BAD.into();
            }

            let mechanism = (*p_mechanism).mechanism;
            let parameter: &[u8] = if (*p_mechanism).pParameter.is_null()
                || (*p_mechanism).ulParameterLen == 0
            {
                &[]
            } else {
                std::slice::from_raw_parts(
                    (*p_mechanism).pParameter as *const u8,
                    (*p_mechanism).ulParameterLen as usize,
                )
            };
            match B::verify_init(&mut slot_guard, h_session, mechanism, parameter, h_key) {
                Ok(()) => {
                    let session = slot_guard.sessions.get_mut(&h_session).unwrap();
                    session.verify_op = VerifyOp { active: true };
                    CKR_OK.into()
                }
                Err(rv) => rv,
            }
        }
    }

    /// Performs signature verification, equivalent to `C_VerifyUpdate` immediately
    /// followed by `C_VerifyFinal`
    pub unsafe fn verify(
        &self,
        h_session: CK_SESSION_HANDLE,
        p_data: CK_BYTE_PTR,
        ul_data_len: CK_ULONG,
        p_signature: CK_BYTE_PTR,
        ul_signature_len: CK_ULONG,
    ) -> CK_RV {
        unsafe {
            let mut guard = self.state.lock();
            let state = match guard.as_mut() {
                Some(s) => s,
                None => return CKR_CRYPTOKI_NOT_INITIALIZED.into(),
            };
            let slot_id = match state.session_to_slot.get(&h_session) {
                Some(id) => *id,
                None => return CKR_SESSION_HANDLE_INVALID.into(),
            };
            let slot = state.slots[slot_id as usize].clone();
            let mut slot_guard = slot.lock();
            let session = match slot_guard.sessions.get(&h_session) {
                Some(s) => s,
                None => return CKR_SESSION_HANDLE_INVALID.into(),
            };
            if !session.verify_op.active {
                return CKR_OPERATION_NOT_INITIALIZED.into();
            }
            if (ul_data_len > 0 && p_data.is_null()) || (ul_signature_len > 0 && p_signature.is_null())
            {
                slot_guard.sessions.get_mut(&h_session).unwrap().verify_op = VerifyOp::default();
                return CKR_ARGUMENTS_BAD.into();
            }

            let data: &[u8] = if ul_data_len == 0 {
                &[]
            } else {
                std::slice::from_raw_parts(p_data as *const u8, ul_data_len as usize)
            };
            let signature: &[u8] = if ul_signature_len == 0 {
                &[]
            } else {
                std::slice::from_raw_parts(p_signature as *const u8, ul_signature_len as usize)
            };
            let result = B::verify_update(&mut slot_guard, h_session, data)
                .and_then(|()| B::verify_final(&mut slot_guard, h_session, signature));
            slot_guard.sessions.get_mut(&h_session).unwrap().verify_op = VerifyOp::default();

            match result {
                Ok(()) => CKR_OK.into(),
                Err(rv) => rv,
            }
        }
    }

    pub unsafe fn verify_update(
        &self,
        h_session: CK_SESSION_HANDLE,
        p_part: CK_BYTE_PTR,
        ul_part_len: CK_ULONG,
    ) -> CK_RV {
        unsafe {
            let mut guard = self.state.lock();
            let state = match guard.as_mut() {
                Some(s) => s,
                None => return CKR_CRYPTOKI_NOT_INITIALIZED.into(),
            };
            let slot_id = match state.session_to_slot.get(&h_session) {
                Some(id) => *id,
                None => return CKR_SESSION_HANDLE_INVALID.into(),
            };
            let slot = state.slots[slot_id as usize].clone();
            let mut slot_guard = slot.lock();
            let session = match slot_guard.sessions.get(&h_session) {
                Some(s) => s,
                None => return CKR_SESSION_HANDLE_INVALID.into(),
            };
            if !session.verify_op.active {
                return CKR_OPERATION_NOT_INITIALIZED.into();
            }
            if p_part.is_null() {
                slot_guard.sessions.get_mut(&h_session).unwrap().verify_op = VerifyOp::default();
                return CKR_ARGUMENTS_BAD.into();
            }

            let data: &[u8] = if ul_part_len == 0 {
                &[]
            } else {
                std::slice::from_raw_parts(p_part as *const u8, ul_part_len as usize)
            };
            match B::verify_update(&mut slot_guard, h_session, data) {
                Ok(()) => CKR_OK.into(),
                Err(rv) => {
                    slot_guard.sessions.get_mut(&h_session).unwrap().verify_op = VerifyOp::default();
                    rv
                }
            }
        }
    }

    pub unsafe fn verify_final(
        &self,
        h_session: CK_SESSION_HANDLE,
        p_signature: CK_BYTE_PTR,
        ul_signature_len: CK_ULONG,
    ) -> CK_RV {
        unsafe {
            let mut guard = self.state.lock();
            let state = match guard.as_mut() {
                Some(s) => s,
                None => return CKR_CRYPTOKI_NOT_INITIALIZED.into(),
            };
            let slot_id = match state.session_to_slot.get(&h_session) {
                Some(id) => *id,
                None => return CKR_SESSION_HANDLE_INVALID.into(),
            };
            let slot = state.slots[slot_id as usize].clone();
            let mut slot_guard = slot.lock();
            let session = match slot_guard.sessions.get(&h_session) {
                Some(s) => s,
                None => return CKR_SESSION_HANDLE_INVALID.into(),
            };
            if !session.verify_op.active {
                return CKR_OPERATION_NOT_INITIALIZED.into();
            }
            if ul_signature_len > 0 && p_signature.is_null() {
                slot_guard.sessions.get_mut(&h_session).unwrap().verify_op = VerifyOp::default();
                return CKR_ARGUMENTS_BAD.into();
            }

            let signature: &[u8] = if ul_signature_len == 0 {
                &[]
            } else {
                std::slice::from_raw_parts(p_signature as *const u8, ul_signature_len as usize)
            };
            let result = B::verify_final(&mut slot_guard, h_session, signature);
            slot_guard.sessions.get_mut(&h_session).unwrap().verify_op = VerifyOp::default();

            match result {
                Ok(()) => CKR_OK.into(),
                Err(rv) => rv,
            }
        }
    }

    pub unsafe fn encrypt_init(
        &self,
        h_session: CK_SESSION_HANDLE,
        p_mechanism: CK_MECHANISM_PTR,
        h_key: CK_OBJECT_HANDLE,
    ) -> CK_RV {
        unsafe {
            let mut guard = self.state.lock();
            let state = match guard.as_mut() {
                Some(s) => s,
                None => return CKR_CRYPTOKI_NOT_INITIALIZED.into(),
            };
            let slot_id = match state.session_to_slot.get(&h_session) {
                Some(id) => *id,
                None => return CKR_SESSION_HANDLE_INVALID.into(),
            };
            let slot = state.slots[slot_id as usize].clone();
            let mut slot_guard = slot.lock();
            let session = match slot_guard.sessions.get(&h_session) {
                Some(s) => s,
                None => return CKR_SESSION_HANDLE_INVALID.into(),
            };
            if session.encrypt_op.active {
                return CKR_OPERATION_ACTIVE.into();
            }
            if p_mechanism.is_null() {
                return CKR_ARGUMENTS_BAD.into();
            }

            let mechanism = (*p_mechanism).mechanism;
            let parameter: &[u8] = if (*p_mechanism).pParameter.is_null()
                || (*p_mechanism).ulParameterLen == 0
            {
                &[]
            } else {
                std::slice::from_raw_parts(
                    (*p_mechanism).pParameter as *const u8,
                    (*p_mechanism).ulParameterLen as usize,
                )
            };
            match B::encrypt_init(&mut slot_guard, h_session, mechanism, parameter, h_key) {
                Ok(out_len) => {
                    let session = slot_guard.sessions.get_mut(&h_session).unwrap();
                    session.encrypt_op = EncryptOp {
                        active: true,
                        out_len,
                    };
                    CKR_OK.into()
                }
                Err(rv) => rv,
            }
        }
    }

    /// Performs RSA encryption, equivalent to `C_EncryptUpdate` immediately
    /// followed by `C_EncryptFinal`.
    pub unsafe fn encrypt(
        &self,
        h_session: CK_SESSION_HANDLE,
        p_data: CK_BYTE_PTR,
        ul_data_len: CK_ULONG,
        p_encrypted_data: CK_BYTE_PTR,
        pul_encrypted_data_len: CK_ULONG_PTR,
    ) -> CK_RV {
        unsafe {
            let mut guard = self.state.lock();
            let state = match guard.as_mut() {
                Some(s) => s,
                None => return CKR_CRYPTOKI_NOT_INITIALIZED.into(),
            };
            let slot_id = match state.session_to_slot.get(&h_session) {
                Some(id) => *id,
                None => return CKR_SESSION_HANDLE_INVALID.into(),
            };
            let slot = state.slots[slot_id as usize].clone();
            let mut slot_guard = slot.lock();
            let session = match slot_guard.sessions.get(&h_session) {
                Some(s) => s,
                None => return CKR_SESSION_HANDLE_INVALID.into(),
            };
            if !session.encrypt_op.active {
                return CKR_OPERATION_NOT_INITIALIZED.into();
            }
            if p_data.is_null() || pul_encrypted_data_len.is_null() {
                return CKR_ARGUMENTS_BAD.into();
            }

            let out_len = session.encrypt_op.out_len;

            if p_encrypted_data.is_null() {
                *pul_encrypted_data_len = out_len;
                return CKR_OK.into();
            }
            if *pul_encrypted_data_len < out_len {
                *pul_encrypted_data_len = out_len;
                return CKR_BUFFER_TOO_SMALL.into();
            }

            let data: &[u8] = if ul_data_len == 0 {
                &[]
            } else {
                std::slice::from_raw_parts(p_data as *const u8, ul_data_len as usize)
            };
            let result = B::encrypt_update(&mut slot_guard, h_session, data)
                .and_then(|()| B::encrypt_final(&mut slot_guard, h_session));
            slot_guard.sessions.get_mut(&h_session).unwrap().encrypt_op = EncryptOp::default();

            match result {
                Ok(ciphertext) => {
                    std::ptr::copy_nonoverlapping(
                        ciphertext.as_ptr(),
                        p_encrypted_data,
                        ciphertext.len(),
                    );
                    *pul_encrypted_data_len = ciphertext.len() as CK_ULONG;
                    CKR_OK.into()
                }
                Err(rv) => rv,
            }
        }
    }

    pub unsafe fn encrypt_update(
        &self,
        h_session: CK_SESSION_HANDLE,
        p_part: CK_BYTE_PTR,
        ul_part_len: CK_ULONG,
        _p_encrypted_part: CK_BYTE_PTR,
        pul_encrypted_part_len: CK_ULONG_PTR,
    ) -> CK_RV {
        unsafe {
            let mut guard = self.state.lock();
            let state = match guard.as_mut() {
                Some(s) => s,
                None => return CKR_CRYPTOKI_NOT_INITIALIZED.into(),
            };
            let slot_id = match state.session_to_slot.get(&h_session) {
                Some(id) => *id,
                None => return CKR_SESSION_HANDLE_INVALID.into(),
            };
            let slot = state.slots[slot_id as usize].clone();
            let mut slot_guard = slot.lock();
            let session = match slot_guard.sessions.get(&h_session) {
                Some(s) => s,
                None => return CKR_SESSION_HANDLE_INVALID.into(),
            };
            if !session.encrypt_op.active {
                return CKR_OPERATION_NOT_INITIALIZED.into();
            }
            if pul_encrypted_part_len.is_null() {
                return CKR_ARGUMENTS_BAD.into();
            }
            *pul_encrypted_part_len = 0;
            if ul_part_len > 0 && p_part.is_null() {
                slot_guard.sessions.get_mut(&h_session).unwrap().encrypt_op = EncryptOp::default();
                return CKR_ARGUMENTS_BAD.into();
            }

            let data: &[u8] = if ul_part_len == 0 {
                &[]
            } else {
                std::slice::from_raw_parts(p_part as *const u8, ul_part_len as usize)
            };
            match B::encrypt_update(&mut slot_guard, h_session, data) {
                Ok(()) => CKR_OK.into(),
                Err(rv) => {
                    slot_guard.sessions.get_mut(&h_session).unwrap().encrypt_op = EncryptOp::default();
                    rv
                }
            }
        }
    }

    pub unsafe fn encrypt_final(
        &self,
        h_session: CK_SESSION_HANDLE,
        p_last_encrypted_part: CK_BYTE_PTR,
        pul_last_encrypted_part_len: CK_ULONG_PTR,
    ) -> CK_RV {
        unsafe {
            let mut guard = self.state.lock();
            let state = match guard.as_mut() {
                Some(s) => s,
                None => return CKR_CRYPTOKI_NOT_INITIALIZED.into(),
            };
            let slot_id = match state.session_to_slot.get(&h_session) {
                Some(id) => *id,
                None => return CKR_SESSION_HANDLE_INVALID.into(),
            };
            let slot = state.slots[slot_id as usize].clone();
            let mut slot_guard = slot.lock();
            let session = match slot_guard.sessions.get(&h_session) {
                Some(s) => s,
                None => return CKR_SESSION_HANDLE_INVALID.into(),
            };
            if !session.encrypt_op.active {
                return CKR_OPERATION_NOT_INITIALIZED.into();
            }
            if pul_last_encrypted_part_len.is_null() {
                return CKR_ARGUMENTS_BAD.into();
            }

            let out_len = session.encrypt_op.out_len;

            if p_last_encrypted_part.is_null() {
                *pul_last_encrypted_part_len = out_len;
                return CKR_OK.into();
            }
            if *pul_last_encrypted_part_len < out_len {
                *pul_last_encrypted_part_len = out_len;
                return CKR_BUFFER_TOO_SMALL.into();
            }

            let result = B::encrypt_final(&mut slot_guard, h_session);
            slot_guard.sessions.get_mut(&h_session).unwrap().encrypt_op = EncryptOp::default();

            match result {
                Ok(ciphertext) => {
                    std::ptr::copy_nonoverlapping(
                        ciphertext.as_ptr(),
                        p_last_encrypted_part,
                        ciphertext.len(),
                    );
                    *pul_last_encrypted_part_len = ciphertext.len() as CK_ULONG;
                    CKR_OK.into()
                }
                Err(rv) => rv,
            }
        }
    }

    pub unsafe fn decrypt_init(
        &self,
        h_session: CK_SESSION_HANDLE,
        p_mechanism: CK_MECHANISM_PTR,
        h_key: CK_OBJECT_HANDLE,
    ) -> CK_RV {
        unsafe {
            let mut guard = self.state.lock();
            let state = match guard.as_mut() {
                Some(s) => s,
                None => return CKR_CRYPTOKI_NOT_INITIALIZED.into(),
            };
            let slot_id = match state.session_to_slot.get(&h_session) {
                Some(id) => *id,
                None => return CKR_SESSION_HANDLE_INVALID.into(),
            };
            let slot = state.slots[slot_id as usize].clone();
            let mut slot_guard = slot.lock();
            let session = match slot_guard.sessions.get(&h_session) {
                Some(s) => s,
                None => return CKR_SESSION_HANDLE_INVALID.into(),
            };
            if session.decrypt_op.active {
                return CKR_OPERATION_ACTIVE.into();
            }
            if p_mechanism.is_null() {
                return CKR_ARGUMENTS_BAD.into();
            }

            let mechanism = (*p_mechanism).mechanism;
            let parameter: &[u8] = if (*p_mechanism).pParameter.is_null()
                || (*p_mechanism).ulParameterLen == 0
            {
                &[]
            } else {
                std::slice::from_raw_parts(
                    (*p_mechanism).pParameter as *const u8,
                    (*p_mechanism).ulParameterLen as usize,
                )
            };
            match B::decrypt_init(&mut slot_guard, h_session, mechanism, parameter, h_key) {
                Ok(()) => {
                    let session = slot_guard.sessions.get_mut(&h_session).unwrap();
                    session.decrypt_op = DecryptOp {
                        active: true,
                        pending: None,
                    };
                    CKR_OK.into()
                }
                Err(rv) => rv,
            }
        }
    }

    /// Performs RSA decryption, equivalent to `C_DecryptUpdate` immediately
    /// followed by `C_DecryptFinal`.
    pub unsafe fn decrypt(
        &self,
        h_session: CK_SESSION_HANDLE,
        p_encrypted_data: CK_BYTE_PTR,
        ul_encrypted_data_len: CK_ULONG,
        p_data: CK_BYTE_PTR,
        pul_data_len: CK_ULONG_PTR,
    ) -> CK_RV {
        unsafe {
            let mut guard = self.state.lock();
            let state = match guard.as_mut() {
                Some(s) => s,
                None => return CKR_CRYPTOKI_NOT_INITIALIZED.into(),
            };
            let slot_id = match state.session_to_slot.get(&h_session) {
                Some(id) => *id,
                None => return CKR_SESSION_HANDLE_INVALID.into(),
            };
            let slot = state.slots[slot_id as usize].clone();
            let mut slot_guard = slot.lock();
            let session = match slot_guard.sessions.get(&h_session) {
                Some(s) => s,
                None => return CKR_SESSION_HANDLE_INVALID.into(),
            };
            if !session.decrypt_op.active {
                return CKR_OPERATION_NOT_INITIALIZED.into();
            }
            if pul_data_len.is_null() {
                return CKR_ARGUMENTS_BAD.into();
            }

            if slot_guard
                .sessions
                .get(&h_session)
                .unwrap()
                .decrypt_op
                .pending
                .is_none()
            {
                if ul_encrypted_data_len > 0 && p_encrypted_data.is_null() {
                    slot_guard.sessions.get_mut(&h_session).unwrap().decrypt_op = DecryptOp::default();
                    return CKR_ARGUMENTS_BAD.into();
                }
                if slot_guard.login_state == LoginState::Public {
                    slot_guard.sessions.get_mut(&h_session).unwrap().decrypt_op = DecryptOp::default();
                    return CKR_USER_NOT_LOGGED_IN.into();
                }

                let data: &[u8] = if ul_encrypted_data_len == 0 {
                    &[]
                } else {
                    std::slice::from_raw_parts(
                        p_encrypted_data as *const u8,
                        ul_encrypted_data_len as usize,
                    )
                };
                let result = B::decrypt_update(&mut slot_guard, h_session, data)
                    .and_then(|()| B::decrypt_final(&mut slot_guard, h_session));
                match result {
                    Ok(plaintext) => {
                        slot_guard
                            .sessions
                            .get_mut(&h_session)
                            .unwrap()
                            .decrypt_op
                            .pending = Some(plaintext);
                    }
                    Err(rv) => {
                        slot_guard.sessions.get_mut(&h_session).unwrap().decrypt_op =
                            DecryptOp::default();
                        return rv;
                    }
                }
            }

            let out_len = slot_guard.sessions[&h_session]
                .decrypt_op
                .pending
                .as_ref()
                .unwrap()
                .len() as CK_ULONG;

            if p_data.is_null() {
                *pul_data_len = out_len;
                return CKR_OK.into();
            }
            if *pul_data_len < out_len {
                *pul_data_len = out_len;
                return CKR_BUFFER_TOO_SMALL.into();
            }

            let plaintext = slot_guard
                .sessions
                .get_mut(&h_session)
                .unwrap()
                .decrypt_op
                .pending
                .take()
                .unwrap();
            slot_guard.sessions.get_mut(&h_session).unwrap().decrypt_op = DecryptOp::default();
            std::ptr::copy_nonoverlapping(plaintext.as_ptr(), p_data, plaintext.len());
            *pul_data_len = plaintext.len() as CK_ULONG;
            CKR_OK.into()
        }
    }

    pub unsafe fn decrypt_update(
        &self,
        h_session: CK_SESSION_HANDLE,
        p_encrypted_part: CK_BYTE_PTR,
        ul_encrypted_part_len: CK_ULONG,
        _p_part: CK_BYTE_PTR,
        pul_part_len: CK_ULONG_PTR,
    ) -> CK_RV {
        unsafe {
            let mut guard = self.state.lock();
            let state = match guard.as_mut() {
                Some(s) => s,
                None => return CKR_CRYPTOKI_NOT_INITIALIZED.into(),
            };
            let slot_id = match state.session_to_slot.get(&h_session) {
                Some(id) => *id,
                None => return CKR_SESSION_HANDLE_INVALID.into(),
            };
            let slot = state.slots[slot_id as usize].clone();
            let mut slot_guard = slot.lock();
            let session = match slot_guard.sessions.get(&h_session) {
                Some(s) => s,
                None => return CKR_SESSION_HANDLE_INVALID.into(),
            };
            if !session.decrypt_op.active {
                return CKR_OPERATION_NOT_INITIALIZED.into();
            }
            if pul_part_len.is_null() {
                return CKR_ARGUMENTS_BAD.into();
            }
            *pul_part_len = 0;
            if ul_encrypted_part_len > 0 && p_encrypted_part.is_null() {
                slot_guard.sessions.get_mut(&h_session).unwrap().decrypt_op = DecryptOp::default();
                return CKR_ARGUMENTS_BAD.into();
            }

            let data: &[u8] = if ul_encrypted_part_len == 0 {
                &[]
            } else {
                std::slice::from_raw_parts(p_encrypted_part as *const u8, ul_encrypted_part_len as usize)
            };
            match B::decrypt_update(&mut slot_guard, h_session, data) {
                Ok(()) => CKR_OK.into(),
                Err(rv) => {
                    slot_guard.sessions.get_mut(&h_session).unwrap().decrypt_op = DecryptOp::default();
                    rv
                }
            }
        }
    }

    pub unsafe fn decrypt_final(
        &self,
        h_session: CK_SESSION_HANDLE,
        p_last_part: CK_BYTE_PTR,
        pul_last_part_len: CK_ULONG_PTR,
    ) -> CK_RV {
        unsafe {
            let mut guard = self.state.lock();
            let state = match guard.as_mut() {
                Some(s) => s,
                None => return CKR_CRYPTOKI_NOT_INITIALIZED.into(),
            };
            let slot_id = match state.session_to_slot.get(&h_session) {
                Some(id) => *id,
                None => return CKR_SESSION_HANDLE_INVALID.into(),
            };
            let slot = state.slots[slot_id as usize].clone();
            let mut slot_guard = slot.lock();
            let session = match slot_guard.sessions.get(&h_session) {
                Some(s) => s,
                None => return CKR_SESSION_HANDLE_INVALID.into(),
            };
            if !session.decrypt_op.active {
                return CKR_OPERATION_NOT_INITIALIZED.into();
            }
            if pul_last_part_len.is_null() {
                return CKR_ARGUMENTS_BAD.into();
            }

            if slot_guard
                .sessions
                .get(&h_session)
                .unwrap()
                .decrypt_op
                .pending
                .is_none()
            {
                if slot_guard.login_state == LoginState::Public {
                    slot_guard.sessions.get_mut(&h_session).unwrap().decrypt_op = DecryptOp::default();
                    return CKR_USER_NOT_LOGGED_IN.into();
                }
                match B::decrypt_final(&mut slot_guard, h_session) {
                    Ok(plaintext) => {
                        slot_guard
                            .sessions
                            .get_mut(&h_session)
                            .unwrap()
                            .decrypt_op
                            .pending = Some(plaintext);
                    }
                    Err(rv) => {
                        slot_guard.sessions.get_mut(&h_session).unwrap().decrypt_op =
                            DecryptOp::default();
                        return rv;
                    }
                }
            }

            let out_len = slot_guard.sessions[&h_session]
                .decrypt_op
                .pending
                .as_ref()
                .unwrap()
                .len() as CK_ULONG;

            if p_last_part.is_null() {
                *pul_last_part_len = out_len;
                return CKR_OK.into();
            }
            if *pul_last_part_len < out_len {
                *pul_last_part_len = out_len;
                return CKR_BUFFER_TOO_SMALL.into();
            }

            let plaintext = slot_guard
                .sessions
                .get_mut(&h_session)
                .unwrap()
                .decrypt_op
                .pending
                .take()
                .unwrap();
            slot_guard.sessions.get_mut(&h_session).unwrap().decrypt_op = DecryptOp::default();
            std::ptr::copy_nonoverlapping(plaintext.as_ptr(), p_last_part, plaintext.len());
            *pul_last_part_len = plaintext.len() as CK_ULONG;
            CKR_OK.into()
        }
    }

    pub unsafe fn generate_key_pair(
        &self,
        h_session: CK_SESSION_HANDLE,
        p_mechanism: CK_MECHANISM_PTR,
        p_public_key_template: CK_ATTRIBUTE_PTR,
        ul_public_key_attribute_count: CK_ULONG,
        p_private_key_template: CK_ATTRIBUTE_PTR,
        ul_private_key_attribute_count: CK_ULONG,
        ph_public_key: CK_OBJECT_HANDLE_PTR,
        ph_private_key: CK_OBJECT_HANDLE_PTR,
    ) -> CK_RV {
        unsafe {
            let mut guard = self.state.lock();
            let state = match guard.as_mut() {
                Some(s) => s,
                None => return CKR_CRYPTOKI_NOT_INITIALIZED.into(),
            };
            let slot_id = match state.session_to_slot.get(&h_session) {
                Some(id) => *id,
                None => return CKR_SESSION_HANDLE_INVALID.into(),
            };
            let slot = state.slots[slot_id as usize].clone();
            let mut slot_guard = slot.lock();
            if !slot_guard.sessions.contains_key(&h_session) {
                return CKR_SESSION_HANDLE_INVALID.into();
            }
            if p_mechanism.is_null() || ph_public_key.is_null() || ph_private_key.is_null() {
                return CKR_ARGUMENTS_BAD.into();
            }
            if (ul_public_key_attribute_count > 0 && p_public_key_template.is_null())
                || (ul_private_key_attribute_count > 0 && p_private_key_template.is_null())
            {
                return CKR_ARGUMENTS_BAD.into();
            }

            let mechanism = (*p_mechanism).mechanism;
            let public_key_template =
                extract_attribute_template(p_public_key_template, ul_public_key_attribute_count);
            let private_key_template =
                extract_attribute_template(p_private_key_template, ul_private_key_attribute_count);

            match B::generate_key_pair(
                &mut slot_guard,
                h_session,
                mechanism,
                &public_key_template,
                &private_key_template,
            ) {
                Ok((pub_handle, priv_handle)) => {
                    *ph_public_key = pub_handle;
                    *ph_private_key = priv_handle;
                    CKR_OK.into()
                }
                Err(rv) => rv,
            }
        }
    }

    pub unsafe fn create_object(
        &self,
        h_session: CK_SESSION_HANDLE,
        p_template: CK_ATTRIBUTE_PTR,
        ul_count: CK_ULONG,
        ph_object: CK_OBJECT_HANDLE_PTR,
    ) -> CK_RV {
        unsafe {
            let mut guard = self.state.lock();
            let state = match guard.as_mut() {
                Some(s) => s,
                None => return CKR_CRYPTOKI_NOT_INITIALIZED.into(),
            };
            let slot_id = match state.session_to_slot.get(&h_session) {
                Some(id) => *id,
                None => return CKR_SESSION_HANDLE_INVALID.into(),
            };
            let slot = state.slots[slot_id as usize].clone();
            let mut slot_guard = slot.lock();
            if !slot_guard.sessions.contains_key(&h_session) {
                return CKR_SESSION_HANDLE_INVALID.into();
            }
            if ph_object.is_null() || (ul_count > 0 && p_template.is_null()) {
                return CKR_ARGUMENTS_BAD.into();
            }

            let template = extract_attribute_template(p_template, ul_count);

            match B::create_object(&mut slot_guard, h_session, &template) {
                Ok(handle) => {
                    *ph_object = handle;
                    CKR_OK.into()
                }
                Err(rv) => rv,
            }
        }
    }

    pub unsafe fn derive_key(
        &self,
        h_session: CK_SESSION_HANDLE,
        p_mechanism: CK_MECHANISM_PTR,
        h_base_key: CK_OBJECT_HANDLE,
        p_template: CK_ATTRIBUTE_PTR,
        ul_attribute_count: CK_ULONG,
        ph_key: CK_OBJECT_HANDLE_PTR,
    ) -> CK_RV {
        unsafe {
            let mut guard = self.state.lock();
            let state = match guard.as_mut() {
                Some(s) => s,
                None => return CKR_CRYPTOKI_NOT_INITIALIZED.into(),
            };
            let slot_id = match state.session_to_slot.get(&h_session) {
                Some(id) => *id,
                None => return CKR_SESSION_HANDLE_INVALID.into(),
            };
            let slot = state.slots[slot_id as usize].clone();
            let mut slot_guard = slot.lock();
            if !slot_guard.sessions.contains_key(&h_session) {
                return CKR_SESSION_HANDLE_INVALID.into();
            }
            if p_mechanism.is_null() || ph_key.is_null() || (ul_attribute_count > 0 && p_template.is_null())
            {
                return CKR_ARGUMENTS_BAD.into();
            }

            let mechanism = (*p_mechanism).mechanism;
            let parameter: &[u8] = if (*p_mechanism).pParameter.is_null()
                || (*p_mechanism).ulParameterLen == 0
            {
                &[]
            } else {
                std::slice::from_raw_parts(
                    (*p_mechanism).pParameter as *const u8,
                    (*p_mechanism).ulParameterLen as usize,
                )
            };
            let template = extract_attribute_template(p_template, ul_attribute_count);

            match B::derive_key(&mut slot_guard, h_session, mechanism, parameter, h_base_key, &template) {
                Ok(handle) => {
                    *ph_key = handle;
                    CKR_OK.into()
                }
                Err(rv) => rv,
            }
        }
    }

    /// PKCS#11 3.2's `C_EncapsulateKey`.
    ///
    /// Calls `B::encapsulate_key` after the input has been validated,
    /// deliberately not run twice just to answer a length query.
    pub unsafe fn encapsulate_key(
        &self,
        h_session: CK_SESSION_HANDLE,
        p_mechanism: CK_MECHANISM_PTR,
        h_public_key: CK_OBJECT_HANDLE,
        p_template: CK_ATTRIBUTE_PTR,
        ul_attribute_count: CK_ULONG,
        p_ciphertext: CK_BYTE_PTR,
        pul_ciphertext_len: CK_ULONG_PTR,
        ph_key: CK_OBJECT_HANDLE_PTR,
    ) -> CK_RV {
        unsafe {
            let mut guard = self.state.lock();
            let state = match guard.as_mut() {
                Some(s) => s,
                None => return CKR_CRYPTOKI_NOT_INITIALIZED.into(),
            };
            let slot_id = match state.session_to_slot.get(&h_session) {
                Some(id) => *id,
                None => return CKR_SESSION_HANDLE_INVALID.into(),
            };
            let slot = state.slots[slot_id as usize].clone();
            let mut slot_guard = slot.lock();
            if !slot_guard.sessions.contains_key(&h_session) {
                return CKR_SESSION_HANDLE_INVALID.into();
            }
            if p_mechanism.is_null()
                || pul_ciphertext_len.is_null()
                || ph_key.is_null()
                || (ul_attribute_count > 0 && p_template.is_null())
            {
                return CKR_ARGUMENTS_BAD.into();
            }

            if p_ciphertext.is_null() {
                return match B::encapsulate_key_len(&mut slot_guard, h_public_key) {
                    Ok(len) => {
                        *pul_ciphertext_len = len as CK_ULONG;
                        CKR_OK.into()
                    }
                    Err(rv) => rv,
                };
            }

            let mechanism = (*p_mechanism).mechanism;
            let parameter: &[u8] = if (*p_mechanism).pParameter.is_null()
                || (*p_mechanism).ulParameterLen == 0
            {
                &[]
            } else {
                std::slice::from_raw_parts(
                    (*p_mechanism).pParameter as *const u8,
                    (*p_mechanism).ulParameterLen as usize,
                )
            };
            let template = extract_attribute_template(p_template, ul_attribute_count);

            match B::encapsulate_key(&mut slot_guard, h_session, mechanism, parameter, h_public_key, &template) {
                Ok((ciphertext, handle)) => {
                    if (*pul_ciphertext_len as usize) < ciphertext.len() {
                        *pul_ciphertext_len = ciphertext.len() as CK_ULONG;
                        return CKR_BUFFER_TOO_SMALL.into();
                    }
                    std::ptr::copy_nonoverlapping(ciphertext.as_ptr(), p_ciphertext, ciphertext.len());
                    *pul_ciphertext_len = ciphertext.len() as CK_ULONG;
                    *ph_key = handle;
                    CKR_OK.into()
                }
                Err(rv) => rv,
            }
        }
    }

    /// PKCS#11 3.2's `C_DecapsulateKey`.
    pub unsafe fn decapsulate_key(
        &self,
        h_session: CK_SESSION_HANDLE,
        p_mechanism: CK_MECHANISM_PTR,
        h_private_key: CK_OBJECT_HANDLE,
        p_template: CK_ATTRIBUTE_PTR,
        ul_attribute_count: CK_ULONG,
        p_ciphertext: CK_BYTE_PTR,
        ul_ciphertext_len: CK_ULONG,
        ph_key: CK_OBJECT_HANDLE_PTR,
    ) -> CK_RV {
        unsafe {
            let mut guard = self.state.lock();
            let state = match guard.as_mut() {
                Some(s) => s,
                None => return CKR_CRYPTOKI_NOT_INITIALIZED.into(),
            };
            let slot_id = match state.session_to_slot.get(&h_session) {
                Some(id) => *id,
                None => return CKR_SESSION_HANDLE_INVALID.into(),
            };
            let slot = state.slots[slot_id as usize].clone();
            let mut slot_guard = slot.lock();
            if !slot_guard.sessions.contains_key(&h_session) {
                return CKR_SESSION_HANDLE_INVALID.into();
            }
            if p_mechanism.is_null()
                || ph_key.is_null()
                || (ul_attribute_count > 0 && p_template.is_null())
                || (ul_ciphertext_len > 0 && p_ciphertext.is_null())
            {
                return CKR_ARGUMENTS_BAD.into();
            }

            let mechanism = (*p_mechanism).mechanism;
            let parameter: &[u8] = if (*p_mechanism).pParameter.is_null()
                || (*p_mechanism).ulParameterLen == 0
            {
                &[]
            } else {
                std::slice::from_raw_parts(
                    (*p_mechanism).pParameter as *const u8,
                    (*p_mechanism).ulParameterLen as usize,
                )
            };
            let ciphertext: &[u8] = if ul_ciphertext_len == 0 {
                &[]
            } else {
                std::slice::from_raw_parts(p_ciphertext, ul_ciphertext_len as usize)
            };
            let template = extract_attribute_template(p_template, ul_attribute_count);

            match B::decapsulate_key(
                &mut slot_guard,
                h_session,
                mechanism,
                parameter,
                h_private_key,
                ciphertext,
                &template,
            ) {
                Ok(handle) => {
                    *ph_key = handle;
                    CKR_OK.into()
                }
                Err(rv) => rv,
            }
        }
    }

    pub unsafe fn destroy_object(&self, h_session: CK_SESSION_HANDLE, h_object: CK_OBJECT_HANDLE) -> CK_RV {
        let mut guard = self.state.lock();
        let state = match guard.as_mut() {
            Some(s) => s,
            None => return CKR_CRYPTOKI_NOT_INITIALIZED.into(),
        };
        let slot_id = match state.session_to_slot.get(&h_session) {
            Some(id) => *id,
            None => return CKR_SESSION_HANDLE_INVALID.into(),
        };
        let slot = state.slots[slot_id as usize].clone();
        let mut slot_guard = slot.lock();
        if !slot_guard.sessions.contains_key(&h_session) {
            return CKR_SESSION_HANDLE_INVALID.into();
        }

        match B::destroy_object(&mut slot_guard, h_session, h_object) {
            Ok(()) => CKR_OK.into(),
            Err(rv) => rv,
        }
    }

    pub unsafe fn set_pin(
        &self,
        h_session: CK_SESSION_HANDLE,
        p_old_pin: CK_UTF8CHAR_PTR,
        ul_old_len: CK_ULONG,
        p_new_pin: CK_UTF8CHAR_PTR,
        ul_new_len: CK_ULONG,
    ) -> CK_RV {
        unsafe {
            let mut guard = self.state.lock();
            let state = match guard.as_mut() {
                Some(s) => s,
                None => return CKR_CRYPTOKI_NOT_INITIALIZED.into(),
            };
            let slot_id = match state.session_to_slot.get(&h_session) {
                Some(id) => *id,
                None => return CKR_SESSION_HANDLE_INVALID.into(),
            };
            let slot = state.slots[slot_id as usize].clone();
            let mut slot_guard = slot.lock();
            if !slot_guard.sessions.contains_key(&h_session) {
                return CKR_SESSION_HANDLE_INVALID.into();
            }

            let old_pin: &[u8] = if p_old_pin.is_null() || ul_old_len == 0 {
                &[]
            } else {
                std::slice::from_raw_parts(p_old_pin as *const u8, ul_old_len as usize)
            };
            let new_pin: &[u8] = if p_new_pin.is_null() || ul_new_len == 0 {
                &[]
            } else {
                std::slice::from_raw_parts(p_new_pin as *const u8, ul_new_len as usize)
            };

            match B::set_pin(&mut slot_guard, h_session, old_pin, new_pin) {
                Ok(()) => CKR_OK.into(),
                Err(rv) => rv,
            }
        }
    }

    /// `C_InitToken` on slot-level, not session-level
    pub unsafe fn init_token(
        &self,
        slot_id: CK_SLOT_ID,
        p_pin: CK_UTF8CHAR_PTR,
        ul_pin_len: CK_ULONG,
        _p_label: CK_UTF8CHAR_PTR,
    ) -> CK_RV {
        unsafe {
            let guard = self.state.lock();
            let state = match guard.as_ref() {
                Some(s) => s,
                None => return CKR_CRYPTOKI_NOT_INITIALIZED.into(),
            };
            let slot = match Self::slot_arc(state, slot_id) {
                Ok(s) => s,
                Err(rv) => return rv,
            };
            let mut slot_guard = slot.lock();
            if !B::is_present(&slot_guard.data) {
                return CKR_TOKEN_NOT_PRESENT.into();
            }
            if !slot_guard.sessions.is_empty() {
                return CKR_SESSION_EXISTS.into();
            }
            if p_pin.is_null() {
                return CKR_ARGUMENTS_BAD.into();
            }
            let pin: &[u8] = if ul_pin_len == 0 {
                &[]
            } else {
                std::slice::from_raw_parts(p_pin as *const u8, ul_pin_len as usize)
            };

            match B::init_token(&mut slot_guard, pin) {
                Ok(()) => CKR_OK.into(),
                Err(rv) => rv,
            }
        }
    }
}
