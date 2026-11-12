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

//! [`pkcs11_common::backend::Backend`] impl for the YubiKey PIV module.

use crate::discovery::ActivePivSession;
use crate::piv_slot::PivSlotData;
use pkcs11_common::backend::{
    Backend, Engine, LibraryInfo, MechanismInfo, ModuleState, Slot, SlotInfo, TokenInfo,
};
use pkcs11_common::session::LoginState;
use pkcs11_sys::*;
use yubikit::piv::{ManagementKey, PivError, PivPin};

const YKCS11_MANUFACTURER: &str = "Yubico (www.yubico.com)";
const YKCS11_LIBDESC: &str = "PKCS#11 PIV Library (SP-800-73)";
const YKCS11_VERSION_MAJOR: u8 = 1;
const YKCS11_VERSION_MINOR: u8 = 0;

pub struct PivBackend;

fn firmware_version(data: &PivSlotData) -> (u8, u8) {
    data.token_info
        .as_ref()
        .map(|t| (t.fw_version_major, t.fw_version_minor))
        .unwrap_or((0, 0))
}

/// Per-session state of active operations
#[derive(Default)]
pub struct PivSessionData {
    pub sign: Option<crate::sign::SignState>,
    pub verify: Option<crate::verify::VerifyState>,
    pub encrypt: Option<crate::encrypt::EncryptState>,
    pub decrypt: Option<crate::decrypt::DecryptState>,
}

impl Backend for PivBackend {
    type SlotData = PivSlotData;
    type SessionData = PivSessionData;
    type ModuleData = ();

    fn library_info() -> LibraryInfo {
        LibraryInfo {
            manufacturer_id: YKCS11_MANUFACTURER,
            library_description: YKCS11_LIBDESC,
            library_version: (YKCS11_VERSION_MAJOR, YKCS11_VERSION_MINOR),
            // The version `C_GetInfo` reports when reached via the legacy
            // `C_GetFunctionList`. The separate 3.2 interface
            // (`C_GetInterface`) reports its own version.
            cryptoki_version: (
                CRYPTOKI_LEGACY_VERSION_MAJOR as u8,
                CRYPTOKI_LEGACY_VERSION_MINOR as u8,
            ),
        }
    }

    fn initialize(reserved: Option<&str>) -> Result<((), Vec<PivSlotData>), CK_RV> {
        if reserved.is_some() {
            return Err(CKR_ARGUMENTS_BAD.into());
        }
        // Slots are discovered by `refresh_slots` on the first `C_GetSlotList` call.
        Ok(((), Vec::new()))
    }

    fn refresh_slots(state: &mut ModuleState<Self>) -> Result<(), CK_RV> {
        crate::discovery::refresh_slots(state)
    }

    fn is_present(data: &PivSlotData) -> bool {
        data.token_present
    }

    fn slot_info(_slot_id: CK_SLOT_ID, data: &PivSlotData) -> SlotInfo {
        SlotInfo {
            description: data.reader_name.clone(),
            manufacturer_id: YKCS11_MANUFACTURER.to_string(),
            hardware_version: data.hw_version,
            firmware_version: data.fw_version,
        }
    }

    fn token_info(data: &mut PivSlotData) -> Option<TokenInfo> {
        if !data.token_present {
            return None;
        }

        // Query live PIN retry state before taking the immutable borrow
        // below.
        let retry_flags: CK_FLAGS = match data.piv_session.as_mut() {
            Some(piv) => match piv.get_pin_attempts() {
                Ok(0) => CKF_USER_PIN_LOCKED as CK_FLAGS,
                Ok(1) => CKF_USER_PIN_FINAL_TRY as CK_FLAGS,
                Ok(2) => CKF_USER_PIN_COUNT_LOW as CK_FLAGS,
                Ok(_) => 0,
                Err(_) => 0,
            },
            None => 0,
        };

        let t = data.token_info.as_ref()?;
        Some(TokenInfo {
            label: t.label.clone(),
            manufacturer_id: t.manufacturer.clone(),
            model: t.model.clone(),
            serial_number: t.serial.clone(),
            min_pin_len: t.min_pin_len,
            max_pin_len: t.max_pin_len,
            hardware_version: (1, 0),
            firmware_version: (t.fw_version_major, t.fw_version_minor),
            extra_flags: retry_flags,
        })
    }

    fn max_sessions(_data: &PivSlotData) -> Option<usize> {
        Some(crate::piv_slot::YKCS11_MAX_SESSIONS)
    }

    fn mechanism_list(data: &PivSlotData) -> Vec<CK_MECHANISM_TYPE> {
        crate::mechanisms::token_mechanisms(firmware_version(data))
    }

    fn mechanism_info(data: &PivSlotData, mechanism: CK_MECHANISM_TYPE) -> Option<MechanismInfo> {
        let entry = crate::mechanisms::mechanism_table(firmware_version(data))
            .into_iter()
            .find(|e| e.mechanism == mechanism)?;

        Some(MechanismInfo {
            min_key_size: entry.min_key_size,
            max_key_size: entry.max_key_size,
            flags: entry.flags,
        })
    }

    fn new_session_data(
        slot: &mut PivSlotData,
        _handle: CK_SESSION_HANDLE,
        _flags: CK_FLAGS,
    ) -> PivSessionData {
        if slot.objects.is_empty() {
            if let Some(piv) = slot.piv_session.as_mut() {
                slot.objects = crate::objects::read_objects(piv);
            }
        }
        PivSessionData::default()
    }

    fn login(
        slot: &mut Slot<Self>,
        h_session: CK_SESSION_HANDLE,
        user_type: CK_USER_TYPE,
        pin: &[u8],
        _username: &[u8],
    ) -> Result<(), CK_RV> {
        // ykcs11 has no C_LoginUser support so `_username` is always empty.
        if user_type != CKU_SO as CK_USER_TYPE
            && user_type != CKU_USER as CK_USER_TYPE
            && user_type != CKU_CONTEXT_SPECIFIC as CK_USER_TYPE
        {
            return Err(CKR_USER_TYPE_INVALID.into());
        }

        // CKU_CONTEXT_SPECIFIC is only legal while a private key operation
        // is in progress on the calling session
        if user_type == CKU_CONTEXT_SPECIFIC as CK_USER_TYPE {
            let op_in_progress = slot
                .sessions
                .get(&h_session)
                .is_some_and(|s| s.sign_op.active || s.decrypt_op.active);
            if !op_in_progress {
                return Err(CKR_USER_TYPE_INVALID.into());
            }
        }

        let piv = slot
            .data
            .piv_session
            .as_mut()
            .ok_or(CK_RV::from(CKR_TOKEN_NOT_PRESENT))?;

        match user_type as u32 {
            CKU_USER | CKU_CONTEXT_SPECIFIC => {
                if user_type == CKU_USER as CK_USER_TYPE {
                    if slot.login_state == LoginState::User {
                        return Err(CKR_USER_ALREADY_LOGGED_IN.into());
                    }
                    if slot.login_state == LoginState::SO {
                        return Err(CKR_USER_ANOTHER_ALREADY_LOGGED_IN.into());
                    }
                }

                verify_user_pin(piv, pin)?;

                // A context-specific login on top of an existing SO session
                // must not downgrade it back to User.
                if slot.login_state == LoginState::Public {
                    slot.login_state = LoginState::User;
                }
            }
            CKU_SO => {
                if slot.login_state == LoginState::User {
                    return Err(CKR_USER_ANOTHER_ALREADY_LOGGED_IN.into());
                }
                if slot.login_state == LoginState::SO {
                    return Err(CKR_USER_ALREADY_LOGGED_IN.into());
                }
                if slot
                    .sessions
                    .values()
                    .any(|s| s.flags & CKF_RW_SESSION as CK_FLAGS == 0)
                {
                    return Err(CKR_SESSION_READ_ONLY_EXISTS.into());
                }

                authenticate_so(piv, pin)?;

                slot.login_state = LoginState::SO;
            }
            _ => unreachable!("validated above"),
        }

        Ok(())
    }

    fn logout(slot: &mut Slot<Self>) -> Result<(), CK_RV> {
        if slot.login_state == LoginState::Public {
            return Err(CKR_USER_NOT_LOGGED_IN.into());
        }

        // Force a real PC/SC card reset to deauthenticate and authenticated state
        if let Some(piv) = slot.data.piv_session.take() {
            let mut conn = piv.into_connection();
            if conn.reconnect(false).is_err() {
                slot.data.disconnect();
                return Err(CKR_DEVICE_ERROR.into());
            }
            match ActivePivSession::new(conn) {
                Ok(fresh) => slot.data.piv_session = Some(fresh),
                Err((e, _conn)) => {
                    slot.data.disconnect();
                    return Err(piv_error_to_rv(e));
                }
            }
        }

        slot.login_state = LoginState::Public;
        Ok(())
    }

    fn generate_random(_slot: &Slot<Self>, buf: &mut [u8]) -> Result<(), CK_RV> {
        // Host-side RNG, not the YubiKey hardware
        getrandom::fill(buf).map_err(|_| CKR_FUNCTION_FAILED.into())
    }

    fn seed_random(_slot: &Slot<Self>, _seed: &[u8]) -> Result<(), CK_RV> {
        // TODO examine intended functionality
        // Matches do_rand_seed (openssl_utils.c:39-46): mixes the caller's
        // bytes into OpenSSL's global RNG state and returns CKR_OK. `getrandom`
        // has no equivalent so the seed is just accepted for API compatibility
        // but has no actual effect.
        Ok(())
    }

    fn object_handles(slot: &Slot<Self>) -> Vec<CK_OBJECT_HANDLE> {
        crate::objects::object_handles(&slot.data.objects, slot.login_state != LoginState::Public)
    }

    fn get_one_attribute_value(
        data: &PivSlotData,
        handle: CK_OBJECT_HANDLE,
        attr_type: CK_ATTRIBUTE_TYPE,
    ) -> Option<Vec<u8>> {
        crate::objects::get_attribute(&data.objects, handle, attr_type)
    }

    fn sign_init(
        slot: &mut Slot<Self>,
        h_session: CK_SESSION_HANDLE,
        mechanism: CK_MECHANISM_TYPE,
        parameter: &[u8],
        key_handle: CK_OBJECT_HANDLE,
    ) -> Result<CK_ULONG, CK_RV> {
        crate::sign::sign_init(slot, h_session, mechanism, parameter, key_handle)
    }

    fn digest_init(
        slot: &mut Slot<Self>,
        _h_session: CK_SESSION_HANDLE,
        mechanism: CK_MECHANISM_TYPE,
        parameter: &[u8],
    ) -> Result<Option<pkcs11_common::digest::DigestOp>, CK_RV> {
        crate::digest::digest_init(slot, mechanism, parameter)
    }

    fn sign_update(
        slot: &mut Slot<Self>,
        h_session: CK_SESSION_HANDLE,
        data: &[u8],
    ) -> Result<(), CK_RV> {
        crate::sign::sign_update(slot, h_session, data)
    }

    fn sign_final(slot: &mut Slot<Self>, h_session: CK_SESSION_HANDLE) -> Result<Vec<u8>, CK_RV> {
        crate::sign::sign_final(slot, h_session)
    }

    fn verify_init(
        slot: &mut Slot<Self>,
        h_session: CK_SESSION_HANDLE,
        mechanism: CK_MECHANISM_TYPE,
        parameter: &[u8],
        key_handle: CK_OBJECT_HANDLE,
    ) -> Result<(), CK_RV> {
        crate::verify::verify_init(slot, h_session, mechanism, parameter, key_handle)
    }

    fn verify_update(
        slot: &mut Slot<Self>,
        h_session: CK_SESSION_HANDLE,
        data: &[u8],
    ) -> Result<(), CK_RV> {
        crate::verify::verify_update(slot, h_session, data)
    }

    fn verify_final(
        slot: &mut Slot<Self>,
        h_session: CK_SESSION_HANDLE,
        signature: &[u8],
    ) -> Result<(), CK_RV> {
        crate::verify::verify_final(slot, h_session, signature)
    }

    fn encrypt_init(
        slot: &mut Slot<Self>,
        h_session: CK_SESSION_HANDLE,
        mechanism: CK_MECHANISM_TYPE,
        parameter: &[u8],
        key_handle: CK_OBJECT_HANDLE,
    ) -> Result<CK_ULONG, CK_RV> {
        crate::encrypt::encrypt_init(slot, h_session, mechanism, parameter, key_handle)
    }

    fn encrypt_update(
        slot: &mut Slot<Self>,
        h_session: CK_SESSION_HANDLE,
        data: &[u8],
    ) -> Result<(), CK_RV> {
        crate::encrypt::encrypt_update(slot, h_session, data)
    }

    fn encrypt_final(slot: &mut Slot<Self>, h_session: CK_SESSION_HANDLE) -> Result<Vec<u8>, CK_RV> {
        crate::encrypt::encrypt_final(slot, h_session)
    }

    fn decrypt_init(
        slot: &mut Slot<Self>,
        h_session: CK_SESSION_HANDLE,
        mechanism: CK_MECHANISM_TYPE,
        parameter: &[u8],
        key_handle: CK_OBJECT_HANDLE,
    ) -> Result<(), CK_RV> {
        crate::decrypt::decrypt_init(slot, h_session, mechanism, parameter, key_handle)
    }

    fn decrypt_update(
        slot: &mut Slot<Self>,
        h_session: CK_SESSION_HANDLE,
        data: &[u8],
    ) -> Result<(), CK_RV> {
        crate::decrypt::decrypt_update(slot, h_session, data)
    }

    fn decrypt_final(slot: &mut Slot<Self>, h_session: CK_SESSION_HANDLE) -> Result<Vec<u8>, CK_RV> {
        crate::decrypt::decrypt_final(slot, h_session)
    }

    fn generate_key_pair(
        slot: &mut Slot<Self>,
        h_session: CK_SESSION_HANDLE,
        mechanism: CK_MECHANISM_TYPE,
        public_key_template: &[(CK_ATTRIBUTE_TYPE, Vec<u8>)],
        private_key_template: &[(CK_ATTRIBUTE_TYPE, Vec<u8>)],
    ) -> Result<(CK_OBJECT_HANDLE, CK_OBJECT_HANDLE), CK_RV> {
        crate::generate::generate_key_pair(
            slot,
            h_session,
            mechanism,
            public_key_template,
            private_key_template,
        )
    }

    fn create_object(
        slot: &mut Slot<Self>,
        h_session: CK_SESSION_HANDLE,
        template: &[(CK_ATTRIBUTE_TYPE, Vec<u8>)],
    ) -> Result<CK_OBJECT_HANDLE, CK_RV> {
        crate::create_object::create_object(slot, h_session, template)
    }

    fn derive_key(
        slot: &mut Slot<Self>,
        h_session: CK_SESSION_HANDLE,
        mechanism: CK_MECHANISM_TYPE,
        parameter: &[u8],
        base_key_handle: CK_OBJECT_HANDLE,
        template: &[(CK_ATTRIBUTE_TYPE, Vec<u8>)],
    ) -> Result<CK_OBJECT_HANDLE, CK_RV> {
        crate::derive::derive_key(slot, h_session, mechanism, parameter, base_key_handle, template)
    }

    fn destroy_object(
        slot: &mut Slot<Self>,
        h_session: CK_SESSION_HANDLE,
        handle: CK_OBJECT_HANDLE,
    ) -> Result<(), CK_RV> {
        crate::destroy_object::destroy_object(slot, h_session, handle)
    }

    fn set_pin(
        slot: &mut Slot<Self>,
        h_session: CK_SESSION_HANDLE,
        old_pin: &[u8],
        new_pin: &[u8],
    ) -> Result<(), CK_RV> {
        crate::set_pin::set_pin(slot, h_session, old_pin, new_pin)
    }

    fn init_token(slot: &mut Slot<Self>, pin: &[u8]) -> Result<(), CK_RV> {
        crate::init_token::init_token(slot, pin)
    }

    fn encapsulate_key_len(slot: &mut Slot<Self>, h_public_key: CK_OBJECT_HANDLE) -> Result<usize, CK_RV> {
        crate::encapsulate::encapsulate_key_len(slot, h_public_key)
    }

    fn encapsulate_key(
        slot: &mut Slot<Self>,
        h_session: CK_SESSION_HANDLE,
        mechanism: CK_MECHANISM_TYPE,
        parameter: &[u8],
        h_public_key: CK_OBJECT_HANDLE,
        template: &[(CK_ATTRIBUTE_TYPE, Vec<u8>)],
    ) -> Result<(Vec<u8>, CK_OBJECT_HANDLE), CK_RV> {
        crate::encapsulate::encapsulate_key(slot, h_session, mechanism, parameter, h_public_key, template)
    }

    fn decapsulate_key(
        slot: &mut Slot<Self>,
        h_session: CK_SESSION_HANDLE,
        mechanism: CK_MECHANISM_TYPE,
        parameter: &[u8],
        h_private_key: CK_OBJECT_HANDLE,
        ciphertext: &[u8],
        template: &[(CK_ATTRIBUTE_TYPE, Vec<u8>)],
    ) -> Result<CK_OBJECT_HANDLE, CK_RV> {
        crate::encapsulate::decapsulate_key(
            slot,
            h_session,
            mechanism,
            parameter,
            h_private_key,
            ciphertext,
            template,
        )
    }
}

/// A request for biometric-only verification
const VERIFY_BIO: &[u8] = b"VERIFY_BIO";
/// And a request to skip verification entirely
const VERIFY_NONE: &[u8] = b"VERIFY_NONE";

pub(crate) fn piv_error_to_rv(e: PivError) -> CK_RV {
    match e {
        PivError::InvalidPin(0) => CKR_PIN_LOCKED.into(),
        PivError::InvalidPin(_) => CKR_PIN_INCORRECT.into(),
        PivError::NotSupported(_) => CKR_FUNCTION_NOT_SUPPORTED.into(),
        PivError::InvalidData(_) => CKR_ARGUMENTS_BAD.into(),
        PivError::Connection(_) => CKR_DEVICE_ERROR.into(),
        _ => CKR_GENERAL_ERROR.into(),
    }
}

fn verify_user_pin(piv: &mut ActivePivSession, pin: &[u8]) -> Result<(), CK_RV> {
    if pin.is_empty() || pin == VERIFY_BIO {
        return piv
            .verify_uv(false, false)
            .map(|_| ())
            .map_err(piv_error_to_rv);
    }
    if pin == VERIFY_NONE {
        return Ok(());
    }

    let piv_pin = std::str::from_utf8(pin)
        .ok()
        .and_then(|s| PivPin::new(s).ok())
        .ok_or(CK_RV::from(CKR_ARGUMENTS_BAD))?;
    piv.verify_pin(&piv_pin).map_err(piv_error_to_rv)
}

fn authenticate_so(piv: &mut ActivePivSession, pin: &[u8]) -> Result<(), CK_RV> {
    if pin.is_empty() || pin == VERIFY_BIO {
        piv.verify_uv(false, false).map_err(piv_error_to_rv)?;
    } else if pin == VERIFY_NONE {
        return Ok(());
    } else if let Some(piv_pin) = std::str::from_utf8(pin)
        .ok()
        .and_then(|s| PivPin::new(s).ok())
    {
        piv.verify_pin(&piv_pin).map_err(piv_error_to_rv)?;
    } else {
        // Not a PIN-length value: must be the literal hex-encoded
        // management key.
        let key_bytes =
            pkcs11_common::util::hex_decode(pin).ok_or(CK_RV::from(CKR_ARGUMENTS_BAD))?;
        let key_type = piv.management_key_type();
        let key =
            ManagementKey::new(key_type, &key_bytes).map_err(|_| CK_RV::from(CKR_ARGUMENTS_BAD))?;
        return piv.authenticate(&key).map_err(|e| match e {
            // Matches token.c:366-367: a rejected response from the device
            // means the supplied key was wrong.
            PivError::InvalidData(_) => CK_RV::from(CKR_PIN_INCORRECT),
            other => piv_error_to_rv(other),
        });
    }

    // TODO Authenticate with PIN protected management key

    Err(CKR_USER_PIN_NOT_INITIALIZED.into())
}

pub static G_ENGINE: Engine<PivBackend> = Engine::new();

#[cfg(test)]
mod tests {
    use super::*;
    use pkcs11_common::backend::{DecryptOp, EncryptOp, FindOp, Session, SignOp, VerifyOp};
    use std::collections::HashMap;

    fn slot_with_session(h_session: CK_SESSION_HANDLE, sign_active: bool, decrypt_active: bool) -> Slot<PivBackend> {
        let mut sessions = HashMap::new();
        sessions.insert(
            h_session,
            Session {
                handle: h_session,
                flags: 0,
                find_op: FindOp::default(),
                digest_op: None,
                sign_op: SignOp {
                    active: sign_active,
                    ..Default::default()
                },
                verify_op: VerifyOp::default(),
                encrypt_op: EncryptOp::default(),
                decrypt_op: DecryptOp {
                    active: decrypt_active,
                    ..Default::default()
                },
                data: PivSessionData::default(),
            },
        );
        Slot {
            login_state: LoginState::Public,
            sessions,
            data: crate::piv_slot::PivSlotData::new("test reader".to_string()),
        }
    }

    #[test]
    fn context_specific_login_rejected_with_no_operation_in_progress() {
        let mut slot = slot_with_session(1, false, false);
        let rv = PivBackend::login(&mut slot, 1, CKU_CONTEXT_SPECIFIC as CK_USER_TYPE, b"123456", b"");
        assert_eq!(rv, Err(CKR_USER_TYPE_INVALID.into()));
    }

    #[test]
    fn context_specific_login_passes_the_gate_while_a_sign_operation_is_active() {
        let mut slot = slot_with_session(1, true, false);
        // No real `piv_session` is wired up in this test, so once the
        // CKU_CONTEXT_SPECIFIC gate is passed, the next thing `login` does
        // is look up `slot.data.piv_session` and fail with
        // CKR_TOKEN_NOT_PRESENT, proving it got past the gate instead of
        // being rejected with CKR_USER_TYPE_INVALID.
        let rv = PivBackend::login(&mut slot, 1, CKU_CONTEXT_SPECIFIC as CK_USER_TYPE, b"123456", b"");
        assert_eq!(rv, Err(CKR_TOKEN_NOT_PRESENT.into()));
    }

    #[test]
    fn context_specific_login_passes_the_gate_while_a_decrypt_operation_is_active() {
        let mut slot = slot_with_session(1, false, true);
        let rv = PivBackend::login(&mut slot, 1, CKU_CONTEXT_SPECIFIC as CK_USER_TYPE, b"123456", b"");
        assert_eq!(rv, Err(CKR_TOKEN_NOT_PRESENT.into()));
    }

    #[test]
    fn context_specific_login_rejected_on_an_unknown_session_handle() {
        let mut slot = slot_with_session(1, true, true);
        let rv = PivBackend::login(&mut slot, 2, CKU_CONTEXT_SPECIFIC as CK_USER_TYPE, b"123456", b"");
        assert_eq!(rv, Err(CKR_USER_TYPE_INVALID.into()));
    }
}
