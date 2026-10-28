#!/usr/bin/env python3
"""End-to-end test of ykcs11's CKM_YUBICO_ML_DSA_EXTERNAL_MU vendor
mechanism, using raw ctypes calls against the compiled library (same
approach as ml_kem_roundtrip.py -- see that script's own module docstring
for why ctypes rather than python-pkcs11/pkcs11-provider: both of those
only ever know about standard PKCS#11 mechanisms, and this one is a Yubico
vendor extension neither has any code path for).

Unlike the ML-KEM script, this does NOT import a key first -- it reuses
whatever ML-DSA key pair already exists on the device (adjust ML_DSA_ID
below to match; defaults to 25/0x19, the "PIV Attestation" slot, since
that's where the project's own manual testing already has an ML-DSA-87
key pair sitting).

What it does:
  1. Reads the public key's raw CKA_VALUE (the FIPS 204 encoded `pk`).
  2. Computes mu = SHAKE256(SHAKE256(pk, 64) || 0x00 || len(ctx) || ctx
     || message, 64) in pure Python -- the exact same formula
     yubikit::__internal::padding::ml_dsa_mu implements
     (crates/yubikit/src/__internal/padding.rs:296-322), so no dependency
     on yubikit's own (Rust-only) implementation is needed here.
  3. C_SignInit/C_Sign with CKM_YUBICO_ML_DSA_EXTERNAL_MU (0xD9554201),
     passing `mu` as the data to sign.
  4. Verifies the resulting signature via ykcs11's own already-proven
     context-aware CKM_ML_DSA verify (C_VerifyInit/C_Verify), against the
     ORIGINAL message and context -- not mu. If that succeeds, it's
     definitive proof the external-mu signing path produces a signature
     that verifies exactly like one FIPS 204's "ExternalMu-ML-DSA.Sign"
     promises: identical to what signing the full message directly would
     have produced. No external ML-DSA crypto library needed on the
     Python side at all.
  5. Two negative checks: verifying with the wrong context must fail, and
     signing with a wrong-length mu must be rejected client-side with
     CKR_DATA_LEN_RANGE (exercising sign.rs's own length check).

Usage:
    cargo build -p ykcs11
    python3 scripts/ml_dsa_external_mu_test.py [path/to/libykcs11.so]
"""

import ctypes
import hashlib
import sys

LIB_PATH = sys.argv[1] if len(sys.argv) > 1 else "target/debug/libykcs11.so"

DEFAULT_USER_PIN = b"123456"
ML_DSA_ID = bytes([0x19])  # ID 25 -- "Private/Public key for PIV Attestation"
ML_DSA_87_PK_LEN = 2592
ML_DSA_87_SIG_LEN = 4627

# --- PKCS#11 constants (from crates/pkcs11-sys/include/pkcs11t.h) ---
CKU_USER = 1
CKO_PUBLIC_KEY = 0x00000002
CKO_PRIVATE_KEY = 0x00000003
CKA_CLASS = 0x00000000
CKA_VALUE = 0x00000011
CKA_ID = 0x00000102
CKH_HEDGE_PREFERRED = 0x00000000
CKM_ML_DSA = 0x0000001D
CKR_OK = 0

# Yubico vendor mechanism -- CKM_VENDOR_DEFINED (0x80000000) |
# YUBICO_BASE_VENDOR (0x59554200), +1 (see mechanisms.rs's own doc
# comment on CKM_YUBICO_ML_DSA_EXTERNAL_MU for the derivation).
CKM_YUBICO_ML_DSA_EXTERNAL_MU = 0xD9554201

# --- ctypes layer ---
CK_ULONG = ctypes.c_ulong
CK_RV = CK_ULONG
CK_SLOT_ID = CK_ULONG
CK_SESSION_HANDLE = CK_ULONG
CK_OBJECT_HANDLE = CK_ULONG
CK_USER_TYPE = CK_ULONG
CK_FLAGS = CK_ULONG
CK_BBOOL = ctypes.c_ubyte


class CK_ATTRIBUTE(ctypes.Structure):
    _fields_ = [
        ("type", CK_ULONG),
        ("pValue", ctypes.c_void_p),
        ("ulValueLen", CK_ULONG),
    ]


class CK_MECHANISM(ctypes.Structure):
    _fields_ = [
        ("mechanism", CK_ULONG),
        ("pParameter", ctypes.c_void_p),
        ("ulParameterLen", CK_ULONG),
    ]


class CK_SIGN_ADDITIONAL_CONTEXT(ctypes.Structure):
    _fields_ = [
        ("hedgeVariant", CK_ULONG),
        ("pContext", ctypes.c_void_p),
        ("ulContextLen", CK_ULONG),
    ]


def ml_dsa_mu(public_key: bytes, context: bytes, message: bytes) -> bytes:
    """FIPS 204 Algorithm 7's message representative -- identical formula to
    yubikit::__internal::padding::ml_dsa_mu, reimplemented here in pure
    Python so this script has no dependency on yubikit itself:
    mu = SHAKE256(SHAKE256(pk, 64) || 0x00 || len(ctx) || ctx || M, 64)
    """
    assert len(context) <= 255, "ML-DSA context must be at most 255 bytes"
    tr = hashlib.shake_256(public_key).digest(64)
    mu_input = tr + bytes([0, len(context)]) + context + message
    return hashlib.shake_256(mu_input).digest(64)


def check(rv: int, what: str) -> None:
    if rv != CKR_OK:
        raise SystemExit(f"{what} failed: rv=0x{rv:x}")


def find_object_handle(lib, h_session: int, class_: int, obj_id: bytes, what: str) -> int:
    class_buf = ctypes.create_string_buffer(class_.to_bytes(8, sys.byteorder), 8)
    id_buf = ctypes.create_string_buffer(obj_id, len(obj_id))
    template = (CK_ATTRIBUTE * 2)()
    template[0].type = CKA_CLASS
    template[0].pValue = ctypes.cast(class_buf, ctypes.c_void_p)
    template[0].ulValueLen = 8
    template[1].type = CKA_ID
    template[1].pValue = ctypes.cast(id_buf, ctypes.c_void_p)
    template[1].ulValueLen = len(obj_id)

    check(lib.C_FindObjectsInit(h_session, template, 2), f"C_FindObjectsInit ({what})")
    handles = (CK_OBJECT_HANDLE * 1)()
    count = CK_ULONG(0)
    check(lib.C_FindObjects(h_session, handles, 1, ctypes.byref(count)), f"C_FindObjects ({what})")
    check(lib.C_FindObjectsFinal(h_session), f"C_FindObjectsFinal ({what})")
    if count.value != 1:
        raise SystemExit(f"{what}: expected exactly one object, found {count.value}")
    return handles[0]


def get_attribute(lib, h_session: int, h_object: int, attr_type: int, length: int, what: str) -> bytes:
    buf = ctypes.create_string_buffer(length)
    template = (CK_ATTRIBUTE * 1)()
    template[0].type = attr_type
    template[0].pValue = ctypes.cast(buf, ctypes.c_void_p)
    template[0].ulValueLen = length
    check(lib.C_GetAttributeValue(h_session, h_object, template, 1), f"C_GetAttributeValue ({what})")
    return buf.raw


def main() -> None:
    lib = ctypes.CDLL(LIB_PATH)

    lib.C_Initialize.argtypes = [ctypes.c_void_p]
    lib.C_Initialize.restype = CK_RV
    lib.C_Finalize.argtypes = [ctypes.c_void_p]
    lib.C_Finalize.restype = CK_RV
    lib.C_GetSlotList.argtypes = [CK_BBOOL, ctypes.POINTER(CK_SLOT_ID), ctypes.POINTER(CK_ULONG)]
    lib.C_GetSlotList.restype = CK_RV
    lib.C_OpenSession.argtypes = [
        CK_SLOT_ID, CK_FLAGS, ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(CK_SESSION_HANDLE)
    ]
    lib.C_OpenSession.restype = CK_RV
    lib.C_CloseSession.argtypes = [CK_SESSION_HANDLE]
    lib.C_CloseSession.restype = CK_RV
    lib.C_Login.argtypes = [CK_SESSION_HANDLE, CK_USER_TYPE, ctypes.c_char_p, CK_ULONG]
    lib.C_Login.restype = CK_RV
    lib.C_Logout.argtypes = [CK_SESSION_HANDLE]
    lib.C_Logout.restype = CK_RV
    lib.C_FindObjectsInit.argtypes = [CK_SESSION_HANDLE, ctypes.POINTER(CK_ATTRIBUTE), CK_ULONG]
    lib.C_FindObjectsInit.restype = CK_RV
    lib.C_FindObjects.argtypes = [
        CK_SESSION_HANDLE, ctypes.POINTER(CK_OBJECT_HANDLE), CK_ULONG, ctypes.POINTER(CK_ULONG)
    ]
    lib.C_FindObjects.restype = CK_RV
    lib.C_FindObjectsFinal.argtypes = [CK_SESSION_HANDLE]
    lib.C_FindObjectsFinal.restype = CK_RV
    lib.C_GetAttributeValue.argtypes = [
        CK_SESSION_HANDLE, CK_OBJECT_HANDLE, ctypes.POINTER(CK_ATTRIBUTE), CK_ULONG
    ]
    lib.C_GetAttributeValue.restype = CK_RV
    lib.C_SignInit.argtypes = [CK_SESSION_HANDLE, ctypes.POINTER(CK_MECHANISM), CK_OBJECT_HANDLE]
    lib.C_SignInit.restype = CK_RV
    lib.C_Sign.argtypes = [
        CK_SESSION_HANDLE, ctypes.POINTER(ctypes.c_ubyte), CK_ULONG,
        ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(CK_ULONG)
    ]
    lib.C_Sign.restype = CK_RV
    lib.C_VerifyInit.argtypes = [CK_SESSION_HANDLE, ctypes.POINTER(CK_MECHANISM), CK_OBJECT_HANDLE]
    lib.C_VerifyInit.restype = CK_RV
    lib.C_Verify.argtypes = [
        CK_SESSION_HANDLE, ctypes.POINTER(ctypes.c_ubyte), CK_ULONG,
        ctypes.POINTER(ctypes.c_ubyte), CK_ULONG
    ]
    lib.C_Verify.restype = CK_RV

    check(lib.C_Initialize(None), "C_Initialize")

    count = CK_ULONG(0)
    check(lib.C_GetSlotList(1, None, ctypes.byref(count)), "C_GetSlotList (count)")
    if count.value == 0:
        raise SystemExit("no YubiKey detected -- plug one in first")
    slots = (CK_SLOT_ID * count.value)()
    check(lib.C_GetSlotList(1, slots, ctypes.byref(count)), "C_GetSlotList (fill)")
    slot_id = slots[0]

    h_session = CK_SESSION_HANDLE(0)
    check(lib.C_OpenSession(slot_id, 0x00000006, None, None, ctypes.byref(h_session)), "C_OpenSession")
    h_session = h_session.value

    # External-mu signing is a private-key crypto op (AUTHENTICATE APDU),
    # gated on CKU_USER PIN verification -- no management-key login needed
    # at all here, since we're reusing an existing key rather than
    # importing/generating one.
    check(lib.C_Login(h_session, CKU_USER, DEFAULT_USER_PIN, len(DEFAULT_USER_PIN)), "C_Login(CKU_USER)")

    h_pub = find_object_handle(lib, h_session, CKO_PUBLIC_KEY, ML_DSA_ID, "ML-DSA public key")
    h_priv = find_object_handle(lib, h_session, CKO_PRIVATE_KEY, ML_DSA_ID, "ML-DSA private key")

    public_key = get_attribute(lib, h_session, h_pub, CKA_VALUE, ML_DSA_87_PK_LEN, "public key CKA_VALUE")

    message = b"a message long enough that a constrained signer would " \
              b"rather not re-hash it on-device" * 50
    context = b"yubikit context"
    mu = ml_dsa_mu(public_key, context, message)
    print(f"computed mu ({len(mu)} bytes): {mu.hex()}")

    # --- Sign via the new vendor mechanism ---
    mechanism = CK_MECHANISM(mechanism=CKM_YUBICO_ML_DSA_EXTERNAL_MU, pParameter=None, ulParameterLen=0)
    check(lib.C_SignInit(h_session, ctypes.byref(mechanism), h_priv), "C_SignInit (external-mu)")

    mu_buf = (ctypes.c_ubyte * len(mu)).from_buffer_copy(mu)
    sig_buf = (ctypes.c_ubyte * ML_DSA_87_SIG_LEN)()
    sig_len = CK_ULONG(ML_DSA_87_SIG_LEN)
    check(
        lib.C_Sign(h_session, mu_buf, len(mu), sig_buf, ctypes.byref(sig_len)),
        "C_Sign (external-mu)",
    )
    signature = bytes(sig_buf[: sig_len.value])
    print(f"signed, signature_len={sig_len.value}")

    # --- Verify via the already-proven context-aware CKM_ML_DSA path,
    # against the ORIGINAL message and context (not mu) ---
    def verify(ctx: bytes, msg: bytes, sig: bytes) -> int:
        # ctx_buf must be a named local, not an inline temporary -- ctypes
        # doesn't keep a pValue/pContext target alive just because a raw
        # pointer references it (see make_template's own doc comment in
        # ml_kem_roundtrip.py for the full explanation of this pitfall).
        ctx_buf = ctypes.create_string_buffer(ctx, len(ctx)) if ctx else None
        additional_context = CK_SIGN_ADDITIONAL_CONTEXT(
            hedgeVariant=CKH_HEDGE_PREFERRED,
            pContext=ctypes.cast(ctx_buf, ctypes.c_void_p) if ctx_buf else None,
            ulContextLen=len(ctx),
        )
        verify_mechanism = CK_MECHANISM(
            mechanism=CKM_ML_DSA,
            pParameter=ctypes.byref(additional_context) if ctx else None,
            ulParameterLen=ctypes.sizeof(additional_context) if ctx else 0,
        )
        check(lib.C_VerifyInit(h_session, ctypes.byref(verify_mechanism), h_pub), "C_VerifyInit")
        msg_buf = (ctypes.c_ubyte * len(msg)).from_buffer_copy(msg)
        sig_buf2 = (ctypes.c_ubyte * len(sig)).from_buffer_copy(sig)
        return lib.C_Verify(h_session, msg_buf, len(msg), sig_buf2, len(sig))

    rv = verify(context, message, signature)
    if rv == CKR_OK:
        print("VERIFIED: external-mu signature verifies against the original message+context")
    else:
        raise SystemExit(f"FAILED: signature did not verify (rv=0x{rv:x})")

    # --- Negative check: wrong context must fail verification ---
    rv = verify(b"wrong context", message, signature)
    if rv != CKR_OK:
        print(f"OK: verification with the wrong context correctly failed (rv=0x{rv:x})")
    else:
        raise SystemExit("BUG: signature verified with the wrong context")

    # --- Negative check: wrong-length mu must be rejected client-side ---
    short_mu = mu[:32]
    check(lib.C_SignInit(h_session, ctypes.byref(mechanism), h_priv), "C_SignInit (short mu)")
    short_buf = (ctypes.c_ubyte * len(short_mu)).from_buffer_copy(short_mu)
    sig_buf2 = (ctypes.c_ubyte * ML_DSA_87_SIG_LEN)()
    sig_len2 = CK_ULONG(ML_DSA_87_SIG_LEN)
    rv = lib.C_Sign(h_session, short_buf, len(short_mu), sig_buf2, ctypes.byref(sig_len2))
    if rv != CKR_OK:
        print(f"OK: signing a 32-byte (wrong-length) mu correctly failed (rv=0x{rv:x})")
    else:
        raise SystemExit("BUG: signing accepted a wrong-length mu")

    check(lib.C_Logout(h_session), "C_Logout")
    check(lib.C_CloseSession(h_session), "C_CloseSession")
    check(lib.C_Finalize(None), "C_Finalize")


if __name__ == "__main__":
    main()
