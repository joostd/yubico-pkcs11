#!/usr/bin/env python3
"""Chain ykcs11's two external-mu mechanisms: have the token compute mu with
CKM_ML_DSA_EXTERNAL_MU_GEN (0x403b), then sign that mu with
CKM_ML_DSA_EXTERNAL_MU (0x403c).

Unlike ml_dsa_external_mu_test.py, which computes mu in Python and drives
the library through raw ctypes, this one never implements FIPS 204's
framing at all -- that is the point of the _GEN mechanism -- and it uses
PyKCS11 rather than ctypes. PyKCS11 turns out to be sufficient for both
mechanisms: it takes an arbitrary mechanism number, and it passes an
arbitrary bytes object through as the mechanism parameter, which is what
CK_MU_GEN_PARAMS needs.

Why bother having the token do it:

  * The FIPS 204 framing (the 0x00 domain separator, the single-byte
    context length, tr = SHAKE256(pk, 64)) is easy to get subtly wrong, and
    a wrong mu does not announce itself -- it produces a signature that
    simply fails to verify, with nothing to say why.
  * Passing a key handle means never having to pull the raw public key out
    of a SubjectPublicKeyInfo, which is the fiddliest part of doing it by
    hand.
  * mu generation is a host-side SHAKE256 computation, so unlike raw
    signing it is not bounded by the device's APDU limits. A message far
    too large to sign directly still yields a mu in one pass.

The signature that comes out is an ordinary ML-DSA signature over the
message, so the check at the end verifies it against the ORIGINAL message
rather than against mu. That matters: if mu were computed wrongly, a
verify against mu would still pass, and this would not.

Usage:
    python3 scripts/ml_dsa_external_mu_gen.py [path/to/libykcs11] [CKA_ID hex]

Requires PyKCS11 (pip install PyKCS11) and a YubiKey holding an ML-DSA key.
"""

import ctypes
import sys

import PyKCS11

LIB_PATH = sys.argv[1] if len(sys.argv) > 1 else "target/debug/libykcs11.so"
ML_DSA_ID = bytes.fromhex(sys.argv[2]) if len(sys.argv) > 2 else bytes([0x02])
DEFAULT_USER_PIN = "123456"

CKM_ML_DSA = 0x0000001D
CKM_ML_DSA_EXTERNAL_MU_GEN = 0x0000403B
CKM_ML_DSA_EXTERNAL_MU = 0x0000403C

# An application-chosen domain separator, bound into the signature. It is
# folded into mu by the token, so it is never passed to the signing call.
CONTEXT = b"ml_dsa_external_mu_gen.py"
MESSAGE = b"The quick brown fox jumps over the lazy dog" * 4096  # ~176 kB


class CK_MU_GEN_PARAMS(ctypes.Structure):
    """PKCS#11 3.3 parameter for CKM_ML_DSA_EXTERNAL_MU_GEN.

    Supplies either a key handle to derive tr from, or a precomputed tr --
    exactly one, not both. An optional context is folded into mu.
    """

    _fields_ = [
        ("hKey", ctypes.c_ulong),
        ("pTR", ctypes.c_void_p),
        ("ulTRLen", ctypes.c_ulong),
        ("pctx", ctypes.c_void_p),
        ("ulctxLen", ctypes.c_ulong),
    ]


class CK_SIGN_ADDITIONAL_CONTEXT(ctypes.Structure):
    """PKCS#11 3.2 parameter for plain CKM_ML_DSA, used here only to verify
    with the same context that was folded into mu. PyKCS11 has no binding
    for it, so it is marshalled by hand like CK_MU_GEN_PARAMS above."""

    _fields_ = [
        ("hedgeVariant", ctypes.c_ulong),
        ("pContext", ctypes.c_void_p),
        ("ulContextLen", ctypes.c_ulong),
    ]


CKH_HEDGE_PREFERRED = 0


def sign_additional_context(context: bytes):
    """Marshal CK_SIGN_ADDITIONAL_CONTEXT. Returns the bytes and the buffer
    they point at, which must stay alive for the duration of the call."""
    buf = ctypes.create_string_buffer(context, len(context))
    params = CK_SIGN_ADDITIONAL_CONTEXT(
        CKH_HEDGE_PREFERRED, ctypes.cast(buf, ctypes.c_void_p).value, len(context)
    )
    return bytes(memoryview(params).cast("B")), buf


def mu_gen_params(key_handle: int, context: bytes):
    """Marshal CK_MU_GEN_PARAMS into the bytes PyKCS11 passes through.

    The struct holds a *pointer* to the context, so the buffer backing it
    has to outlive the call -- hence returning it alongside the bytes for
    the caller to keep alive.
    """
    ctx_buf = ctypes.create_string_buffer(context, len(context)) if context else None
    params = CK_MU_GEN_PARAMS(
        key_handle,
        None,
        0,
        ctypes.cast(ctx_buf, ctypes.c_void_p).value if context else None,
        len(context),
    )
    return bytes(memoryview(params).cast("B")), ctx_buf


def find(session, cls, cka_id):
    objs = session.findObjects([(PyKCS11.CKA_CLASS, cls), (PyKCS11.CKA_ID, tuple(cka_id))])
    if not objs:
        sys.exit(f"no object of class {cls} with CKA_ID {cka_id.hex()}")
    return objs[0]


def main() -> None:
    lib = PyKCS11.PyKCS11Lib()
    lib.load(LIB_PATH)

    slots = lib.getSlotList(tokenPresent=True)
    if not slots:
        sys.exit("no token present")
    if len(slots) > 1:
        print(f"note: {len(slots)} tokens present, using the first", file=sys.stderr)

    session = lib.openSession(slots[0], PyKCS11.CKF_SERIAL_SESSION)
    session.login(DEFAULT_USER_PIN)
    try:
        pub = find(session, PyKCS11.CKO_PUBLIC_KEY, ML_DSA_ID)
        priv = find(session, PyKCS11.CKO_PRIVATE_KEY, ML_DSA_ID)

        # 1. Ask the token for mu. The message never reaches the card, so
        #    its size is not subject to the limits that bound raw signing.
        params, _keepalive = mu_gen_params(int(pub.value()), CONTEXT)
        mu = bytes(
            session.digest(MESSAGE, PyKCS11.Mechanism(CKM_ML_DSA_EXTERNAL_MU_GEN, params))
        )
        print(f"mu over a {len(MESSAGE)}-byte message: {len(mu)} bytes, {mu.hex()[:32]}...")

        # 2. Sign that mu. No mechanism parameter: the context is already
        #    inside mu, and the spec requires ulContextLen to be zero here.
        sig = bytes(
            session.sign(priv, mu, PyKCS11.Mechanism(CKM_ML_DSA_EXTERNAL_MU, None))
        )
        print(f"signature: {len(sig)} bytes")

        # 3. The result is an ordinary ML-DSA signature over the message.
        #    Verify it as such -- against the message and context, not mu --
        #    so that a wrongly computed mu cannot pass.
        add_ctx, _ctx_keepalive = sign_additional_context(CONTEXT)
        try:
            session.verify(
                pub, MESSAGE, sig, PyKCS11.Mechanism(CKM_ML_DSA, add_ctx)
            )
            print("verified against the original message: OK")
        except PyKCS11.PyKCS11Error as exc:
            sys.exit(f"verification against the original message failed: {exc}")
    finally:
        session.logout()
        session.closeSession()


if __name__ == "__main__":
    main()
