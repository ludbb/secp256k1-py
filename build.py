import os
from cffi import FFI, ffiplatform


definitions = """
    /* secp256k1.h*/

    typedef struct secp256k1_context_struct secp256k1_context_t;

    typedef struct {
        unsigned char data[64];
    } secp256k1_pubkey_t;

    typedef struct {
        unsigned char data[64];
    } secp256k1_ecdsa_signature_t;

    typedef int (*secp256k1_nonce_function_t)(
        unsigned char *nonce32,
        const unsigned char *msg32,
        const unsigned char *key32,
        const unsigned char *algo16,
        const void *data,
        unsigned int attempt
    );

    #define SECP256K1_CONTEXT_VERIFY 1
    #define SECP256K1_CONTEXT_SIGN   2

    secp256k1_context_t* secp256k1_context_create(
        int flags
    );

    secp256k1_context_t* secp256k1_context_clone(
        const secp256k1_context_t* ctx
    );

    void secp256k1_context_destroy(
       secp256k1_context_t* ctx
    );

    int secp256k1_ec_pubkey_parse(
        const secp256k1_context_t* ctx,
        secp256k1_pubkey_t* pubkey,
        const unsigned char *input,
        int inputlen
    );

    int secp256k1_ec_pubkey_serialize(
        const secp256k1_context_t* ctx,
        unsigned char *output,
        int *outputlen,
        const secp256k1_pubkey_t* pubkey,
        int compressed
    );

    int secp256k1_ecdsa_signature_parse_der(
        const secp256k1_context_t* ctx,
        secp256k1_ecdsa_signature_t* sig,
        const unsigned char *input,
        int inputlen
    );

    int secp256k1_ecdsa_signature_serialize_der(
        const secp256k1_context_t* ctx,
        unsigned char *output,
        int *outputlen,
        const secp256k1_ecdsa_signature_t* sig
    );

    int secp256k1_ecdsa_verify(
        const secp256k1_context_t* ctx,
        const secp256k1_ecdsa_signature_t *sig,
        const unsigned char *msg32,
        const secp256k1_pubkey_t *pubkey
    );

    extern const secp256k1_nonce_function_t secp256k1_nonce_function_rfc6979;
    extern const secp256k1_nonce_function_t secp256k1_nonce_function_default;


    int secp256k1_ecdsa_sign(
        const secp256k1_context_t* ctx,
        secp256k1_ecdsa_signature_t *sig,
        const unsigned char *msg32,
        const unsigned char *seckey,
        secp256k1_nonce_function_t noncefp,
        const void *ndata
    );

    int secp256k1_ec_seckey_verify(
        const secp256k1_context_t* ctx,
        const unsigned char *seckey
    );

    int secp256k1_ec_pubkey_create(
        const secp256k1_context_t* ctx,
        secp256k1_pubkey_t *pubkey,
        const unsigned char *seckey
    );

    int secp256k1_ec_privkey_export(
        const secp256k1_context_t* ctx,
        unsigned char *privkey,
        int *privkeylen,
        const unsigned char *seckey,
        int compressed
    );

    int secp256k1_ec_privkey_import(
        const secp256k1_context_t* ctx,
        unsigned char *seckey,
        const unsigned char *privkey,
        int privkeylen
    );

    int secp256k1_ec_privkey_tweak_add(
        const secp256k1_context_t* ctx,
        unsigned char *seckey,
        const unsigned char *tweak
    );

    int secp256k1_ec_pubkey_tweak_add(
        const secp256k1_context_t* ctx,
        secp256k1_pubkey_t *pubkey,
        const unsigned char *tweak
    );

    int secp256k1_ec_privkey_tweak_mul(
        const secp256k1_context_t* ctx,
        unsigned char *seckey,
        const unsigned char *tweak
    );

    int secp256k1_ec_pubkey_tweak_mul(
        const secp256k1_context_t* ctx,
        secp256k1_pubkey_t *pubkey,
        const unsigned char *tweak
    );

    int secp256k1_context_randomize(
        secp256k1_context_t* ctx,
        const unsigned char *seed32
    );

    int secp256k1_ec_pubkey_combine(
        const secp256k1_context_t* ctx,
        secp256k1_pubkey_t *out,
        const secp256k1_pubkey_t * const * ins,
        int n
    );
"""

definitions_recovery = """
    /* secp256k1_recovery.h */

    typedef struct {
        unsigned char data[65];
    } secp256k1_ecdsa_recoverable_signature_t;

    int secp256k1_ecdsa_recoverable_signature_parse_compact(
        const secp256k1_context_t* ctx,
        secp256k1_ecdsa_recoverable_signature_t* sig,
        const unsigned char *input64,
        int recid
    );

    int secp256k1_ecdsa_recoverable_signature_convert(
        const secp256k1_context_t* ctx,
        secp256k1_ecdsa_signature_t* sig,
        const secp256k1_ecdsa_recoverable_signature_t* sigin
    );

    int secp256k1_ecdsa_recoverable_signature_serialize_compact(
        const secp256k1_context_t* ctx,
        unsigned char *output64,
        int *recid,
        const secp256k1_ecdsa_recoverable_signature_t* sig
    );

    int secp256k1_ecdsa_sign_recoverable(
        const secp256k1_context_t* ctx,
        secp256k1_ecdsa_recoverable_signature_t *sig,
        const unsigned char *msg32,
        const unsigned char *seckey,
        secp256k1_nonce_function_t noncefp,
        const void *ndata
    );

    int secp256k1_ecdsa_recover(
        const secp256k1_context_t* ctx,
        secp256k1_pubkey_t *pubkey,
        const secp256k1_ecdsa_recoverable_signature_t *sig,
        const unsigned char *msg32
    );
"""

definitions_schnorr = """
    /* secp256k1_schnorr.h */

    int secp256k1_schnorr_sign(
        const secp256k1_context_t* ctx,
        unsigned char *sig64,
        const unsigned char *msg32,
        const unsigned char *seckey,
        secp256k1_nonce_function_t noncefp,
        const void *ndata
    );

    int secp256k1_schnorr_verify(
        const secp256k1_context_t* ctx,
        const unsigned char *sig64,
        const unsigned char *msg32,
        const secp256k1_pubkey_t *pubkey
    );

    int secp256k1_schnorr_recover(
        const secp256k1_context_t* ctx,
        secp256k1_pubkey_t *pubkey,
        const unsigned char *sig64,
        const unsigned char *msg32
    );

    int secp256k1_schnorr_generate_nonce_pair(
        const secp256k1_context_t* ctx,
        secp256k1_pubkey_t *pubnonce,
        unsigned char *privnonce32,
        const unsigned char *msg32,
        const unsigned char *sec32,
        secp256k1_nonce_function_t noncefp,
        const void* noncedata
    );

    int secp256k1_schnorr_partial_sign(
        const secp256k1_context_t* ctx,
        unsigned char *sig64,
        const unsigned char *msg32,
        const unsigned char *sec32,
        const secp256k1_pubkey_t *pubnonce_others,
        const unsigned char *secnonce32
    );

    int secp256k1_schnorr_partial_combine(
        const secp256k1_context_t* ctx,
        unsigned char *sig64,
        const unsigned char * const * sig64sin,
        int n
    );
"""


def build_ffi(include_recovery=True, include_schnorr=True):
    ffi = FFI()

    source = "#include <secp256k1.h>"
    cdefs = definitions
    if include_recovery:
        cdefs += definitions_recovery
        source += "\n#include <secp256k1_recovery.h>"
    if include_schnorr:
        cdefs += definitions_schnorr
        source += "\n#include <secp256k1_schnorr.h>"

    incpath = [os.environ['INCLUDE_DIR']] if 'INCLUDE_DIR' in os.environ else None
    libpath = [os.environ['LIB_DIR']] if 'LIB_DIR' in os.environ else None

    ffi.set_source(
        "_libsecp256k1",
        source,
        libraries=["secp256k1"],
        library_dirs=libpath,
        include_dirs=incpath)
    ffi.cdef(cdefs)

    return ffi


_attempts = ((True, True), (True, False), (False, True), (False, False))
_map = {0: 'secp256k1_recovery', 1: 'secp256k1_schnorr'}
for opt in _attempts:
    try:
        ffi = build_ffi(*opt)
        ffi.compile()
        _msg = '\n'.join("{} not supported".format(_map[i])
            for i, entry in enumerate(opt) if not entry)
        print(_msg)
        break
    except ffiplatform.VerificationError:
        pass
