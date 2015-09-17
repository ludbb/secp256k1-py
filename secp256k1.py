import os
import ctypes
import hashlib

from _libsecp256k1 import ffi, lib


FLAG_SIGN = lib.SECP256K1_CONTEXT_SIGN
FLAG_VERIFY = lib.SECP256K1_CONTEXT_VERIFY
ALL_FLAGS = FLAG_SIGN | FLAG_VERIFY


class Base(object):

    def __init__(self, ctx, flags):
        self._destroy = None
        if ctx is None:
            assert flags in (0, FLAG_SIGN, FLAG_VERIFY, ALL_FLAGS)
            ctx = lib.secp256k1_context_create(flags)
            self._destroy = lib.secp256k1_context_destroy

        self.ctx = ctx

    def __del__(self):
        if self._destroy and self.ctx:
            self._destroy(self.ctx)
            self.ctx = None


class ECDSA:  # Use as a mixin; instance.ctx is assumed to exist.

    def ecdsa_serialize(self, raw_sig):
        len_sig = 74
        output = ffi.new('unsigned char[%d]' % len_sig)
        outputlen = ffi.new('int *', len_sig)

        res = lib.secp256k1_ecdsa_signature_serialize_der(
            self.ctx, output, outputlen, raw_sig)
        assert res == 1

        return bytes(ffi.buffer(output, outputlen[0]))

    def ecdsa_deserialize(self, ser_sig):
        raw_sig = ffi.new('secp256k1_ecdsa_signature_t *')
        res = lib.secp256k1_ecdsa_signature_parse_der(
            self.ctx, raw_sig, ser_sig, len(ser_sig))
        assert res == 1

        return raw_sig


class PublicKey(Base, ECDSA):

    def __init__(self, pubkey=None, raw=False, ctx=None, flags=FLAG_VERIFY):
        Base.__init__(self, ctx, flags)
        if pubkey:
            if raw:
                self.public_key = pubkey
            else:
                self.public_key = self.deserialize(pubkey)
        else:
            self.public_key = None

    def serialize(self):
        assert self.public_key, "No public key defined"

        len_compressed = 33
        res_compressed = ffi.new('char [%d]' % len_compressed)
        outlen = ffi.new('int *', len_compressed)

        serialized = lib.secp256k1_ec_pubkey_serialize(
            self.ctx, res_compressed, outlen, self.public_key, 1)
        assert serialized == 1

        return bytes(ffi.buffer(res_compressed, len_compressed))

    def deserialize(self, pubkey_ser):
        pubkey = ffi.new('secp256k1_pubkey_t *')

        res = lib.secp256k1_ec_pubkey_parse(
            self.ctx, pubkey, pubkey_ser, len(pubkey_ser))
        assert res == 1

        return pubkey

    def ecdsa_verify(self, msg_bytes, raw_sig, digest=hashlib.sha256):
        assert self.public_key, "No public key defined"
        msg32 = digest(msg_bytes).digest()
        if len(msg32) * 8 != 256:
            raise Exception("digest function must produce 256 bits")

        result = lib.secp256k1_ecdsa_verify(
            self.ctx, raw_sig, msg32, self.public_key)

        return bool(result)


class PrivateKey(Base, ECDSA):

    def __init__(self, privkey=None, raw=False, ctx=None, flags=ALL_FLAGS):
        Base.__init__(self, ctx, flags)
        self.public_key = None
        self.private_key = None
        if privkey is None:
            self.gen_private_key()
        else:
            if raw:
                self.private_key = privkey
                self._update_public_key()
            else:
                self.deserialize(privkey)

    def _update_public_key(self):
        public_key = self._gen_public_key(self.private_key)
        self.public_key = PublicKey(public_key, raw=True, ctx=self.ctx)

    def gen_private_key(self):
        key = os.urandom(32)
        assert lib.secp256k1_ec_seckey_verify(self.ctx, key) == 1

        self.private_key = key
        self._update_public_key()
        return key

    def serialize(self):
        privser = ffi.new('char [279]')
        keylen = ffi.new('int *')

        res = lib.secp256k1_ec_privkey_export(
            self.ctx, privser, keylen, self.private_key, 1)
        assert res == 1

        return bytes(ffi.buffer(privser, keylen[0]))

    def deserialize(self, privkey_ser):
        privkey = ffi.new('char [32]')

        res = lib.secp256k1_ec_privkey_import(
            self.ctx, privkey, privkey_ser, len(privkey_ser))
        assert res == 1

        self.private_key = bytes(ffi.buffer(privkey, 32))
        self._update_public_key()
        return self.private_key

    def _gen_public_key(self, privkey):
        pubkey_ptr = ffi.new('secp256k1_pubkey_t *')

        created = lib.secp256k1_ec_pubkey_create(self.ctx, pubkey_ptr, privkey)
        assert created == 1

        return pubkey_ptr

    def ecdsa_sign(self, msg_bytes, digest=hashlib.sha256):
        msg32 = digest(msg_bytes).digest()
        if len(msg32) * 8 != 256:
            raise Exception("digest function must produce 256 bits")

        raw_sig = ffi.new('secp256k1_ecdsa_signature_t *')
        signed = lib.secp256k1_ecdsa_sign(
            self.ctx, raw_sig, msg32, self.private_key, ffi.NULL, ffi.NULL)
        assert signed == 1

        return raw_sig
