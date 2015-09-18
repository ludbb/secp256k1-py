import os
import json
import pytest

import secp256k1

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(HERE, 'data')


def test_ecdsa():
    data = open(os.path.join(DATA, 'ecdsa_sig.json')).read()
    vec = json.loads(data)['vectors']

    inst = secp256k1.PrivateKey()

    for item in vec:
        seckey = bytes(bytearray.fromhex(item['privkey']))
        msg32 = bytes(bytearray.fromhex(item['msg']))
        sig = bytes(bytearray.fromhex(item['sig'])[:-1])

        inst.set_raw_privkey(seckey)

        sig_raw = inst.ecdsa_sign(msg32, raw=True)
        sig_check = inst.ecdsa_serialize(sig_raw)
        assert sig_check == sig
        assert inst.ecdsa_serialize(inst.ecdsa_deserialize(sig_check)) == sig_check

        assert inst.public_key.ecdsa_verify(msg32, sig_raw, raw=True)

def test_ecdsa_recover():
    if not secp256k1.HAS_RECOVERABLE:
        pytest.skip('secp256k1_recoverable not enabled, skipping')
        return

    class MyECDSA(secp256k1.Base, secp256k1.ECDSA):
        def __init__(self):
            secp256k1.Base.__init__(self, ctx=None, flags=secp256k1.ALL_FLAGS)

    privkey = secp256k1.PrivateKey()
    unrelated = MyECDSA()

    # Create a signature that allows recovering the public key.
    recsig = privkey.ecdsa_sign_recoverable(b'hello')
    # Recover the public key.
    pubkey = unrelated.ecdsa_recover(b'hello', recsig)
    # Check that the recovered public key matches the one used
    # in privkey.public_key.
    pubser = secp256k1.PublicKey(pubkey).serialize()
    assert privkey.public_key.serialize() == pubser

    # Check that after serializing and deserializing recsig
    # we still recover the same public key.
    recsig_ser = unrelated.ecdsa_recoverable_serialize(recsig)
    recsig2 = unrelated.ecdsa_recoverable_deserialize(*recsig_ser)
    pubkey2 = unrelated.ecdsa_recover(b'hello', recsig2)
    pubser2 = secp256k1.PublicKey(pubkey2).serialize()
    assert pubser == pubser2

    raw_sig = unrelated.ecdsa_recoverable_convert(recsig2)
    unrelated.ecdsa_deserialize(unrelated.ecdsa_serialize(raw_sig))
