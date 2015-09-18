import os
import json

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

        inst.private_key = seckey
        inst._update_public_key()

        sig_raw = inst.ecdsa_sign(msg32, raw=True)
        sig_check = inst.ecdsa_serialize(sig_raw)
        assert sig_check == sig
        assert inst.ecdsa_serialize(inst.ecdsa_deserialize(sig_check)) == sig_check

        assert inst.public_key.ecdsa_verify(msg32, sig_raw, raw=True)
