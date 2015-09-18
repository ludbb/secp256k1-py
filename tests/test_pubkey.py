import os
import json

import secp256k1

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(HERE, 'data')


def test_pubkey_from_privkey():
    data = open(os.path.join(DATA, 'pubkey.json')).read()
    vec = json.loads(data)['vectors']

    inst = secp256k1.PrivateKey()

    for item in vec:
        seckey = bytes(bytearray.fromhex(item['seckey']))
        pubkey_uncp = bytes(bytearray.fromhex(item['pubkey']))
        pubkey_comp = bytes(bytearray.fromhex(item['compressed']))

        inst.private_key = seckey
        inst._update_public_key()

        assert inst.public_key.serialize(compressed=False) == pubkey_uncp
        assert inst.public_key.serialize(compressed=True) == pubkey_comp

        assert inst.deserialize(inst.serialize(compressed=True)) == seckey
        assert inst.deserialize(inst.serialize(compressed=False)) == seckey
