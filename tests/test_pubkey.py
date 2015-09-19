import os
import json
from io import StringIO

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

        inst.set_raw_privkey(seckey)

        assert inst.public_key.serialize(compressed=False) == pubkey_uncp
        assert inst.public_key.serialize(compressed=True) == pubkey_comp

        assert inst.deserialize(inst.serialize(compressed=True)) == seckey
        assert inst.deserialize(inst.serialize(compressed=False)) == seckey

def test_cli():
    parser, enc = secp256k1._parse_cli()

    args = parser.parse_args(['privkey', '-p'])
    out = StringIO()
    res = secp256k1._main_cli(args, out, enc)
    assert res == 0
    raw_privkey, raw_pubkey = out.getvalue().strip().split('\n')
    raw_pubkey = raw_pubkey.split(':')[1].strip()

    args = parser.parse_args(['privkey', '-k', raw_privkey, '-p'])
    out = StringIO()
    res = secp256k1._main_cli(args, out, enc)
    assert res == 0
    raw_privkey2, raw_pubkey2 = out.getvalue().strip().split('\n')
    raw_pubkey2 = raw_pubkey2.split(':')[1].strip()
    assert raw_privkey2 == raw_privkey
    assert raw_pubkey2 == raw_pubkey2
