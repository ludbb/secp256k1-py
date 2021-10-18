import pytest

import secp256k1

def test_schnorr_simple():
    if not secp256k1.HAS_SCHNORR:
        pytest.skip('secp256k1_schnorr not enabled, skipping')
        return

    inst = secp256k1.PrivateKey()
    raw_sig = inst.schnorr_sign(b'hello', 'test_schnorr_simple')

    assert inst.pubkey.schnorr_verify(b'hello', raw_sig, 'test_schnorr_simple')
    assert not inst.pubkey.schnorr_verify(b'hello', raw_sig, 'test_schnorr_simple2')
    key2 = secp256k1.PrivateKey()
    assert not key2.pubkey.schnorr_verify(b'hello', raw_sig, 'test_schnorr_simple')
