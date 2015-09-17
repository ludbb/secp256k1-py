import pytest
import secp256k1

def test_values():
    assert secp256k1.FLAG_VERIFY == 1
    assert secp256k1.FLAG_SIGN == 2
    assert secp256k1.ALL_FLAGS == secp256k1.FLAG_SIGN | secp256k1.FLAG_VERIFY

def test_privkey():
    with pytest.raises(AssertionError):
        secp256k1.PrivateKey(flags=secp256k1.FLAG_VERIFY)
        secp256k1.PrivateKey(flags=0)

    privkey = secp256k1.PrivateKey(flags=secp256k1.FLAG_SIGN)
    sig = privkey.ecdsa_sign(b'hi')
    with pytest.raises(Exception):
        # FLAG_SIGN was not specified.
        privkey.public_key.ecdsa_verify(b'hi', sig)

    assert privkey.flags == privkey.public_key.flags

    privkey = secp256k1.PrivateKey()
    sig = privkey.ecdsa_sign(b'hi')
    assert privkey.public_key.ecdsa_verify(b'hi', sig)

def test_pubkey():
    privkey = secp256k1.PrivateKey()
    sig = privkey.ecdsa_sign(b'hello')
    pubkeyser = privkey.public_key.serialize()

    pubkey = secp256k1.PublicKey(pubkeyser, flags=0)
    with pytest.raises(Exception):
        # FLAG_SIGN was not specified.
        pubkey.ecdsa_verify(b'hello', sig)

    pubkey = secp256k1.PublicKey(pubkeyser)
    assert pubkey.ecdsa_verify(b'hello', sig)
