import pytest
import hashlib
import secp256k1

def test_privkey():
    with pytest.raises(TypeError):
        key = 'abc'
        secp256k1.PrivateKey(key)

    with pytest.raises(TypeError):
        key = bytearray.fromhex('a' * 32)  # This will result in 16 bytes.
        secp256k1.PrivateKey(bytes(key))

    with pytest.raises(Exception):
        secp256k1.PrivateKey(bytes(bytearray.fromhex('0' * 64)))

    with pytest.raises(Exception):
        secp256k1.PrivateKey(bytes(bytearray.fromhex('F' * 64)))

    with pytest.raises(Exception):
        # This is a good raw key, but here it's being passed as serialized.
        secp256k1.PrivateKey(b'1' * 32, raw=False)

    # "good" key, should be fine.
    assert secp256k1.PrivateKey(b'1' * 32)

def test_publickey():
    with pytest.raises(Exception):
        # Must be bytes.

        # In Python 2 this will not raise a TypeError
        # since bytes is an alias to str, instead it will fail
        # during serialization.
        secp256k1.PublicKey('abc', raw=True)
    with pytest.raises(Exception):
        secp256k1.PublicKey([], raw=True)

    with pytest.raises(Exception):
        # Invalid size.
        secp256k1.PublicKey(b'abc', raw=True)

    with pytest.raises(Exception):
        # Invalid public key.
        secp256k1.PublicKey(b'a' * 33, raw=True)

    # Invalid usage: passing a raw public key but not specifying raw=True.
    invalid = secp256k1.PublicKey(b'a' * 33)
    with pytest.raises(TypeError):
        invalid.serialize()

    # No public key.
    assert secp256k1.PublicKey()

def test_ecdsa():
    priv = secp256k1.PrivateKey()
    with pytest.raises(Exception):
        # Bad digestion function (doesn't produce 256 bits).
        priv.ecdsa_sign(b'hi', digest=hashlib.sha1)

    raw_sig = priv.ecdsa_sign(b'hi')
    assert priv.public_key.ecdsa_verify(b'hi', raw_sig)

    with pytest.raises(AssertionError):
        sig = priv.ecdsa_serialize(raw_sig)[:-1]
        priv.ecdsa_deserialize(sig)

    sig = priv.ecdsa_serialize(raw_sig)
    sig = sig[:-1] + bytes([sig[0]])  # Assuming sig[0] != sig[-1].
    invalid_sig = priv.ecdsa_deserialize(sig)
    assert not priv.public_key.ecdsa_verify(b'hi', invalid_sig)

test_ecdsa()
