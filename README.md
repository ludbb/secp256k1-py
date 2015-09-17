# secp256k1-py
FFI bindings for secp256k1

```
pip install secp256k1
```

[![Build Status](https://travis-ci.org/ludbb/secp256k1-py.svg?branch=master)](https://travis-ci.org/ludbb/secp256k1-py)


## Example

```
from secp256k1 import PrivateKey, PublicKey

privkey = PrivateKey()
privkey_der = privkey.serialize()
assert privkey.deserialize(privkey_der) == privkey.private_key

sig = privkey.ecdsa_sign(b'hello')
verified = privkey.public_key.ecdsa_verify(b'hello', sig)
assert verified

sig_der = privkey.ecdsa_serialize(sig)
sig2 = privkey.ecdsa_deserialize(sig_der)
vrf2 = privkey.public_key.ecdsa_verify(b'hello', sig2)
assert vrf2

pubkey = privkey.public_key
pub = pubkey.serialize()

pubkey2 = PublicKey(pub)
assert pubkey2.serialize() == pub
assert pubkey2.ecdsa_verify(b'hello', sig)
```

```
from secp256k1 import PrivateKey

key = '31a84594060e103f5a63eb742bd46cf5f5900d8406e2726dedfc61c7cf43ebad'
msg = '9e5755ec2f328cc8635a55415d0e9a09c2b6f2c9b0343c945fbbfe08247a4cbe'
sig = '30440220132382ca59240c2e14ee7ff61d90fc63276325f4cbe8169fc53ade4a407c2fc802204d86fbe3bde6975dd5a91fdc95ad6544dcdf0dab206f02224ce7e2b151bd82ab'

privkey = PrivateKey(bytes(bytearray.fromhex(key)), raw=True)
sig_check = privkey.ecdsa_sign(bytes(bytearray.fromhex(msg)), raw=True)
sig_ser = privkey.ecdsa_serialize(sig_check)

assert sig_ser == bytes(bytearray.fromhex(sig))
```

```
from secp256k1 import PrivateKey

key = '7ccca75d019dbae79ac4266501578684ee64eeb3c9212105f7a3bdc0ddb0f27e'
pub_compressed = '03e9a06e539d6bf5cf1ca5c41b59121fa3df07a338322405a312c67b6349a707e9'
pub_uncompressed = '04e9a06e539d6bf5cf1ca5c41b59121fa3df07a338322405a312c67b6349a707e94c181c5fe89306493dd5677143a329065606740ee58b873e01642228a09ecf9d'

privkey = PrivateKey(bytes(bytearray.fromhex(key)), raw=True)
pubkey_ser = privkey.public_key.serialize()
pubkey_ser_uncompressed = privkey.public_key.serialize(compressed=False)

assert pubkey_ser == bytes(bytearray.fromhex(pub_compressed))
assert pubkey_ser_uncompressed == bytes(bytearray.fromhex(pub_uncompressed))
```
