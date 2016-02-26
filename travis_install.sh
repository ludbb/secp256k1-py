#!/bin/bash

if [[ $BUNDLED -eq 0 ]]; then
  git clone git://github.com/bitcoin/secp256k1.git libsecp256k1_ext
  pushd libsecp256k1_ext
  ./autogen.sh
  ./configure --enable-module-recovery --enable-experimental --enable-module-ecdh --enable-module-schnorr
  make
  popd
fi
