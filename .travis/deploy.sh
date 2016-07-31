#!/bin/bash

set -e -x

echo "deploy"

# remove left over files from previous steps
rm -rf build dist
mkdir dist

python setup.py sdist

# On linux we want to build `manylinux1` wheels. See:
if [[ "$TRAVIS_OS_NAME" == "linux" && ${BUILD_LINUX_WHEELS} -eq 1 ]]; then
	docker run --rm -v $(pwd):/io ${WHEELBUILDER_IMAGE} /io/.travis/build-linux-wheels.sh
else
	# Only build wheels for the non experimental bundled version
	if [[ ${BUNDLED} -eq 1 && ${SECP_BUNDLED_EXPERIMENTAL} -eq 0 && "$TRAVIS_OS_NAME" == "osx" ]]; then
		python -m pip install wheel
		python setup.py bdist_wheel
	fi
fi

ls -l dist

python -m pip install twine

twine register dist/secp256k1*.tar.gz

# Ignore non-existing files in globs
shopt -s nullglob

twine upload --skip-existing dist/secp256k1*.{whl,gz}

set +e +x
