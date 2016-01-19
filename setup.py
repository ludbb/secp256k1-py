from setuptools import setup

classifiers = [
    "Intended Audience :: Developers",
    "License :: OSI Approved :: MIT License",
    "Programming Language :: Python :: 2",
    "Programming Language :: Python :: 3",
    "Topic :: Software Development :: Libraries",
    "Topic :: Security :: Cryptography"
]

setup(
    name="secp256k1-transient",
    version="0.11.1",
    description='FFI bindings to secp256k1',
    author='Pawel Bylica',
    author_email='chfast@gmail.com',
    url='https://github.com/chfast/secp256k1-py',
    license='MIT',
    classifiers=classifiers,
    py_modules=['secp256k1'],
    setup_requires=['cffi>=1.0.0', 'pytest-runner'],
    cffi_modules=['build.py:ffi'],
    install_requires=['cffi>=1.0.0'],
    tests_require=['pytest']
)
