from setuptools import setup

classifiers = [
    "Development Status :: 4 - Beta",
    "Intended Audience :: Developers",
    "License :: OSI Approved :: MIT License",
    "Programming Language :: Python :: 2",
    "Programming Language :: Python :: 3",
    "Topic :: Software Development :: Libraries",
    "Topic :: Security :: Cryptography"
]

setup(
    name="secp256k1",
    version="0.8.1",
    description='FFI bindings to secp256k1',
    author='Ludvig Broberg',
    author_email='lud@tutanota.com',
    url='https://github.com/ludbb/secp256k1-py',
    license='MIT',
    classifiers=classifiers,
    py_modules=['secp256k1', 'build'],
    setup_requires=['cffi>=1.0.0', 'pytest-runner'],
    cffi_modules=['build.py:ffi'],
    install_requires=['cffi>=1.0.0'],
    tests_require=['pytest']
)
