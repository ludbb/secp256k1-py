import errno
import os
import os.path
import shutil
import subprocess
import tarfile
from distutils import log
from distutils.command.build_clib import build_clib as _build_clib
from distutils.command.build_ext import build_ext as _build_ext
from distutils.errors import DistutilsError
from io import BytesIO
import sys

from setuptools import Distribution as _Distribution, setup, find_packages, __version__ as setuptools_version
from setuptools.command.develop import develop as _develop
from setuptools.command.egg_info import egg_info as _egg_info
from setuptools.command.sdist import sdist as _sdist
try:
    from wheel.bdist_wheel import bdist_wheel as _bdist_wheel
except ImportError:
    _bdist_wheel = None
    pass

try:
    from urllib2 import urlopen, URLError
except ImportError:
    from urllib.request import urlopen
    from urllib.error import URLError


sys.path.append(os.path.abspath(os.path.dirname(__file__)))
from setup_support import absolute, build_flags, has_system_lib


# Version of libsecp256k1 to download if none exists in the `libsecp256k1`
# directory
LIB_TARBALL_URL = "https://github.com/bitcoin-core/secp256k1/archive/1086fda4c1975d0cad8d3cad96794a64ec12dca4.tar.gz"


# We require setuptools >= 3.3
if [int(i) for i in setuptools_version.split('.')] < [3, 3]:
    raise SystemExit(
        "Your setuptools version ({}) is too old to correctly install this "
        "package. Please upgrade to a newer version (>= 3.3).".format(setuptools_version)
    )

# Ensure pkg-config is available
try:
    subprocess.check_call(['pkg-config', '--version'])
except OSError:
    raise SystemExit(
        "'pkg-config' is required to install this package. "
        "Please see the README for details."
    )


def download_library(command):
    if command.dry_run:
        return
    libdir = absolute("libsecp256k1")
    if os.path.exists(os.path.join(libdir, "autogen.sh")):
        # Library already downloaded
        return
    if not os.path.exists(libdir):
        command.announce("downloading libsecp256k1 source code", level=log.INFO)
        try:
            r = urlopen(LIB_TARBALL_URL)
            if r.getcode() == 200:
                content = BytesIO(r.read())
                content.seek(0)
                with tarfile.open(fileobj=content) as tf:
                    dirname = tf.getnames()[0].partition('/')[0]
                    tf.extractall()
                shutil.move(dirname, libdir)
            else:
                raise SystemExit(
                    "Unable to download secp256k1 library: HTTP-Status: %d",
                    r.getcode()
                )
        except URLError as ex:
            raise SystemExit("Unable to download secp256k1 library: %s",
                             ex.message)


class egg_info(_egg_info):
    def run(self):
        # Ensure library has been downloaded (sdist might have been skipped)
        download_library(self)

        _egg_info.run(self)


class sdist(_sdist):
    def run(self):
        download_library(self)
        _sdist.run(self)


if _bdist_wheel:
    class bdist_wheel(_bdist_wheel):
        def run(self):
            download_library(self)
            _bdist_wheel.run(self)
else:
    bdist_wheel = None


class Distribution(_Distribution):
    def has_c_libraries(self):
        return not has_system_lib()


class build_clib(_build_clib):
    def initialize_options(self):
        _build_clib.initialize_options(self)
        self.build_flags = None

    def finalize_options(self):
        _build_clib.finalize_options(self)
        if self.build_flags is None:
            self.build_flags = {
                'include_dirs': [],
                'library_dirs': [],
                'define': [],
            }

    def get_source_files(self):
        # Ensure library has been downloaded (sdist might have been skipped)
        download_library(self)

        return [
            absolute(os.path.join(root, filename))
            for root, _, filenames in os.walk(absolute("libsecp256k1"))
            for filename in filenames
        ]

    def build_libraries(self, libraries):
        raise Exception("build_libraries")

    def check_library_list(self, libraries):
        raise Exception("check_library_list")

    def get_library_names(self):
        return build_flags('libsecp256k1', 'l', os.path.abspath(self.build_temp))

    def run(self):
        if has_system_lib():
            log.info("Using system library")
            return

        build_temp = os.path.abspath(self.build_temp)

        try:
            os.makedirs(build_temp)
        except OSError as e:
            if e.errno != errno.EEXIST:
                raise

        if not os.path.exists(absolute("libsecp256k1/configure")):
            # configure script hasn't been generated yet
            autogen = absolute("libsecp256k1/autogen.sh")
            os.chmod(absolute(autogen), 0o755)
            subprocess.check_call(
                [autogen],
                cwd=absolute("libsecp256k1"),
            )

        for filename in [
            "libsecp256k1/configure",
            "libsecp256k1/build-aux/compile",
            "libsecp256k1/build-aux/config.guess",
            "libsecp256k1/build-aux/config.sub",
            "libsecp256k1/build-aux/depcomp",
            "libsecp256k1/build-aux/install-sh",
            "libsecp256k1/build-aux/missing",
            "libsecp256k1/build-aux/test-driver",
        ]:
            try:
                os.chmod(absolute(filename), 0o755)
            except OSError as e:
                # some of these files might not exist depending on autoconf version
                if e.errno != errno.ENOENT:
                    # If the error isn't "No such file or directory" something
                    # else is wrong and we want to know about it
                    raise

        cmd = [
            absolute("libsecp256k1/configure"),
            "--disable-shared",
            "--enable-static",
            "--disable-dependency-tracking",
            "--with-pic",
            "--enable-module-recovery",
            "--prefix",
            os.path.abspath(self.build_clib),
        ]
        if os.environ.get('SECP_BUNDLED_WITH_BIGNUM'):
            log.info("Building with bignum support (requires libgmp)")
            cmd.extend(["--with-bignum=gmp"])
        else:
            cmd.extend(["--without-bignum"])

        if os.environ.get('SECP_BUNDLED_EXPERIMENTAL'):
            log.info("Building experimental")
            cmd.extend([
                "--enable-experimental",
                "--enable-module-ecdh",
                "--enable-module-schnorr",
            ])

        log.debug("Running configure: {}".format(" ".join(cmd)))
        subprocess.check_call(
            cmd,
            cwd=build_temp,
        )

        subprocess.check_call(["make"], cwd=build_temp)
        subprocess.check_call(["make", "install"], cwd=build_temp)

        self.build_flags['include_dirs'].extend(build_flags('libsecp256k1', 'I', build_temp))
        self.build_flags['library_dirs'].extend(build_flags('libsecp256k1', 'L', build_temp))
        if not has_system_lib():
            self.build_flags['define'].append(('CFFI_ENABLE_RECOVERY', None))
        else:
            pass


class build_ext(_build_ext):
    def run(self):
        if self.distribution.has_c_libraries():
            build_clib = self.get_finalized_command("build_clib")
            self.include_dirs.append(
                os.path.join(build_clib.build_clib, "include"),
            )
            self.include_dirs.extend(build_clib.build_flags['include_dirs'])

            self.library_dirs.append(
                os.path.join(build_clib.build_clib, "lib"),
            )
            self.library_dirs.extend(build_clib.build_flags['library_dirs'])

            self.define = build_clib.build_flags['define']

        return _build_ext.run(self)


class develop(_develop):
    def run(self):
        if not has_system_lib():
            raise DistutilsError(
                "This library is not usable in 'develop' mode when using the "
                "bundled libsecp256k1. See README for details.")
        _develop.run(self)


setup(
    name="secp256k1",
    version="0.13.2",

    description='FFI bindings to libsecp256k1',
    url='https://github.com/ludbb/secp256k1-py',
    author='Ludvig Broberg',
    author_email='lud@tutanota.com',
    license='MIT',

    setup_requires=['cffi>=1.3.0', 'pytest-runner==2.6.2'],
    install_requires=['cffi>=1.3.0'],
    tests_require=['pytest==2.8.7'],

    packages=find_packages(exclude=('_cffi_build', '_cffi_build.*', 'libsecp256k1')),
    ext_package="secp256k1",
    cffi_modules=[
        "_cffi_build/build.py:ffi"
    ],

    cmdclass={
        'build_clib': build_clib,
        'build_ext': build_ext,
        'develop': develop,
        'egg_info': egg_info,
        'sdist': sdist,
        'bdist_wheel': bdist_wheel
    },
    distclass=Distribution,
    zip_safe=False,

    classifiers=[
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 2",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: Implementation :: CPython",
        "Programming Language :: Python :: Implementation :: PyPy",
        "Topic :: Software Development :: Libraries",
        "Topic :: Security :: Cryptography"
    ]
)
