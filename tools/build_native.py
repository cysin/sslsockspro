#!/usr/bin/env python3
"""Build ARM64 Android 16 native engines from pinned upstream sources."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import re
import subprocess
import sys
import fcntl
from contextlib import contextmanager
from bootstrap import ROOT, SDK, SOURCES, native_sources
from build_tools import perl

ABI = 'arm64-v8a'
NDK = SDK / 'ndk/30.0.16248370'
TOOLCHAIN = NDK / 'toolchains/llvm/prebuilt/linux-x86_64/bin'
WORK = ROOT / '.native/build' / ABI
OUTPUT = ROOT / 'app/src/main/jniLibs' / ABI
JOBS = str(min(os.cpu_count() or 2, 12))


def run(args, cwd, environment=None):
    print('Build:', Path(str(args[0])).name, str(cwd.relative_to(ROOT)), flush=True)
    subprocess.run(list(map(str, args)), cwd=cwd, env=environment, check=True)


def copied(name):
    output = WORK / name
    if not output.exists():
        shutil.copytree(SOURCES / name, output)
    return output


@contextmanager
def build_lock():
    path = ROOT / '.native/build.lock'
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('a') as stream:
        fcntl.flock(stream.fileno(), fcntl.LOCK_EX)
        yield


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--force', action='store_true')
    args = parser.parse_args()
    with build_lock():
        build(args)


def build(args):
    if not (NDK / 'ndk-build').exists():
        raise SystemExit('Run python3 tools/bootstrap.py --sdk-only first.')
    manifest = json.loads((ROOT / 'native-dependencies.json').read_text())
    fingerprint = hashlib.sha256((ROOT / 'native-dependencies.json').read_bytes()
        + (ROOT / 'app/src/main/cpp/protect_connect.c').read_bytes()
        + (ROOT / 'build-dependencies.json').read_bytes()
        + (ROOT / 'tools/bootstrap.py').read_bytes()
        + (ROOT / 'tools/build_tools.py').read_bytes()
        + Path(__file__).read_bytes()).hexdigest()
    stamp = OUTPUT / 'build.sha256'
    binaries = ('libstunnel_exec.so', 'libopenvpn_exec.so', 'libhev-socks5-tunnel.so')
    state = OUTPUT / 'artifacts.json'
    checksums = lambda: {name: hashlib.file_digest((OUTPUT / name).open('rb'), 'sha256').hexdigest() for name in binaries}
    if not args.force and stamp.exists() and stamp.read_text().strip() == fingerprint and state.exists() and \
            all((OUTPUT / name).exists() for name in binaries) and json.loads(state.read_text()) == checksums() and \
            (ROOT / 'app/src/main/assets/native-versions.json').exists():
        print('Verified native build already exists.', flush=True)
        return
    native_sources()
    perl_runtime = perl()
    # Changes to source versions, compiler setup, or native integration must
    # invalidate OpenSSL and copied sources as well as the final executables.
    if WORK.exists():
        shutil.rmtree(WORK)
    WORK.mkdir(parents=True, exist_ok=True)
    OUTPUT.mkdir(parents=True, exist_ok=True)
    compiler = TOOLCHAIN / 'aarch64-linux-android36-clang'
    flags = '-O2 -fPIE -fstack-protector-strong -ffile-prefix-map=' + str(ROOT) + '=.'
    linker = '-pie -Wl,-z,max-page-size=16384 -Wl,-z,relro,-z,now'
    environment = os.environ | {
        'ANDROID_NDK_ROOT': str(NDK), 'PATH': str(TOOLCHAIN) + os.pathsep + os.environ['PATH'],
        'CC': str(compiler), 'AR': str(TOOLCHAIN / 'llvm-ar'), 'RANLIB': str(TOOLCHAIN / 'llvm-ranlib'),
        'STRIP': str(TOOLCHAIN / 'llvm-strip'), 'CFLAGS': flags, 'LDFLAGS': linker,
        'SOURCE_DATE_EPOCH': '1791849600',
        'PERL': perl_runtime,
    }
    protect = WORK / 'protect_connect.o'
    run([compiler, *flags.split(), '-c', ROOT / 'app/src/main/cpp/protect_connect.c', '-o', protect], WORK, environment)
    openssl = WORK / 'openssl-build'
    openssl.mkdir(exist_ok=True)
    install_root = WORK / 'openssl-install'
    prefix = install_root / 'sslsockspro'
    if not (prefix / 'lib/libssl.a').exists() or args.force:
        run([perl_runtime, SOURCES / 'openssl/Configure', 'android-arm64', 'no-shared', 'no-tests', 'no-module',
             '-D__ANDROID_API__=36', '--prefix=/sslsockspro', '--openssldir=/sslsockspro/ssl', '--libdir=lib'], openssl, environment)
        run(['make', '-j' + JOBS, 'build_libs'], openssl, environment)
        run(['make', 'install_dev', 'DESTDIR=' + str(install_root)], openssl, environment)
    lz4 = copied('lz4')
    run(['make', '-j' + JOBS, '-C', 'lib', 'liblz4.a'], lz4, environment)
    cli_environment = environment | {
        'CPPFLAGS': '-I' + str(prefix / 'include'),
        'LDFLAGS': linker + ' ' + str(protect) + ' -Wl,--wrap=connect -Wl,--wrap=accept -Wl,--wrap=accept4 -L' + str(prefix / 'lib'),
        'PKG_CONFIG_LIBDIR': str(prefix / 'lib/pkgconfig'),
    }
    stunnel = WORK / 'stunnel-build'
    stunnel.mkdir(exist_ok=True)
    run([SOURCES / 'stunnel/configure', '--host=aarch64-linux-android', '--with-ssl=' + str(prefix),
         '--disable-libwrap', '--disable-systemd'], stunnel, cli_environment)
    run(['make', '-j' + JOBS], stunnel, cli_environment)
    shutil.copy2(stunnel / 'src/stunnel', OUTPUT / 'libstunnel_exec.so')
    openvpn = WORK / 'openvpn-build'
    openvpn.mkdir(exist_ok=True)
    vpn_environment = cli_environment | {
        'LDFLAGS': cli_environment['LDFLAGS'] + ' -L' + str(lz4 / 'lib'),
        'OPENSSL_CFLAGS': '-I' + str(prefix / 'include'),
        'OPENSSL_LIBS': str(prefix / 'lib/libssl.a') + ' ' + str(prefix / 'lib/libcrypto.a') + ' -ldl',
        'LZ4_CFLAGS': '-I' + str(lz4 / 'lib'), 'LZ4_LIBS': str(lz4 / 'lib/liblz4.a'),
        'IFCONFIG': '/system/bin/false', 'ROUTE': '/system/bin/false', 'IPROUTE': '/system/bin/false',
    }
    # The upstream generated configure script treats Android as generic Linux
    # and requests libcap-ng. Android uses VpnService/management descriptors and
    # must skip desktop-only Linux capability and interface dependencies.
    configure = SOURCES / 'openvpn/configure.android'
    text = (SOURCES / 'openvpn/configure').read_text()
    text = re.sub(r'(?m)^([ \t]*)\*-\*-linux\*\)', r'\1*-*-linux-android*) ;;\n\1*-*-linux*)', text)
    configure.write_text(text); configure.chmod(0o755)
    run([configure, '--host=aarch64-linux-android', '--disable-dco', '--disable-lzo',
         '--disable-plugins', '--disable-plugin-auth-pam', '--disable-plugin-down-root', '--disable-debug',
         '--with-openssl-engine=no'], openvpn, vpn_environment)
    config = openvpn / 'config.h'
    text = config.read_text().replace('#define TARGET_LINUX 1', '#undef TARGET_LINUX')
    text += '\n#define TARGET_ANDROID 1\n#undef TARGET_PREFIX\n#define TARGET_PREFIX "A"\n'
    config.write_text(text)
    run(['make', 'config-version.h'], openvpn, vpn_environment)
    run(['make', '-j' + JOBS, '-C', 'src/compat'], openvpn, vpn_environment)
    run(['make', '-j' + JOBS, '-C', 'src/openvpn'], openvpn, vpn_environment)
    shutil.copy2(openvpn / 'src/openvpn/openvpn', OUTPUT / 'libopenvpn_exec.so')
    hev = SOURCES / 'hev'
    run([NDK / 'ndk-build', '-j' + JOBS, 'NDK_PROJECT_PATH=' + str(hev),
         'APP_BUILD_SCRIPT=' + str(hev / 'Android.mk'), 'NDK_APPLICATION_MK=' + str(hev / 'Application.mk'),
         'APP_ABI=' + ABI, 'APP_PLATFORM=android-36', 'NDK_OUT=' + str(WORK / 'hev-obj'),
         'NDK_LIBS_OUT=' + str(WORK / 'hev-libs'),
         'APP_CFLAGS=-O2 -DANDROID -DPKGNAME=io/github/cysin/sslsockspro/engine -DCLSNAME=HevEngine -fstack-protector-strong'], hev, environment)
    shutil.copy2(WORK / 'hev-libs' / ABI / 'libhev-socks5-tunnel.so', OUTPUT / 'libhev-socks5-tunnel.so')
    for name in binaries:
        run([TOOLCHAIN / 'llvm-strip', '--strip-unneeded', OUTPUT / name], WORK, environment)
        OUTPUT.joinpath(name).chmod(0o755)
        report = subprocess.check_output([str(TOOLCHAIN / 'llvm-readelf'), '-lW', str(OUTPUT / name)], text=True)
        alignments = [line.split()[-1] for line in report.splitlines() if line.strip().startswith('LOAD')]
        if not alignments or any(int(value, 16) < 16384 for value in alignments):
            raise RuntimeError('Native library is not 16 KiB aligned: ' + name)
    stamp.write_text(fingerprint + '\n')
    state.write_text(json.dumps(checksums(), indent=2) + '\n')
    versions = {name: entry['version'] for name, entry in manifest.items()}
    assets = ROOT / 'app/src/main/assets'
    assets.mkdir(parents=True, exist_ok=True)
    (assets / 'native-versions.json').write_text(json.dumps(versions, indent=2) + '\n')
    print('ARM64 native engines ready; verified 16 KiB ELF alignment.', flush=True)


if __name__ == '__main__':
    main()
