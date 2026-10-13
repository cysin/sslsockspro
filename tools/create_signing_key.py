#!/usr/bin/env python3
"""Create a private release signing key outside the source checkout."""
import argparse
import os
from pathlib import Path
import secrets
import subprocess
from bootstrap import ROOT, jdk


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, default=Path.home() / '.local/share/sslsockspro/signing')
    args = parser.parse_args()
    directory = args.directory.expanduser().resolve()
    if directory.is_relative_to(ROOT):
        raise SystemExit('Signing keys must be kept outside the repository.')
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    directory.chmod(0o700)
    properties = directory / 'signing.properties'
    keystore = directory / 'release.p12'
    if properties.exists():
        print('Private signing properties:', properties)
        return
    if keystore.exists():
        raise SystemExit('A signing key already exists without properties; do not overwrite it.')
    password = secrets.token_urlsafe(32)
    environment = os.environ | {'SSLSOCKSPRO_KEYSTORE_PASSWORD': password}
    subprocess.run([str(jdk() / 'bin/keytool'), '-genkeypair', '-alias', 'release', '-keyalg', 'RSA', '-keysize', '3072',
        '-sigalg', 'SHA256withRSA', '-validity', '10000', '-dname', 'CN=SSLSocks Pro Release',
        '-storetype', 'PKCS12', '-keystore', str(keystore), '-storepass:env', 'SSLSOCKSPRO_KEYSTORE_PASSWORD',
        '-keypass:env', 'SSLSOCKSPRO_KEYSTORE_PASSWORD'], env=environment, check=True,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    keystore.chmod(0o600)
    with properties.open('x') as stream:
        properties.chmod(0o600)
        stream.write('storeFile=' + str(keystore).replace('\\', '\\\\') + '\nstorePassword=' + password +
                     '\nkeyAlias=release\nkeyPassword=' + password + '\n')
    print('Private signing properties:', properties)
    print('Keep this directory backed up privately; the same key is needed for app updates.')


if __name__ == '__main__':
    main()
