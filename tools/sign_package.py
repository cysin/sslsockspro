#!/usr/bin/env python3
"""Create a signed SSLSocks Pro client package.

The operator signs a manifest of every file's SHA-256 with an Ed25519 key.
The app verifies the signature and shows the key's fingerprint; give users
that fingerprint through a different channel than the package itself.

  python3 tools/sign_package.py --generate-key ~/private/operator-ed25519.pem
  python3 tools/sign_package.py --key ~/private/operator-ed25519.pem \\
      --output client-signed.zip --backend SOCKS5 client.conf client.pem server-ca.crt

The private key never enters the package. Uses the host OpenSSL 3 CLI.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import zipfile

NAMES = {'ssp-manifest.json', 'ssp-manifest.sig', 'ssp-operator.pub'}
SAFE = re.compile(r'^[^/\\\x00-\x1f\x7f]{1,160}$')


def openssl(*arguments, data=None):
    return subprocess.run(['openssl', *arguments], input=data, capture_output=True, check=True).stdout


def fingerprint(public_pem):
    body = b''.join(line for line in public_pem.splitlines() if line and not line.startswith(b'-----'))
    digest = hashlib.sha256(base64.b64decode(body)).hexdigest().upper()
    return ' '.join(digest[index:index + 4] for index in range(0, len(digest), 4))


def generate(path):
    path = path.expanduser()
    if path.exists():
        raise SystemExit('Refusing to overwrite an existing key: ' + str(path))
    path.parent.mkdir(parents=True, exist_ok=True)
    previous = os.umask(0o077)
    try:
        openssl('genpkey', '-algorithm', 'ed25519', '-out', str(path))
    finally:
        os.umask(previous)
    print('Created private operator key:', path)
    print('Operator fingerprint:', fingerprint(openssl('pkey', '-in', str(path), '-pubout')))


def collect(paths):
    files = {}
    for path in paths:
        sources = sorted(item for item in path.rglob('*') if item.is_file()) if path.is_dir() else [path]
        for source in sources:
            if source.is_symlink():
                raise SystemExit('Links are not packaged: ' + str(source))
            name = source.name
            if not SAFE.match(name) or name in ('.', '..') or name in NAMES or name == 'SHA256SUMS':
                raise SystemExit('Unsupported file name: ' + name)
            if name in files:
                raise SystemExit('Two files share the name ' + name)
            files[name] = source.read_bytes()
    if not any(name.lower().endswith(('.conf', '.ovpn')) for name in files):
        raise SystemExit('Include at least one stunnel .conf or OpenVPN .ovpn profile.')
    return files


def sign(args):
    key = args.key.expanduser()
    if (key.stat().st_mode & 0o077) != 0:
        raise SystemExit('The private key must not be readable by other users: ' + str(key))
    files = collect(args.files)
    hints = []
    for name in sorted(files):
        if name.lower().endswith('.conf') or (name.lower().endswith('.ovpn') and not any(n.lower().endswith('.conf') for n in files)):
            hint = {'config': name}
            for field, value in (('name', args.name), ('mode', args.mode), ('proxyKind', args.backend),
                                 ('section', args.section), ('dnsMode', args.dns_mode)):
                if value:
                    hint[field] = value
            hints.append(hint)
    manifest = {'format': 1, 'files': {name: hashlib.sha256(data).hexdigest() for name, data in sorted(files.items())}}
    if any(len(hint) > 1 for hint in hints):
        manifest['profiles'] = hints
    manifest_bytes = json.dumps(manifest, sort_keys=True, separators=(',', ':')).encode()
    with tempfile.TemporaryDirectory() as directory:
        message = Path(directory) / 'manifest'
        message.write_bytes(manifest_bytes)
        signature = openssl('pkeyutl', '-sign', '-rawin', '-inkey', str(key), '-in', str(message))
    public = openssl('pkey', '-in', str(key), '-pubout')
    output = args.output.expanduser()
    entries = dict(files)
    entries['ssp-manifest.json'] = manifest_bytes
    entries['ssp-manifest.sig'] = base64.b64encode(signature) + b'\n'
    entries['ssp-operator.pub'] = public
    with zipfile.ZipFile(output, 'w', zipfile.ZIP_DEFLATED) as archive:
        for name in sorted(entries):
            info = zipfile.ZipInfo(name, date_time=(2026, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o600 << 16
            archive.writestr(info, entries[name])
    print('Signed package:', output)
    print('Operator fingerprint:', fingerprint(public))


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--generate-key', type=Path, metavar='PATH', help='create a private Ed25519 operator key and exit')
    parser.add_argument('--key', type=Path, help='private Ed25519 operator key')
    parser.add_argument('--output', type=Path, help='signed ZIP to write')
    parser.add_argument('--name', help='profile name shown in the app')
    parser.add_argument('--mode', choices=('LOCAL_PROXY', 'PROXY_VPN', 'OPENVPN'))
    parser.add_argument('--backend', choices=('HTTP_CONNECT', 'SOCKS5'), help='proxy protocol behind stunnel')
    parser.add_argument('--section', help='stunnel section used by VPN modes')
    parser.add_argument('--dns-mode', choices=('DOH', 'PROXY'))
    parser.add_argument('files', nargs='*', type=Path)
    args = parser.parse_args()
    if args.generate_key:
        generate(args.generate_key)
        return
    if not args.key or not args.output or not args.files:
        parser.error('--key, --output and package files are required')
    sign(args)


if __name__ == '__main__':
    try:
        main()
    except subprocess.CalledProcessError as failure:
        raise SystemExit('OpenSSL failed: ' + failure.stderr.decode(errors='replace').strip()) from None
