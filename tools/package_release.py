#!/usr/bin/env python3
"""Package the signed ARM64 APK and its corresponding source, without secrets."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import zipfile
from bootstrap import ROOT, DOWNLOADS, SDK, fetch


def release_version():
    values = {}
    for line in (ROOT / 'version.properties').read_text().splitlines():
        if line.strip() and not line.lstrip().startswith('#'):
            key, _, value = line.partition('=')
            values[key.strip()] = value.strip()
    name, code = values.get('versionName', ''), values.get('versionCode', '')
    if not re.fullmatch(r'\d+\.\d+\.\d+', name) or not code.isdigit():
        raise SystemExit('version.properties needs a semantic versionName and numeric versionCode.')
    return name, int(code)


def apk_version(apk):
    aapt2 = sorted((SDK / 'build-tools').glob('*/aapt2'))
    if not aapt2:
        raise SystemExit('Run tools/bootstrap.py to install Android build tools.')
    badging = subprocess.check_output([str(aapt2[-1]), 'dump', 'badging', str(apk)], text=True)
    match = re.search(r"versionCode='(\d+)' versionName='([^']+)'", badging)
    if not match:
        raise SystemExit('Could not read the APK version.')
    return match[2], int(match[1])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=ROOT / 'out')
    args = parser.parse_args()
    output = args.output.expanduser().resolve()
    output.mkdir(parents=True, exist_ok=True)
    source_apk = ROOT / 'app/build/outputs/apk/release/app-release.apk'
    if not source_apk.exists():
        raise SystemExit('Build a signed release APK first.')
    with zipfile.ZipFile(source_apk) as archive:
        abis = {name.split('/')[1] for name in archive.namelist() if name.startswith('lib/')}
        if abis != {'arm64-v8a'}:
            raise SystemExit('Release APK must contain ARM64 only.')
    version, code = release_version()
    if apk_version(source_apk) != (version, code):
        raise SystemExit('Release APK version does not match version.properties; rebuild it.')
    apk = output / ('sslsockspro-' + version + '-arm64.apk')
    shutil.copyfile(source_apk, apk)
    package = output / ('sslsockspro-' + version + '-source.tar.gz')
    roots = ['app/src', 'tools', 'gradle', 'gradlew', 'gradlew.bat', 'build.gradle.kts', 'settings.gradle.kts',
             'gradle.properties', 'app/build.gradle.kts', 'app/proguard-rules.pro', 'app/proguard-test.pro', 'native-dependencies.json',
             'build-dependencies.json', 'version.properties', 'buildscript-gradle.lockfile', 'app/gradle.lockfile',
             '.editorconfig', '.github', 'README.md', 'HANDOFF.md', 'VALIDATION.md', 'LICENSE', 'COPYING', '.gitignore']
    files = set()
    epoch = int(os.environ.get('SOURCE_DATE_EPOCH', '1767225600'))
    def metadata(info):
        info.uid = info.gid = 0
        info.uname = info.gname = ''
        info.mtime = epoch
        info.mode = 0o755 if info.mode & 0o111 else 0o644
        return info
    for name in roots:
        path = ROOT / name
        if path.is_file():
            files.add(path)
        elif path.is_dir():
            files.update(item for item in path.rglob('*') if item.is_file())
    with tarfile.open(package, 'w:gz') as archive:
        for path in sorted(files):
            relative = path.relative_to(ROOT)
            if any(part in ('jniLibs', '__pycache__', 'build', '.tools', '.native') for part in relative.parts):
                continue
            if path.suffix.lower() in ('.apk', '.aab', '.so', '.jks', '.keystore', '.p12', '.pem', '.key'):
                raise SystemExit('Unexpected binary or private material in source: ' + str(relative))
            if path.is_symlink():
                raise SystemExit('Source links are unsupported: ' + str(relative))
            archive.add(path, arcname='sslsockspro/' + str(relative), recursive=False, filter=metadata)
        # Preserve exact original archives in addition to all local patches and
        # build instructions. They are not generated app/native binaries.
        manifest = json.loads((ROOT / 'native-dependencies.json').read_text())
        for specification in manifest.values():
            path = fetch(specification['url'], specification['filename'], specification['sha256'])
            archive.add(path, arcname='sslsockspro/upstream/' + path.name, recursive=False, filter=metadata)
    checksums = []
    for path in (apk, package):
        with path.open('rb') as stream:
            checksum = hashlib.file_digest(stream, 'sha256').hexdigest()
        checksums.append(checksum + '  ' + path.name)
        print('Packaged:', path, '(' + str(path.stat().st_size // 1024 // 1024) + ' MiB)')
    (output / 'SHA256SUMS').write_text('\n'.join(checksums) + '\n')


if __name__ == '__main__':
    main()
