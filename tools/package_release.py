#!/usr/bin/env python3
"""Package the signed ARM64 APK and its corresponding source, without secrets."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import tarfile
import zipfile
from bootstrap import ROOT, DOWNLOADS, fetch


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
    apk = output / 'sslsockspro-1.0.0-arm64.apk'
    shutil.copyfile(source_apk, apk)
    package = output / 'sslsockspro-1.0.0-source.tar.gz'
    roots = ['app/src', 'tools', 'gradle', 'gradlew', 'gradlew.bat', 'build.gradle.kts', 'settings.gradle.kts',
             'gradle.properties', 'app/build.gradle.kts', 'app/proguard-rules.pro', 'app/proguard-test.pro', 'native-dependencies.json',
             'build-dependencies.json', 'README.md', 'HANDOFF.md', 'VALIDATION.md', 'LICENSE', 'COPYING', '.gitignore']
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
