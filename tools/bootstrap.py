#!/usr/bin/env python3
"""Install the project's Android SDK and fetch checksum-verified native sources."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import time
import urllib.request
import xml.etree.ElementTree as ET
import zipfile

ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / '.tools'
DOWNLOADS = TOOLS / 'downloads'
SDK = TOOLS / 'android-sdk'
SOURCES = ROOT / '.native' / 'sources'


def request(url):
    return urllib.request.Request(url, headers={'User-Agent': 'SSLSocksPro-build/1.0'})


def fetch(url, filename, expected=None, algorithm='sha256'):
    DOWNLOADS.mkdir(parents=True, exist_ok=True)
    output = DOWNLOADS / filename
    if output.exists() and (not expected or digest(output, algorithm) == expected.lower()):
        return output
    for attempt in range(4):
        temporary = output.with_suffix(output.suffix + '.partial')
        try:
            with urllib.request.urlopen(request(url), timeout=90) as response, temporary.open('wb') as stream:
                shutil.copyfileobj(response, stream, 1024 * 1024)
            if expected and digest(temporary, algorithm) != expected.lower():
                raise RuntimeError('Checksum mismatch: ' + filename)
            temporary.replace(output)
            print('Downloaded:', filename, flush=True)
            return output
        except Exception:
            temporary.unlink(missing_ok=True)
            if attempt == 3:
                raise
            time.sleep(2 ** attempt)


def digest(path, algorithm='sha256'):
    checksum = hashlib.new(algorithm)
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            checksum.update(chunk)
    return checksum.hexdigest()


def extract(archive, output):
    if output.exists():
        return
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.extract-', dir=output.parent) as temporary:
        stage = Path(temporary)
        if zipfile.is_zipfile(archive):
            with zipfile.ZipFile(archive) as package:
                for member in package.infolist():
                    if not (stage / member.filename).resolve().is_relative_to(stage.resolve()):
                        raise RuntimeError('Archive path escapes its destination')
                    if (member.external_attr >> 16) & 0o170000 == 0o120000:
                        raise RuntimeError('ZIP symlinks are unsupported')
                package.extractall(stage)
                for member in package.infolist():
                    path = stage / member.filename
                    mode = (member.external_attr >> 16) & 0o777
                    if path.is_file() and mode:
                        path.chmod(mode)
        else:
            with tarfile.open(archive) as package:
                package.extractall(stage, filter='data')
        entries = list(stage.iterdir())
        if len(entries) != 1 or not entries[0].is_dir():
            raise RuntimeError('Expected one archive root: ' + str(archive))
        entries[0].rename(output)


def native_sources():
    manifest_path = ROOT / 'native-dependencies.json'
    manifest = json.loads(manifest_path.read_text())

    def prepare(item):
        name, specification = item
        require_digest = specification['sha256']
        archive = fetch(specification['url'], specification['filename'], require_digest)
        return name, archive

    with ThreadPoolExecutor(max_workers=4) as pool:
        archives = dict(pool.map(prepare, manifest.items()))
    # Extract parents before nested, pinned submodules. Parallel extraction can
    # create a child directory and mistakenly make an unextracted parent appear
    # complete on a clean checkout.
    for name in sorted(manifest, key=lambda name: len(Path(manifest[name].get('destination', name)).parts)):
        specification = manifest[name]
        output = SOURCES / specification.get('destination', name)
        stamp = SOURCES / ('.' + name + '.sha256')
        expected = specification['sha256']
        if output.exists() and (not stamp.exists() or stamp.read_text().strip() != expected):
            shutil.rmtree(output)
        extract(archives[name], output)
        stamp.write_text(expected + '\n')
    print('Verified native sources:', ', '.join(sorted(manifest)), flush=True)


def jdk():
    specification = json.loads((ROOT / 'build-dependencies.json').read_text())['jdk']
    output = TOOLS / 'jdk'
    if (output / 'bin/javac').exists():
        return output
    archive = fetch(specification['url'], specification['filename'], specification['sha256'])
    extract(archive, output)
    return output


def android_sdk():
    xml = fetch('https://dl.google.com/android/repository/repository2-3.xml', 'android-repository.xml')
    packages = {element.attrib['path']: element for element in ET.parse(xml).getroot()
                if element.tag.endswith('remotePackage')}
    candidates = [name for name, element in packages.items()
                  if name.startswith('cmdline-tools;') and name.rsplit(';', 1)[1].replace('.', '').isdigit()
                  and (element.find('channelRef') is None or element.find('channelRef').attrib['ref'] == 'channel-0')]
    name = max(candidates, key=lambda value: tuple(map(int, value.rsplit(';', 1)[1].split('.'))))
    for archive in packages[name].findall('./archives/archive'):
        if archive.findtext('host-os') == 'linux':
            complete = archive.find('complete')
            url = 'https://dl.google.com/android/repository/' + complete.findtext('url')
            package = fetch(url, Path(url).name, complete.findtext('checksum'), 'sha1')
            extract(package, SDK / 'cmdline-tools/latest')
            break
    manager = SDK / 'cmdline-tools/latest/bin/sdkmanager'
    if not manager.exists():
        raise RuntimeError('Android command-line tools were not installed')
    manager.chmod(0o755)
    java = jdk()
    environment = os.environ | {'ANDROID_HOME': str(SDK), 'ANDROID_SDK_ROOT': str(SDK),
                               'JAVA_HOME': str(java), 'PATH': str(java / 'bin') + os.pathsep + os.environ['PATH']}
    proxy_arguments = []
    import urllib.parse
    proxy_value = urllib.request.getproxies().get('https')
    if proxy_value:
        proxy = urllib.parse.urlsplit(proxy_value)
        if proxy.scheme != 'http' or proxy.username:
            raise RuntimeError('SDK setup requires an unauthenticated HTTP proxy or a direct connection.')
        proxy_arguments = ['--proxy=http', '--proxy_host=' + proxy.hostname, '--proxy_port=' + str(proxy.port or 80)]
    command = [str(manager), '--sdk_root=' + str(SDK), *proxy_arguments]
    subprocess.run(command + ['--licenses'], input='y\n' * 100,
                   text=True, env=environment, check=True)
    subprocess.run(command + ['platform-tools', 'platforms;android-37.2',
                    'build-tools;37.0.0', 'ndk;30.0.16248370'], env=environment, check=True)
    (ROOT / 'local.properties').write_text('sdk.dir=' + str(SDK) + '\n')
    print('Android SDK ready:', SDK, flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--native-only', action='store_true')
    parser.add_argument('--sdk-only', action='store_true')
    arguments = parser.parse_args()
    if not arguments.sdk_only:
        native_sources()
    if not arguments.native_only:
        android_sdk()


if __name__ == '__main__':
    main()
