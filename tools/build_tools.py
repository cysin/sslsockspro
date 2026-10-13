#!/usr/bin/env python3
"""Prepare build-only tools locally when the system Perl lacks core modules."""
import os
import json
from pathlib import Path
import shutil
import subprocess
from bootstrap import ROOT, SOURCES, fetch, extract


def perl():
    local = ROOT / '.tools/perl/bin/perl'
    if local.exists():
        return str(local)
    check = subprocess.run(['perl', '-MFindBin', '-MIPC::Cmd', '-Mversion', '-e', 'exit 0'], capture_output=True)
    if check.returncode == 0:
        return 'perl'
    specification = json.loads((ROOT / 'build-dependencies.json').read_text())['perl']
    archive = fetch(specification['url'], specification['filename'], specification['sha256'])
    extract(archive, SOURCES / 'perl-build')
    work = ROOT / '.native/build/perl-host'
    if not work.exists():
        shutil.copytree(SOURCES / 'perl-build', work)
    prefix = ROOT / '.tools/perl'
    subprocess.run(['sh', 'Configure', '-des', '-Dprefix=' + str(prefix), '-Dman1dir=none', '-Dman3dir=none'], cwd=work, check=True)
    subprocess.run(['make', '-j' + str(min(os.cpu_count() or 2, 12))], cwd=work, check=True)
    subprocess.run(['make', 'install'], cwd=work, check=True)
    return str(local)


if __name__ == '__main__':
    print('Perl build runtime:', perl())
