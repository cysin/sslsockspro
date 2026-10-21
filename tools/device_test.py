#!/usr/bin/env python3
"""Run ARM64 instrumentation tests on one connected Android 16+ phone.

Optionally stage a user-owned ZIP/TAR client package into private app storage.
The fixture is supplied at runtime and is never added to either APK.
"""
import argparse
from pathlib import Path
import shlex
import subprocess
import sys
import contextlib
from bootstrap import ROOT, SDK


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--client-package', type=Path)
    parser.add_argument('--server-ip', help='Override connect addresses in the test package only')
    parser.add_argument('--openvpn-fixture', action='store_true', help='Test a disposable local OpenVPN server through ADB')
    parser.add_argument('--provision-profile', help='After successful live tests, retain an all-app proxy VPN profile with this name')
    parser.add_argument('--benchmark-url', help='HTTPS URL used for the opt-in proxy VPN latency/throughput benchmark')
    parser.add_argument('--saved-profile-ports', help='Comma-separated local ports (e.g. 33009,33008) of profiles already saved on the phone '
                        'to run live checks with; saved profiles and settings are restored afterwards')
    parser.add_argument('--test-class', action='append', choices=('NativeComponentsTest', 'ProfileStorageTest', 'DeviceTunnelTest', 'OpenVpnDeviceTest', 'UiDeviceTest'),
                        help='Run selected test classes instead of the complete suite')
    args = parser.parse_args()
    if args.provision_profile and not args.client_package:
        parser.error('--provision-profile requires --client-package')
    if args.saved_profile_ports and not all(part.strip().isdigit() for part in args.saved_profile_ports.split(',')):
        parser.error('--saved-profile-ports takes comma-separated port numbers')
    if args.benchmark_url and ((not args.client_package and not args.saved_profile_ports) or not args.benchmark_url.startswith('https://')):
        parser.error('--benchmark-url requires an https:// URL and --client-package or --saved-profile-ports')
    adb = str(SDK / 'platform-tools/adb')
    result = subprocess.check_output([adb, 'devices'], text=True)
    devices = [line.split()[0] for line in result.splitlines()[1:] if line.endswith('\tdevice')]
    if len(devices) != 1:
        raise SystemExit('Connect exactly one authorized phone.')
    device = devices[0]

    def run(*command, **kwargs):
        return subprocess.run([adb, '-s', device, *command], check=True, **kwargs)

    sdk = subprocess.check_output([adb, '-s', device, 'shell', 'getprop', 'ro.build.version.sdk'], text=True)
    abi = subprocess.check_output([adb, '-s', device, 'shell', 'getprop', 'ro.product.cpu.abi'], text=True).strip()
    if int(sdk) < 36 or abi != 'arm64-v8a':
        raise SystemExit('Tests require an Android 16+ ARM64 device.')
    run('shell', 'input', 'keyevent', 'KEYCODE_WAKEUP')
    variant = 'debug'
    run('install', '-r', str(ROOT / ('app/build/outputs/apk/' + variant + '/app-' + variant + '.apk')))
    run('install', '-r', str(ROOT / ('app/build/outputs/apk/androidTest/' + variant + '/app-' + variant + '-androidTest.apk')))
    fixture = None
    if args.client_package:
        import io
        import ipaddress
        import re
        import tarfile
        import zipfile
        source = args.client_package.read_bytes()
        if len(source) > 16 * 1024 * 1024:
            raise SystemExit('Test package exceeds 16 MiB.')
        files = {}
        if zipfile.is_zipfile(io.BytesIO(source)):
            with zipfile.ZipFile(io.BytesIO(source)) as archive:
                for item in archive.infolist():
                    if not item.is_dir():
                        if item.file_size > 4 * 1024 * 1024:
                            raise SystemExit('Test file exceeds 4 MiB.')
                        files[item.filename] = archive.read(item)
        else:
            with tarfile.open(fileobj=io.BytesIO(source)) as archive:
                for item in archive:
                    if item.isfile():
                        if item.size > 4 * 1024 * 1024:
                            raise SystemExit('Test file exceeds 4 MiB.')
                        files[item.name] = archive.extractfile(item).read()
        if len(files) > 128 or sum(map(len, files.values())) > 16 * 1024 * 1024:
            raise SystemExit('Expanded test package exceeds its limits.')
        if args.server_ip:
            address = str(ipaddress.ip_address(args.server_ip))
            if ':' in address:
                address = '[' + address + ']'
            for name, content in list(files.items()):
                if name.endswith('.conf'):
                    text = content.decode()
                    text = re.sub(r'(?im)^(\s*connect\s*=\s*)(?:\[[^]]+\]|[^:\s]+):(\d+)\s*$',
                                  lambda match: match[1] + address + ':' + match[2], text)
                    files[name] = text.encode()
            files = {name: data for name, data in files.items() if Path(name).name != 'SHA256SUMS'}
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, 'w', zipfile.ZIP_DEFLATED) as archive:
            for name, content in files.items():
                archive.writestr(name, content)
        fixture = 'device-client.zip'
        command = 'run-as io.github.cysin.sslsockspro.test sh -c ' + shlex.quote('umask 077; mkdir -p files; cat > files/' + fixture)
        run('shell', command, input=buffer.getvalue(), stdout=subprocess.DEVNULL)
    stack = contextlib.ExitStack()
    openvpn_fixture = None
    if args.openvpn_fixture:
        from openvpn_fixture import fixture as make_fixture
        content = stack.enter_context(make_fixture(device))
        openvpn_fixture = 'openvpn-fixture.zip'
        command = 'run-as io.github.cysin.sslsockspro.test sh -c ' + shlex.quote('umask 077; mkdir -p files; cat > files/' + openvpn_fixture)
        run('shell', command, input=content, stdout=subprocess.DEVNULL)
    try:
        classes = 'io.github.cysin.sslsockspro.NativeComponentsTest'
        classes += ',io.github.cysin.sslsockspro.ProfileStorageTest'
        if fixture or args.saved_profile_ports:
            classes += ',io.github.cysin.sslsockspro.DeviceTunnelTest'
        if openvpn_fixture:
            classes += ',io.github.cysin.sslsockspro.OpenVpnDeviceTest'
        classes += ',io.github.cysin.sslsockspro.UiDeviceTest'
        if args.test_class:
            classes = ','.join('io.github.cysin.sslsockspro.' + name for name in args.test_class)
        command = ['shell', 'am', 'instrument', '-w', '-r', '-e', 'class', classes]
        if fixture:
            command += ['-e', 'clientFixture', fixture]
            if args.provision_profile:
                command += ['-e', 'provisionProfile', args.provision_profile]
        if args.saved_profile_ports:
            # Also runs the disconnect regression with the selected saved VPN profile.
            command += ['-e', 'savedProfilePorts', args.saved_profile_ports.replace(' ', ''), '-e', 'savedProfileTest', 'true']
        if args.benchmark_url:
            command += ['-e', 'benchmarkUrl', args.benchmark_url]
        if openvpn_fixture:
            command += ['-e', 'openVpnFixture', openvpn_fixture]
        command += ['io.github.cysin.sslsockspro.test/androidx.test.runner.AndroidJUnitRunner']
        result = subprocess.run([adb, '-s', device, 'shell', shlex.join(command[1:])], capture_output=True, text=True, check=True)
        output = result.stdout + result.stderr
        (ROOT / '.tools/device-tests.txt').write_text(output)
        print(output)
        reports = [line.split('ssp-benchmark=', 1)[1] for line in output.splitlines() if 'ssp-benchmark=' in line]
        if reports:
            import json
            import time
            report = json.loads(reports[-1])
            path = ROOT / ('.tools/benchmark-' + time.strftime('%Y%m%d-%H%M%S') + '.json')
            path.write_text(json.dumps(report, indent=2) + '\n')
            print('Benchmark:', json.dumps(report, sort_keys=True), '->', path)
        if 'FAILURES!!!' in output or 'INSTRUMENTATION_FAILED' in output or 'Process crashed' in output or 'OK (' not in output:
            raise SystemExit('Device tests failed; see .tools/device-tests.txt.')
    finally:
        stack.close()
        if openvpn_fixture:
            # The disposable server logs the peer information each client sent.
            log = ROOT / '.tools/openvpn-fixture-server.log'
            text = log.read_text(errors='replace') if log.exists() else ''
            leaked = sorted({marker for marker in ('IV_HWADDR', 'IV_PLAT_VER', 'UV_', 'IV_SSL') if marker in text})
            if leaked:
                raise SystemExit('The OpenVPN client sent identifying peer information: ' + ', '.join(leaked))
            print('OpenVPN peer information contained no hardware address, kernel version or user variables.')
        if fixture:
            run('shell', 'run-as', 'io.github.cysin.sslsockspro.test', 'rm', '-f', 'files/' + fixture, stdout=subprocess.DEVNULL)
        if openvpn_fixture:
            run('shell', 'run-as', 'io.github.cysin.sslsockspro.test', 'rm', '-f', 'files/' + openvpn_fixture, stdout=subprocess.DEVNULL)


if __name__ == '__main__':
    try:
        main()
    except subprocess.CalledProcessError as failure:
        raise SystemExit('A device or fixture command failed (exit ' + str(failure.returncode) + ').') from None
