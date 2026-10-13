#!/usr/bin/env python3
"""Create an isolated, disposable OpenVPN TLS/data-channel fixture for ADB tests.

No root, system services, host routes, or production credentials are required.
The server uses dev null: it accepts encrypted packets but does not provide
Internet access. TCP listeners are loopback-only and ADB reverses are removed.
"""
import contextlib
import io
import os
from pathlib import Path
import selectors
import shutil
import socket
import subprocess
import tarfile
import tempfile
import threading
import zipfile
from bootstrap import ROOT, SDK


def port():
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        return listener.getsockname()[1]


class Proxy:
    def __init__(self, destination):
        self.destination = destination
        self.listener = socket.socket()
        self.listener.bind(('127.0.0.1', 0))
        self.listener.listen(8)
        self.port = self.listener.getsockname()[1]
        self.clients = set()
        self.running = True
        threading.Thread(target=self.accept, daemon=True).start()

    def accept(self):
        while self.running:
            try:
                client, _ = self.listener.accept()
            except OSError:
                break
            self.clients.add(client)
            threading.Thread(target=self.forward, args=(client,), daemon=True).start()

    def forward(self, client):
        remote = None
        try:
            client.settimeout(10)
            header = bytearray()
            while not header.endswith(b'\r\n\r\n') and len(header) < 16384:
                chunk = client.recv(1)
                if not chunk:
                    return
                header.extend(chunk)
            request = bytes(header).split(b'\r\n', 1)[0].split()
            if len(request) != 3 or request[0] != b'CONNECT' or request[1] != b'127.0.0.1:' + str(self.destination).encode() or request[2] not in (b'HTTP/1.0', b'HTTP/1.1'):
                client.sendall(b'HTTP/1.1 403 Forbidden\r\n\r\n')
                return
            remote = socket.create_connection(('127.0.0.1', self.destination), timeout=10)
            self.clients.add(remote)
            client.sendall(b'HTTP/1.1 200 Connection established\r\n\r\n')
            client.setblocking(False)
            remote.setblocking(False)
            with selectors.DefaultSelector() as selector:
                selector.register(client, selectors.EVENT_READ, remote)
                selector.register(remote, selectors.EVENT_READ, client)
                while self.running:
                    for key, _ in selector.select(1):
                        chunk = key.fileobj.recv(65536)
                        if not chunk:
                            return
                        # The local fixture moves small test packets. Bounded
                        # blocking writes avoid discarding a partial send.
                        target = key.data
                        target.setblocking(True); target.settimeout(10)
                        target.sendall(chunk)
                        target.setblocking(False)
        except (OSError, ValueError):
            pass
        finally:
            for item in (client, remote):
                if item:
                    self.clients.discard(item)
                    item.close()

    def close(self):
        self.running = False
        self.listener.close()
        for client in tuple(self.clients):
            with contextlib.suppress(OSError):
                client.close()


@contextlib.contextmanager
def fixture(device=None):
    if not shutil.which('openvpn') or not shutil.which('stunnel'):
        raise RuntimeError('Fixture tests require host openvpn and stunnel executables.')
    adb = str(SDK / 'platform-tools/adb')
    proxy = None
    with tempfile.TemporaryDirectory(prefix='openvpn-test-', dir=ROOT / '.tools') as path, contextlib.ExitStack() as cleanup:
        work = Path(path); work.chmod(0o700)

        def stop_child(child, log, source, destination):
            if child.poll() is None:
                child.terminate()
                try:
                    child.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    child.kill(); child.wait()
            log.close()
            shutil.copyfile(source, destination)

        def run(*args):
            subprocess.run(args, cwd=work, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, check=True)

        def reverse(number):
            if device is None:
                return
            subprocess.run([adb, '-s', device, 'reverse', 'tcp:' + str(number), 'tcp:' + str(number)], check=True, stdout=subprocess.DEVNULL)
            cleanup.callback(subprocess.run, [adb, '-s', device, 'reverse', '--remove', 'tcp:' + str(number)],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        def key(name):
            run('openssl', 'genpkey', '-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:P-256', '-out', name + '.key')
            (work / (name + '.key')).chmod(0o600)

        key('ca')
        run('openssl', 'req', '-x509', '-new', '-key', 'ca.key', '-days', '2', '-sha256', '-subj', '/CN=Disposable test CA',
            '-addext', 'basicConstraints=critical,CA:TRUE', '-addext', 'keyUsage=critical,keyCertSign,cRLSign', '-out', 'ca.crt')
        for name, purpose in [('server', 'serverAuth'), ('client', 'clientAuth')]:
            key(name)
            run('openssl', 'req', '-new', '-key', name + '.key', '-subj', '/CN=' + name + '.test', '-out', name + '.csr')
            extension = work / (name + '.ext')
            extension.write_text('basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=' + purpose + '\nsubjectAltName=DNS:' + name + '.test\n')
            run('openssl', 'x509', '-req', '-in', name + '.csr', '-CA', 'ca.crt', '-CAkey', 'ca.key', '-CAcreateserial',
                '-days', '2', '-sha256', '-extfile', name + '.ext', '-out', name + '.crt')
        vpn_port = port()
        server = work / 'server.ovpn'
        server.write_text('local 127.0.0.1\nport ' + str(vpn_port) + '\nproto tcp-server\ndev null\ntls-server\nca ca.crt\ncert server.crt\nkey server.key\ndh none\ndisable-occ\nifconfig-noexec\nroute-noexec\nverb 4\n')
        vpn_log = (work / 'server.log').open('wb')
        vpn = subprocess.Popen(['openvpn', '--config', str(server)], cwd=work, stdout=vpn_log, stderr=subprocess.STDOUT)
        cleanup.callback(stop_child, vpn, vpn_log, work / 'server.log', ROOT / '.tools/openvpn-fixture-server.log')
        reverse(vpn_port)
        proxy = Proxy(vpn_port)
        cleanup.callback(proxy.close)
        tls_port = port()
        tls_config = work / 'stunnel.conf'
        tls_config.write_text('foreground = yes\nsyslog = no\ndebug = warning\npid =\nsslVersionMin = TLSv1.3\nverifyChain = yes\nCAfile = ca.crt\ncert = server.crt\nkey = server.key\n[fixture]\naccept = 127.0.0.1:' + str(tls_port) + '\nconnect = 127.0.0.1:' + str(proxy.port) + '\n')
        tls_log = (work / 'stunnel.log').open('wb')
        tls = subprocess.Popen(['stunnel', str(tls_config)], cwd=work, stdout=tls_log, stderr=subprocess.STDOUT)
        cleanup.callback(stop_child, tls, tls_log, work / 'stunnel.log', ROOT / '.tools/openvpn-fixture-stunnel.log')
        reverse(tls_port)
        vpn_text = 'tls-client\nremote 127.0.0.1 ' + str(vpn_port) + ' tcp-client\nnobind\nifconfig 10.8.0.2 10.8.0.1\nifconfig-ipv6 fd00:8::2/64 fd00:8::1\ndhcp-option DNS 10.8.0.1\nremote-cert-tls server\ndisable-occ\n'
        for kind, name in [('ca', 'ca.crt'), ('cert', 'client.crt'), ('key', 'client.key')]:
            vpn_text += '<' + kind + '>\n' + (work / name).read_text() + '</' + kind + '>\n'
        tls_text = 'client = yes\nsslVersionMin = TLSv1.3\nverifyChain = yes\ncheckHost = server.test\nCAfile = ca.crt\ncert = client.crt\nkey = client.key\nsni =\n[fixture]\naccept = 127.0.0.1:33017\nconnect = 127.0.0.1:' + str(tls_port) + '\n'
        bundle = io.BytesIO()
        with zipfile.ZipFile(bundle, 'w', zipfile.ZIP_DEFLATED) as archive:
            archive.writestr('fixture.ovpn', vpn_text)
            archive.writestr('fixture.conf', tls_text)
            for name in ('ca.crt', 'client.crt', 'client.key'):
                archive.writestr(name, (work / name).read_bytes())
        import time
        time.sleep(1)
        if vpn.poll() is not None or tls.poll() is not None:
            raise RuntimeError('Fixture failed to start: ' + (work / 'server.log').read_text() + (work / 'stunnel.log').read_text())
        yield bundle.getvalue()


if __name__ == '__main__':
    raise SystemExit('Run this fixture through tools/device_test.py --openvpn-fixture.')
