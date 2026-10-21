# SSLSocks Pro

An Android 16+ ARM64 client for authenticated stunnel connections and built-in
OpenVPN. The Material 3 app keeps profiles and credentials in encrypted private
storage and runs native network engines in a separate worker process. It is
designed so that routed traffic never falls back to a direct connection and so
that the app itself reveals no device identifiers, location or account data.
See [Privacy protections](#privacy-protections) for exact guarantees and limits.

Application ID: `io.github.cysin.sslsockspro`. Android 16 (API 36) is the minimum.
The APK contains only `arm64-v8a` code. Native ELF files support 16 KB page
alignment; actual-device checks are described in [VALIDATION.md](VALIDATION.md).

## Connection modes

| Mode | Behavior | Required server |
| --- | --- | --- |
| Local proxy | Starts loopback TCP listeners. Apps must explicitly use a listener. Generic TCP tunnels such as SSH are supported. | stunnel forwarding to the corresponding TCP service |
| Phone VPN through stunnel | Routes all apps, or selected apps, through one tunnel. TCP and DNS are supported. Other UDP, including QUIC, is blocked. | stunnel forwarding to HTTP CONNECT or SOCKS5 (identified when connecting) |
| Built-in OpenVPN | Runs the embedded client with an `.ovpn` profile. Supports TCP/UDP and IPv4/IPv6 inside the authenticated VPN. Can carry OpenVPN TCP through a stunnel HTTP/SOCKS proxy. | An OpenVPN server; a proxy alone is insufficient |

In local mode, **Local proxy ready** means the listeners started. Remote TLS is
verified when an app uses a listener. In proxy VPN mode, **Connected** requires a
successful encrypted DNS transaction through the proxy. There is no direct
network or DNS fallback.

## Start using the app

1. Install the signed ARM64 APK on an Android 16+ phone.
2. Open **Profiles** and use the import button, or open/share the package from
   another app. Select a ZIP/TAR/TAR.GZ client package, or the stunnel `.conf`
   and companion credential files. The import dialog shows the operator key
   fingerprint of a [signed package](#signed-client-packages); compare it with
   the fingerprint your operator gave you separately. Nothing is saved until you
   confirm.
3. Edit the profile. Check the server address/port, local port, certificate name,
   and backend type. The app asks the server whether it is HTTP CONNECT or SOCKS5
   when connecting and uses the answer. Prefer a numeric server address: a name
   is looked up on the current network before the tunnel starts.
4. Choose **Phone VPN through stunnel** for phone-wide routing. Leave app
   selection empty to route all apps, or choose a specific list. Leave **Enable
   IPv6 destinations** off for an IPv4-only proxy server.
5. Select the profile on **Status** and tap **Connect**. Notification
   permission and Android VPN consent are requested separately. Afterwards the
   Quick Settings tile and launcher shortcuts can connect and disconnect; they
   show only the connection state and require an unlocked phone.
6. Check status and **Logs**. Disconnect before editing an active profile or
   restoring a backup. The button shows **Disconnecting…** until the native
   worker releases its VPN descriptors. A shutdown timeout keeps traffic
   blocked and asks you to retry; it does not report a completed disconnect.
   Disconnecting from Android's VPN status dialog returns the app to
   **Disconnected** with **Connect** available.

Basic settings change the selected tunnel while preserving comments, other
tunnels, and repeated socket directives. The advanced editor shows the complete
configuration. Desktop credential paths are mapped to imported private files;
the app does not read `/etc/stunnel` or arbitrary phone files.

For an encrypted PEM key, attach the file, choose **Unlock key**, and save the
profile. The unlocked representation stays encrypted at rest. OpenVPN also has
username/password and private-key/PKCS#12 passphrase fields, and answers static
(`static-challenge`) and dynamic (CRV1) one-time-code challenges in the app.
Web-based single sign-on is not supported.

RSA and EC OpenVPN client keys move into Android Keystore (StrongBox for P-256
keys when available) when a profile is saved or imported. From then on no one,
including this app, can read the key; OpenVPN asks the app to sign through its
management interface. Such keys are not part of backups: keep the original client
package to set up another phone. Ed25519 keys and stunnel keys stay in encrypted
app storage because stunnel cannot use Keystore keys.

## stunnel configuration

Import this configuration with `server-ca.crt` and `client.pem`. Replace
`SERVER_ADDRESS`, and use the server certificate name issued by your CA.

```ini
client = yes
sslVersionMin = TLSv1.3
verifyChain = yes
checkHost = stunnel-server.internal
CAfile = server-ca.crt
cert = client.pem
key = client.pem
sni =
sessionResume = no
options = NO_TICKET
options = NO_COMPRESSION
TIMEOUTconnect = 15
TIMEOUTbusy = 300
TIMEOUTidle = 43200
TIMEOUTclose = 60
socket = l:TCP_NODELAY=1
socket = r:TCP_NODELAY=1
socket = l:SO_KEEPALIVE=1
socket = r:SO_KEEPALIVE=1
socket = r:TCP_KEEPIDLE=300
socket = r:TCP_KEEPINTVL=30
socket = r:TCP_KEEPCNT=4

[proxy]
accept = 127.0.0.1:33009
connect = SERVER_ADDRESS:9983
```

The connection IP need not appear in the certificate when `checkHost` verifies
the trusted certificate name. Numeric gateway IPs avoid bootstrap DNS lookups.
IPv6 endpoints use `[address]:port`; listeners must be loopback addresses with
unprivileged ports.

The app owns foreground operation, log level, runtime files, and process
lifecycle. It requires client mode, TLS 1.3, CA/server-identity verification,
and a matching client certificate/key. It rejects executable hooks, external
configuration files, provider loading, environment overrides, legacy `verify`
overrides, unsafe TLS versions, and ancillary network services.

Multiple stunnel sections can run together. In the VPN modes the selected
section listens on a private per-connection loopback port instead of its
configured `accept` port: only the app's own authenticated relay may connect,
and the worker checks with Android that every client belongs to this app. Other
sections remain local TCP tunnels that any app on the phone can use, as in local
proxy mode.

For OpenVPN through an HTTP/SOCKS tunnel, the proxy must permit the OpenVPN
server's TCP destination port. A strict HTTPS-only exit commonly permits 443;
its ACL may reject an OpenVPN server using the usual 1194 port.

### IPv4 and IPv6

Proxy VPN profiles use IPv4 by default. **Enable IPv6 destinations** is off:
Android blocks IPv6 traffic from routed apps, allowing browsers to use IPv4
without trying an unavailable IPv6 proxy exit. The app does not unblock IPv6
onto the physical network. Enable this setting only after verifying that the
proxy server has working IPv6 routing, DNS, firewall rules, and outbound proxy
support. The stunnel gateway itself can remain an IPv4 address.

OpenVPN uses the address families assigned by its configuration/server. An
unassigned family stays blocked. An assigned configuration must also supply
at least one DNS server in an assigned family through `dhcp-option DNS` or a
server push; otherwise the app reports an error and retains its blocking TUN.
It does not inherit the phone's DNS servers.

## DNS

Proxy VPN DNS uses DNS-over-HTTPS through the selected stunnel proxy. The default
endpoint is `https://cloudflare-dns.com/dns-query`; another HTTPS endpoint can be
configured per profile. Its operator receives queries from the proxy exit, not
from the phone. Queries are padded to 128-byte blocks and carry no software
identifier. There is no fallback to phone DNS, ordinary DNS, or another provider.

**Resolve names at the proxy server** (per profile) keeps lookups away from any
DNS-over-HTTPS provider: apps receive placeholder addresses
(`198.18.128.0/17`, `fd00:5353:1::/64`) and the relay sends the original name to
your proxy, which resolves it. Mail, service and text records still use
DNS-over-HTTPS through the tunnel. Placeholders survive reconnects of the same
profile and are forgotten on disconnect.

Answers are cached for their time-to-live (at most one hour; failures at most 30
seconds) until disconnect. While IPv6 is off, address lookups for IPv6 are
answered locally with no data instead of being sent anywhere.

UDP and TCP DNS are supported. Identifying EDNS options such as client subnet
are stripped, and upstream transaction IDs are neutralized. SVCB/HTTPS records
(types 64/65) are suppressed by default without claiming DNSSEC authentication.
This can disable service-binding and ECH discovery; turn the option off when
those features or a validating resolver are required. Site TLS names can still
be observable at the proxy exit.

For proxy VPN mode, set Android **Private DNS** to **Automatic** or **Off**.
A strict provider hostname requires DNS-over-TLS behavior this mode does not
emulate; the app detects it and asks for a settings change rather than sending
DNS directly.

Configured gateway names are resolved on the physical network before the
tunnel starts. Native gateway sockets are protected and bound to that network;
application destinations use the tunnel. A gateway bootstrap lookup is outside
the tunnel, so use numeric IPs when that disclosure matters.

## Always-on, failures, and coverage

Enable **Always-on VPN** and **Block connections without VPN** in Android VPN
settings for protection before startup and after the entire app stops. Choose
a VPN-mode profile first. Android controls disconnecting an always-on VPN.
Local proxy mode cannot be used while this app is Android's always-on VPN.

The Java/Kotlin VPN owner retains the TUN interface if the native worker crashes
or a connection fails, blocking routed traffic during recovery. Native children
terminate with their worker, and stale runtime credentials are removed before
startup. Configuration/authentication failures require an edit; network failures
use bounded backoff, and a network that returns after a loss reconnects at once.
A change between Wi-Fi and mobile data keeps the tunnel: new gateway connections
use the new network, OpenVPN floats or reconnects internally, and the tunnel is
checked; only a failed check rebuilds it. Proxy VPN health checks run through
the tunnel every 30 seconds while the screen is on and every 5 minutes while it
is off, and are skipped when recent traffic already proved the tunnel. Three
consecutive failures trigger a reconnect. Socket-protection failure never opens
a direct route.

Process separation contains native crashes; it is not a security boundary
between this app's components. System lockdown is needed when the owner process,
whole app, or device stops. Per-app lists control routing, not firewall denials.
Android lockdown may block apps outside that list. System network management
and tethered-device traffic are outside this app's guarantees.

A VPN changes routing, not GPS readings, account identity, advertising IDs,
hardware fingerprints, or data other apps send. The gateway sees the client's
public IP and authenticated certificate. Site traffic is end-to-end encrypted
when the originating app uses TLS. IPv6 destinations need an IPv6-capable exit
and the profile's IPv6 option enabled; unavailable destinations fail without a
direct retry. Android's [VPN address-family policy](https://developer.android.com/reference/android/net/VpnService.Builder#allowFamily(int))
blocks a family when no address, route, or DNS server of that family is added.

For captive Wi-Fi, use the Wi-Fi settings action and finish hotspot sign-in
before connecting. The app does not bypass a blocking VPN automatically.

## Privacy protections

What the app does:

- Routed traffic and DNS never fall back to a direct connection. Unassigned
  address families stay blocked. The app adds no exclusions or split routes;
  OpenVPN always routes all traffic of covered apps.
- No telemetry, analytics, crash upload, cloud sync, location, phone-state or
  package-inventory permission. The app reads only network capabilities, never
  Wi-Fi names.
- OpenVPN sends no hardware address, kernel version or custom peer variables.
  Without `tls-crypt`, OpenVPN must use TLS 1.3 so the client certificate is
  encrypted on the network; stunnel always requires TLS 1.3.
- Internal proxy endpoints accept only this app's own connections. Native
  engines cannot be read by other processes of the app user.
- Logs and status text omit IP addresses, hardware addresses, certificate
  names, email addresses, private paths and gateway names.
- The app screens cannot be captured or shown in the recent-apps preview; the
  lock screen shows only that a tunnel exists. Text fields ask keyboards not to
  learn or suggest and are excluded from autofill.

What it cannot do: your server and its proxy see your real IP address and your
client certificate. A gateway *name* is looked up on the current network before
connecting; a numeric address avoids that. The DNS-over-HTTPS provider (unless
names are resolved at the proxy) and the sites you visit see the proxy's
address. Apps that are not selected for the VPN, other local tunnels, and data
apps send about you are outside the tunnel's control. Use Android's always-on VPN
with **Block connections without VPN** to protect traffic while the app is not
running.

## Signed client packages

Operators can sign client packages so users can check their origin. The app
verifies an Ed25519 signature over `ssp-manifest.json`, which lists every file's
SHA-256 and can declare the profile name, mode, backend, tunnel section and DNS
mode. The import dialog shows the operator key fingerprint; a modified, extra or
missing file is rejected. Unsigned packages are labelled as such, and a
`SHA256SUMS` file, when present, must list every file.

```bash
python3 tools/sign_package.py --generate-key ~/private/operator-ed25519.pem
python3 tools/sign_package.py --key ~/private/operator-ed25519.pem \
    --output client-signed.zip --backend SOCKS5 client.conf client.pem server-ca.crt
```

Publish the printed fingerprint through a different channel than the package.

## Private data and backups

Profiles, keys, and saved credentials use Android Keystore AES-256-GCM in private,
non-backup storage; settings have their own snapshot so changing them never
rewrites credentials. A cross-process lock and atomic snapshot protect
reads/edits. Android/cloud backups are disabled. Private runtime PEM files are
removed when the connection stops. Uninstalling removes app data and its
Keystore keys.

Create a local backup in **Settings** before uninstalling or moving phones.
Portable backups use AES-256-GCM and PBKDF2-HMAC-SHA256 with 600,000 rounds,
random salt/nonce, and a password of at least 12 characters. Wrong passwords and
damaged backups do not replace saved profiles. Keep the password separately.
OpenVPN keys held in Android Keystore are never included. Backups from older
versions restore; a backup from a newer version is refused.

Import limits are 16 MiB expanded data, 4 MiB per file, and 128 entries. Traversal,
TAR links/special files, and ambiguous credential basenames are rejected.
Storage allows 128 profiles and a 32 MiB authenticated snapshot.

Logs are bounded in memory, exclude packet payloads, and are redacted when
written (see above). **Save redacted diagnostics** creates a manual local export;
review it before sharing. Native output is rate-limited and summarized instead of
truncated.

Aggregate DNS and connection counters help diagnose load without recording
queried domains. One non-blocking relay performs local and proxy handshakes and
transfers for up to 1024 connections; idle streams yield near that limit. While
the screen is on and traffic is recent, it keeps two pre-established tunnel
connections to save the TLS handshake for the next request.

## Build

The scripted build supports Linux x86-64 hosts and produces ARM64 Android code.
Install Python 3.12+, GNU make, a host C compiler, and standard build utilities.
Scripts prepare a local SDK/NDK/JDK under `.tools` and sources/builds under
`.native`. A local Perl is built when host modules are missing. Host networking
settings and system services are not changed.

```bash
python3 tools/bootstrap.py
python3 tools/gradle.py :app:testDebugUnitTest :app:assembleDebug
```

`preBuild` builds every engine from checksum-pinned sources and verifies cached
artifacts. Native code is built with `_FORTIFY_SOURCE`, stack clash protection and
zero-initialized locals; executables request asynchronous MTE heap tagging, and
OpenSSL omits QUIC, DTLS, SRP, compression and SSLv3. It cannot silently package a partial native build. Use
`python3 tools/build_native.py --force` to rebuild native code.

The Gradle helper honors an existing unauthenticated HTTP proxy in
`HTTP_PROXY`/`HTTPS_PROXY`; it does not create or modify one.

| Component | Version |
| --- | --- |
| stunnel / OpenSSL | 5.82 / 4.0.3 |
| OpenVPN / Android integration source | 2.7.8 / 0.7.68 |
| HevSocks5Tunnel / LZ4 | 2.18.0 / 1.10.0 |
| Android Gradle Plugin / Gradle | 9.4.1 / 9.8.1 |
| Kotlin / build JDK | 2.4.21 / Temurin 27+35 |
| SDK / build tools / NDK | 37.2 / 37.0.0 / 30.0.16248370 |
| Compose BOM / Activity / Lifecycle | 2026.09.00 / 1.13.0 / 2.11.0 |
| Coroutines / Serialization | 1.11.0 / 1.11.0 |
| OkHttp / dnsjava | 5.5.0 / 3.6.5 |
| Commons Compress / Bouncy Castle | 1.28.0 / 1.86 |

Source URLs/digests are in `native-dependencies.json` and
`build-dependencies.json`. Gradle verifies every downloaded artifact against
`gradle/verification-metadata.xml` and resolves the versions in the lockfiles.
After an intentional dependency change, regenerate both with:

```bash
python3 tools/gradle.py --write-locks --write-verification-metadata sha256 \
    :app:testDebugUnitTest :app:lintRelease :app:assembleDebug :app:assembleRelease \
    :app:assembleMinifiedDebug :app:assembleDebugAndroidTest
```

GitHub Actions (`.github/workflows/ci.yml`, actions pinned to commit SHAs) runs
the unit tests, release lint and builds. The release version is set in
`version.properties`.

### Signed release

```bash
python3 tools/create_signing_key.py
export SSLSOCKSPRO_SIGNING_PROPERTIES="$HOME/.local/share/sslsockspro/signing/signing.properties"
python3 tools/gradle.py :app:lintRelease :app:assembleRelease
```

The key/properties stay outside the checkout with private permissions. Back them
up privately; updates require the same key. The signed APK is
`app/build/outputs/apk/release/app-release.apk`. Debug and release signatures
differ; export a backup before uninstalling an installation signed with another
key.

### Phone tests

Connect one authorized, unlocked Android 16+ ARM64 phone. Accept VPN consent on
the device. Credentials are supplied at runtime into private app storage and
are never compiled into the APK.

```bash
python3 tools/gradle.py :app:assembleDebug :app:assembleDebugAndroidTest
python3 tools/device_test.py --client-package /private/path/client.tar.gz --server-ip SERVER_IP --openvpn-fixture
```

The optional OpenVPN fixture needs host `openvpn` and `stunnel`. It creates
disposable certificates, loopback listeners and temporary ADB TCP reverses.
Its `dev null` server tests authenticated data channels, not Internet forwarding.
It needs no root, host TUN interface, routes, or persistent service. After the
run, the script fails if the fixture server received a hardware address, kernel
version or user variables from the client.

Add `--saved-profile-ports 33009,33008` to run live checks with profiles already
saved on the phone, selected by a tunnel's local port; they are restored
afterwards. Add `--benchmark-url https://...` with a client package or saved
profile ports to measure DNS latency,
connection setup (sequential and 32 in parallel) and download throughput through
the proxy VPN; the result is saved under `.tools/benchmark-*.json`.

Tests restore saved profiles and settings. Add `--provision-profile NAME` with
a client package to retain that package as a selected all-app proxy VPN profile
after a successful live test. Test-only credentials are removed from the test
APK's private staging directory when the run finishes.

Build an optimized APK with the debug signing certificate for ordinary
device testing. This variant is non-debuggable and updates a debug installation
without deleting its profiles:

```bash
python3 tools/gradle.py :app:assembleMinifiedDebug
adb install -r app/build/outputs/apk/minifiedDebug/app-minifiedDebug.apk
```

Use the app's normal UI to check startup, profile editing, connection, encrypted
DNS, browsing, and disconnect. White-box instrumentation targets the debug
build: release R8 can remove or change APIs used only by the test harness.
Test credentials are staged in the private test APK and read through a provider
that requires the same signing certificate. Uninstall the test APK after tests.

## Source and licenses

The Android application is GPL-3.0-or-later. Components retain upstream licenses
and linking exceptions; the socket-protection shim is MIT licensed. Full texts
are in `app/src/main/assets/licenses`, with attribution in
`THIRD_PARTY_NOTICES.txt`. The OpenVPN executable is GPL-2.0 with upstream
exceptions. Publish corresponding source alongside an APK.

[HANDOFF.md](HANDOFF.md) covers implementation boundaries, updates, and checks.
Build outputs, signing material, test credentials, phone identifiers, and local
deployment packages do not belong in this repository.

After building the signed release and recording validation, package the APK,
corresponding application/native source, a CycloneDX software bill of materials,
and SHA-256 checksums:

```bash
python3 tools/package_release.py
```

The files are written to `out/`. The source archive includes local changes,
build scripts, license texts, and the checksum-pinned upstream native archives;
it excludes signing material, deployment credentials, and generated binaries.
