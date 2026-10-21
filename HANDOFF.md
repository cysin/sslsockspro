# SSLSocks Pro agent handoff

Read README.md and VALIDATION.md before changing this application.

## Current task: real-phone validation of `privacy-performance-hardening`

Branch `privacy-performance-hardening` (pushed to `origin`) holds eight commits
after `aa462be` (see `git log aa462be..HEAD`): CI and dependency verification,
robustness fixes, the `TunnelController` state machine and split storage,
privacy hardening, the non-blocking relay and DNS work, quick controls and
OpenVPN challenges, native hardening with Keystore OpenVPN keys, and docs.
Everything passed host checks (85 JVM tests, release lint, all builds; see
VALIDATION.md), but **nothing has run on a phone yet**. Your job is to validate it
on the user's connected Android 16 ARM64 phone, fix what fails, and record the
results. The phone holds the user's real profiles; the user asked to test with
the saved profiles whose stunnel tunnels listen on local ports **33009** and
**33008**.

Ground rules: do not change production servers, Android Private DNS, Wi-Fi,
always-on VPN or lockdown settings; do not reboot, uninstall, `pm clear`, or
restore backups without the user's explicit agreement; keep phone identifiers,
server addresses and credentials out of Git and of VALIDATION.md. Commit or push
only when the user asks (stored credentials: `git -c
credential.helper="store --file=$HOME/.git-credentials" push`).

### Step 0 — protect the phone's data (blocking)

1. Check the phone and the installed app (`ADB=.tools/android-sdk/platform-tools/adb`):
   `$ADB devices -l`, `$ADB shell getprop ro.build.version.sdk` (36+),
   `$ADB shell getprop ro.product.cpu.abi` (arm64-v8a), and the installed signer:
   `$ADB shell pm path io.github.cysin.sslsockspro`, pull that `base.apk`, then
   `JAVA_HOME=$PWD/.tools/jdk .tools/android-sdk/build-tools/37.0.0/apksigner verify --print-certs base.apk`.
2. Signing certificates seen so far (SHA-256):
   - `2a1fe8cacdd20aceb723c95ed05d22efa34616c4bb138527d0f2df1cbc62ae55`: the old
     debug key that signed the `*-phone-update.apk` builds in `out/`, which is
     most likely what the phone runs.
   - `7d59dfada238c9b44545668b7ed3720120ff96e7651c7b1c5810835e2328ca9b`: the
     release key (`SSLSOCKSPRO_SIGNING_PROPERTIES`); not on this machine.
   - `fab032fd0ba68fc72ee9ef5747a67cc90324e42ed997a9ec47c3246a0176dcab`: the
     debug key that `~/.android/debug.keystore` on this machine (created
     2026-10-21) puts on every new build.
   Android updates an app in place only when the certificate matches. **If the
   phone's signer is not `fab032fd…`, `adb install -r` fails, and uninstalling
   would destroy the profiles and their Keystore keys.** Then either:
   - A (preferred): ask the user for the keystore that signed the installed
     app (old `debug.keystore`, or the release signing properties). Move the
     current `~/.android/debug.keystore` aside, put the old one in place (or
     export `SSLSOCKSPRO_SIGNING_PROPERTIES`), and rebuild. The update then keeps
     all data.
   - B: only with the user's explicit agreement — the user creates **Settings →
     Create encrypted local backup** in the installed app and keeps the
     password; then uninstall, install the new build, and restore that backup
     (format-1 backups are accepted). Keystore-held keys do not exist in the old
     version, so nothing else is lost.
3. The first launch of the new version migrates storage from format 1 to 2
   (settings move to `settings.enc`); the old version cannot read format 2,
   so there is no downgrade. Any OpenVPN RSA/EC client key in a profile is also
   moved into Android Keystore and removed from the profile. Before the first
   launch, install the debuggable debug build manually
   (`$ADB install -r app/build/outputs/apk/debug/app-debug.apk`, after Step 1)
   and copy the sealed files, which stay readable only with this app's Keystore
   key:
   `$ADB shell run-as io.github.cysin.sslsockspro sh -c 'mkdir -p files/pre-upgrade && cp -p no_backup/profiles.enc* files/pre-upgrade/'`.
   Only then run `device_test.py` or open the app. (`device_test.py` installs
   and starts the tests in one go, so it leaves no point to copy in between.)

### Step 1 — build

```bash
python3 tools/gradle.py :app:testDebugUnitTest :app:assembleDebug :app:assembleDebugAndroidTest :app:assembleMinifiedDebug
```

The build sandbox used so far denies loopback UDP (one JVM test skips with a
message); the Gradle daemon must have network access to resolve dependencies.

### Step 2 — automated phone tests

```bash
python3 tools/device_test.py --saved-profile-ports 33009,33008 --openvpn-fixture \
    [--benchmark-url https://<large file chosen by the user>]
```

This installs the debug and test APKs, then runs `NativeComponentsTest`
(engines run, are not dumpable), `ProfileStorageTest` (Keystore storage,
backups, damaged-store handling; it restores the saved profiles), `UiDeviceTest`
(navigation, rotation; secure fields are platform `EditText`s driven through
accessibility), `OpenVpnDeviceTest` (disposable host OpenVPN server — direct,
through stunnel, Keystore-held key via PK_SIGN, IPv6-only, missing DNS) and
`DeviceTunnelTest`:
- `savedProfileLiveChecks`: for each port, finds the saved profile whose
  stunnel section listens there, runs it as a local proxy (listener reachable),
  then as an all-app proxy VPN with DoH and with proxy-side DNS. It checks that
  the configured port is not listening in VPN mode, VPN-resolver DNS (placeholder
  `198.18.x` answers in proxy-side mode), the default resolver, an HTTPS request,
  IPv6 blocking, and the in-app tunnel test, and finally that a killed worker
  leaves traffic blocked until reconnect.
- `savedProfileDisconnectReleasesSystemVpn`: runs only if the selected saved
  profile is a proxy VPN profile.
- `benchmarkProxyVpn`: with `--benchmark-url`, measures DNS, connection setup
  and throughput with the first saved profile.
Saved profiles and settings are restored after each test. Output:
`.tools/device-tests.txt`, `.tools/benchmark-*.json`, and the OpenVPN fixture
logs `.tools/openvpn-fixture-*.log`; the script fails if the fixture server saw
a hardware address, kernel version or user variables. Host `openvpn` 2.7 and
`stunnel` are installed. A meaningful before/after benchmark needs the old
version measured before upgrading; with saved profiles only the new version has
this test, so report absolute numbers unless the user provides a client package
for `da870eb`.

### Step 3 — ordinary-UI checks with the optimized build

Install `app/build/outputs/apk/minifiedDebug/app-minifiedDebug.apk` with
`install -r`. The app sets `FLAG_SECURE`, so `screencap` shows black (that is
itself check 6); inspect screens with `$ADB shell uiautomator dump` and read
logs on the Logs screen or via **Save redacted diagnostics**.

1. Profiles 33009/33008 are intact after the migration; selection and settings
   are preserved.
2. Phone VPN with each profile: Chrome browsing works and **Test connection**
   reports a round trip. The status page shows the duration, rates and network
   type, plus a notice if the backend type was corrected.
3. Loopback guard: while connected, list loopback listeners
   (`$ADB shell cat /proc/net/tcp`; 33009 is 0x80F1, 33008 is 0x80F0) and confirm
   the selected tunnel's port is not listening. Connect from the shell UID to
   each other app listener (`$ADB shell 'toybox nc -w 2 127.0.0.1 PORT < /dev/null; echo $?'`):
   the internal stunnel and relay ports must close immediately without data,
   the relay's 30-second diagnostics line must count "rejected local clients",
   and the log must not say the platform "cannot attribute loopback
   connections". (Other sections of a profile intentionally stay open to all
   local apps.)
4. Toggle **Resolve names at the proxy server** in a profile; browsing still
   works.
5. Handover: switch between Wi-Fi and mobile data while connected. Expect
   "Network changed; keeping the tunnel and checking it", the status stays
   Connected and browsing resumes; after a full loss the tunnel reconnects as
   soon as a network returns.
6. Privacy surfaces: screenshot black, recents thumbnail hidden, lock-screen
   notification reads "Tunnel status is hidden on the lock screen", keyboard
   shows no suggestions in profile fields.
7. Quick Settings tile toggles (unlock required when locked); launcher shortcuts
   Connect/Disconnect work. If Android refuses to start the non-exported
   `ShortcutActivity`, remove the `android.app.shortcuts` meta-data — never
   export the activity.
8. Share or open a client package from a file manager: an import confirmation
   appears; a package signed with `tools/sign_package.py` (use a throwaway key)
   shows its fingerprint.
9. Optional, with the user's agreement: boot start of a local proxy profile
   (needs a reboot) and Disconnect from Android's system VPN dialog.

### Likely failure points and where to look

- Owner check unavailable or rejecting the app itself: `engine/LoopbackOwner.kt`,
  `ProtectionBroker` `'U'` requests, `protect_connect.c` (`guarded_listener`,
  `owner_allowed`). Per-app mode deliberately adds this app to the VPN.
- Stalls with large transfers: MTU 8500 — set `EngineService.PROXY_MTU` to 1500
  (the owner TUN uses the same constant) and retest.
- Relay problems: `network/SocksRelay.kt` (reactor states, warm pool); its
  diagnostics line every 30 s; JVM tests in `SocksRelayTest`.
- Backend identification: `network/BackendProbe.kt` (results are cached per
  profile in the worker process).
- Keystore signing: `data/KeystoreKeys.kt`, `OpenVpnManagement.sign` (errors
  report "Android Keystore could not sign").
- APIs newer than API 36 crash on Android 16 (`Process.pid()`, `onExit()`);
  check `platforms/android-37.2/data/api-versions.xml`.

### Record the results

Replace the "Not yet verified on a phone" list at the top of VALIDATION.md with
what was actually verified, the benchmark numbers, and every failure or
limitation (including anything skipped). Run the JVM tests and release lint
again after any fix.

## Product boundary

Android 16/API 36 minimum, ARM64 APKs only, English only. The package is
`io.github.cysin.sslsockspro`. Support local stunnel TCP tunnels, strict proxy VPN
(TCP plus tunneled DNS; other UDP blocked), and built-in OpenVPN. Use native
OpenVPN management/TUN integration; do not require another installed VPN app.

Keep raw, ordered stunnel configuration and repeated directives. GUI modes,
credentials, DNS policy, app routing, and selected tunnel live in the encrypted
profile model. Never advertise listeners as verified VPN connectivity. Explain
coverage and failures in plain language.

No Drive integration, analytics, device identifier/location collection, automatic
crash upload, unsafe TLS fallback, or direct DNS fallback. Do not put production
certificates, client/server keys, signing keys, test fixture packages, phone
identifiers, generated APKs, or native binaries in Git.

## Privacy invariants

Privacy has priority over reach and convenience. Changes must keep all of these:

1. Routed traffic and DNS never fall back to a direct path. Never add
   `allowBypass`, `allowFamily`, `excludeRoute`, disallowed (excluded) apps, or
   OpenVPN split routes. The include-only app list is the only routing choice.
2. Internal endpoints serve only this app: in VPN modes the selected stunnel
   tunnel listens on a per-session loopback port whose only client is the
   authenticated relay; native `accept()` and the relay admit a client only if
   `ConnectivityManager.getConnectionOwnerUid` names this app. A startup probe
   disables the owner check (keeping the private port) where the platform
   cannot attribute loopback connections; log that case.
3. Nothing identifies the device to servers: OpenVPN rejects `push-peer-info`,
   `UV_`/`IV_` variables and options nested in `setenv opt` that would be
   rejected directly. The VPN session name is generic.
4. Client certificates are never sent in clear: stunnel requires TLS 1.3;
   OpenVPN requires TLS 1.3 unless `tls-crypt`/`tls-crypt-v2` is configured.
5. No new permissions beyond the manifest's (no location, phone state or
   `QUERY_ALL_PACKAGES`), no SSID reads, and no new third-party network
   services (for example no "what is my IP" check).
6. Every diagnostic and status text passes `privacy/Redactor` (addresses,
   hardware addresses, certificate subjects, emails, private paths, gateway
   names). Screens use `FLAG_SECURE` and no recents screenshot; lock-screen
   notifications and the Quick Settings tile show state only; sensitive input
   uses `SecureTextField` (no IME learning or suggestions, no autofill, no
   saved-state copy).
7. DNS has one egress, through the tunnel, padded (RFC 8467) and without
   User-Agent. Gateway-name lookups on the physical network are disclosed in
   the UI with an option to use the address instead.
8. Native children are non-dumpable. OpenVPN RSA/EC client keys live in
   non-exportable Android Keystore entries and are excluded from backups.

## Code map

Paths are under `app/src/main/kotlin/io/github/cysin/sslsockspro` unless noted.

| Area | Files |
| --- | --- |
| Profile schema | `model/Models.kt` |
| Ordered stunnel parse/edit/render and policy | `config/StunnelDocument.kt` |
| Gateway resolution plan (multi-address failover) | `config/GatewayPlan.kt`, `data/Gateways.kt` |
| OpenVPN parse/render and policy | `data/OpenVpnDocument.kt` |
| Import limits, safe archives, signed manifests | `data/PackageImporter.kt`, `data/PackageManifest.kt`, `tools/sign_package.py` |
| Keystore-sealed storage (profiles and settings), portable backups | `data/ProfileStore.kt`, `data/Sealer.kt`, `data/BackupCodec.kt` |
| PEM/key/CA validation and private runtime files | `data/Credentials.kt` |
| OpenVPN client keys in Android Keystore | `data/KeystoreKeys.kt` |
| Connection lifecycle decisions | `service/TunnelController.kt` (pure Kotlin, JVM-tested) |
| VPN owner, notifications, platform operations | `service/ConnectionService.kt`, `service/TunnelPlatform.kt`, `service/TunnelState.kt` |
| Tile, shortcuts, boot start | `service/TunnelTileService.kt`, `ui/ShortcutActivity.kt`, `service/BootReceiver.kt`, `service/QuickControls.kt` |
| Worker/native lifecycle, event codes | `engine/EngineService.kt`, `engine/EngineEvent.kt`, `engine/LogLimiter.kt` |
| Native socket protection and accept guard | `engine/ProtectionBroker.kt`, `engine/LoopbackOwner.kt`, `app/src/main/cpp/protect_connect.c` |
| OpenVPN management, challenges, PK_SIGN | `engine/OpenVpnManagement.kt` |
| Packet JNI bridge | `engine/HevEngine.kt` |
| Relay reactor (SOCKS5/HTTP frontends, upstream, warm pool) | `network/SocksRelay.kt`, `network/BackendProbe.kt` |
| DNS: DoH, cache, proxy-side resolution | `network/TunneledDns.kt`, `network/DnsService.kt` |
| Redaction | `privacy/Redactor.kt` |
| Compose UI | `ui/TunnelApp.kt`, `ui/MainViewModel.kt`, `ui/*Screen.kt`, `ui/ProfileEditor.kt`, `ui/AppPicker.kt`, `ui/SecureTextField.kt` |

AIDL lives under `app/src/main/aidl`.

## Invariants

- System VPN revocation must stop the owner without relying on a coroutine
  that service destruction can cancel. Teardown resets transient connection
  stages to IDLE; ordinary configuration errors remain visible until retry.
- The VPN owner must retain its TUN during worker/native failure and network
  loss. Only explicit disconnect, permission revocation, Android service
  destruction, or mode changes close it. Whole-process death needs Android's
  system lockdown.
- Lifecycle decisions belong in `TunnelController`; `ConnectionService` only
  performs platform operations. Cover each new transition with a JVM test.
- Network callbacks are debounced. A working tunnel survives a network change
  (rebind, drop pooled connections, OpenVPN `network-change`, worker re-check);
  escalate to a full reconnect only after failed checks, and reconnect at once
  when a lost network returns.
- Protect gateway descriptors before connecting; verify callback UID and session.
  Do not protect arbitrary application sockets. Gateway resolution is the only
  physical-network DNS bootstrap; every resolved address is an allowed peer.
- Native children are read-only installed executables. Never execute from app
  data. Parent-death monitoring must stop orphan listeners.
- Keep native start/stop and cleanup serialized across service instances.
  Binder/UI threads must not wait for native startup, health probes, child exits,
  or joins. Cancellation must interrupt pending startup and cancel DoH calls.
- Pass duplicated TUN descriptors; the owner retains the original. HEV
  borrows the worker descriptor; the worker closes it after HEV stops. Never
  detach a duplicate into HEV. Close all received SCM_RIGHTS descriptors.
- The proxy VPN TUN MTU (`EngineService.PROXY_MTU`) must equal HEV's MTU.
- OpenVPN connection blocks inherit proxy defaults at parse time. Insert proxy
  options before blocks and force TCP for stunnel-carried OpenVPN, which uses
  the relay's authenticated HTTP frontend. Do not add `ifconfig-noexec`:
  Android's IFCONFIG management events must populate the TUN. The app owns
  `auth-retry interact` (for CRV1) and `management-external-key`.
- Proxy VPN defaults to IPv4 only (`proxyIpv6 = false`). Leave IPv6 addresses,
  routes, and DNS servers out of its TUN so Android blocks that family.
- OpenVPN establishes only its assigned address families, including IPv6-only
  assignments. Filter DNS servers to those families and require at least one;
  missing usable DNS is a permanent configuration error with the blocking TUN
  retained. Preserve the first actionable configuration/authentication error
  when native shutdown emits generic failures.
- Do not execute OpenVPN scripts/plugins or honor alternate management/proxy/log
  options from imported profiles.
- The relay is one non-blocking reactor; nothing in it may block on the network.
  Keep queues, buffers, session count (1024), DNS requests in flight, import
  sizes, and logs bounded. UDP carries DNS only.
- DoH always uses the relay, neutralizes query IDs, strips EDNS identity options,
  pads queries, and never preserves an invalid AD flag. Synthetic DNS answers
  must never be produced for local names (`localhost`, `.local`, `.arpa`).
- Profile writes use a cross-process file lock and authenticated snapshots.
  Never replace a damaged store with an empty one automatically. Reject storage
  or backup formats newer than `Backup.FORMAT`.
- UI drafts and document results survive rotation in `MainViewModel`, never in
  a saved-state bundle. Active profiles are immutable until disconnected.
  Permission dialogs are sequenced. Shared files are always confirmed.

## Build and native changes

Use `python3 tools/bootstrap.py`, then `python3 tools/gradle.py ...`.
`build-dependencies.json` pins build tools; `native-dependencies.json` pins native
source archives and nested HEV submodules. Downloads are checksum verified;
parent sources are extracted before nested dependencies. Gradle verifies every
artifact against `gradle/verification-metadata.xml` and the lockfiles; regenerate
both (README, Build) after any intentional dependency change and review the diff.

`tools/build_native.py` builds only ARM64 with hardening flags, uses Android-
specific OpenVPN configuration, links socket protection and the accept guard into
CLI engines, validates 16 KB LOAD alignment and the MTE note, and fingerprints all
inputs/artifacts. It runs from Gradle preBuild. Change versions/hashes and build
scripts together; do not edit generated `.native` sources as the sole
implementation of a fix. A changed fingerprint invalidates the whole native cache.

APIs newer than API 36 (for example `Process.pid()` or `onExit()`) are not
available on Android 16; check `api-versions.xml` before using JDK additions.

Keep the JNI package/class name and ProGuard rule in sync. Credentials use Bouncy
Castle's lightweight API only, so no provider classes are kept; do not register
the Bouncy Castle provider. dnsjava's desktop JVM service-provider resources are
excluded on Android.

Create a private signing key with `tools/create_signing_key.py` and point
`SSLSOCKSPRO_SIGNING_PROPERTIES` to its external properties file. Keep the same
key for updates. Do not replace or rotate an existing key automatically. Raise
`versionCode` in `version.properties` for every published APK.

## Verification and delivery

Run JVM tests and release lint/build. For native/network/lifecycle changes, run
the real-phone tests with a user-owned stunnel package and the disposable OpenVPN
fixture. Run white-box instrumentation on debug, then exercise the actual
optimized `minifiedDebug` APK through its ordinary UI and network path. R8 may
remove test-only APIs/dependencies, so a release instrumentation-runner failure
is not a successful device test or proof of an application startup failure.

Some build sandboxes deny loopback UDP; the UDP relay test then skips with a
message. Run it on a normal host or CI before relying on UDP DNS changes.

The phone must be connected, authorized, and unlocked. Launch VPN permission from
an Activity with a result caller; standalone new-task confirmation immediately
loses its calling identity. Accept consent on the phone. Do not alter global
Private DNS, Wi-Fi, system VPN lockdown, or production servers to make a test pass.

`tools/device_test.py` stages runtime credentials only into private test APK storage.
The test-only provider checks the caller's signing certificate. Credentials
never appear in command arguments or the production APK.
The fixture uses host OpenVPN/stunnel, rootless dev-null servers, synthetic
certificates, and temporary ADB reverses. Its logs are ignored under `.tools`;
the script checks them for identifying peer information.
It tests authenticated data-channel packets rather than Internet routing.

Check APK ABI/minimum API/signature, native versions/alignment/hardening, profile
import, Keystore and backup integrity, TCP/UDP DNS, record suppression, HTTP/SOCKS
framing, partial writes/half closes, worker death/blocking TUN, reconnect and
handover, native process cleanup, the loopback guard against other UIDs, and UI
navigation/rotation. Record actual successes and limitations in VALIDATION.md.
A 4 KB phone does not validate execution on a 16 KB phone.

Produce an APK checksum, SBOM and corresponding source bundle with
`tools/package_release.py`. Include original license notices. Report remaining
device/server coverage gaps; do not claim universal anonymity or all-device
compatibility. Commit/publish only when the user requests it.
