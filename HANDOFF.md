# SSLSocks Pro agent handoff

Read README.md and VALIDATION.md before changing this application.

## Product boundary

Android 16/API 36 minimum, ARM64 APKs only. The package is
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

## Code map

| Area | Files |
| --- | --- |
| Profile schema | `model/Models.kt` |
| Ordered stunnel parse/edit/render and policy | `config/StunnelDocument.kt` |
| OpenVPN parse/render and policy | `data/OpenVpnDocument.kt` |
| Import limits and safe archive handling | `data/PackageImporter.kt` |
| Keystore snapshot, locks, portable backups | `data/ProfileStore.kt`, `data/BackupCodec.kt` |
| PEM/key/CA validation and private runtime files | `data/Credentials.kt` |
| VPN owner, notifications, fail-closed recovery | `service/ConnectionService.kt` |
| Worker/native lifecycle | `engine/EngineService.kt` |
| Native socket protection IPC | `engine/ProtectionBroker.kt`, `main/cpp/protect_connect.c` |
| OpenVPN management events and descriptor ownership | `engine/OpenVpnManagement.kt` |
| Packet JNI bridge | `engine/HevEngine.kt` |
| DoH and authenticated SOCKS frontend | `network/TunneledDns.kt`, `network/SocksRelay.kt` |
| Compose UI/drafts | `ui/MainActivity.kt`, `ui/ProfileEditor.kt`, `ui/TunnelUiState.kt` |

Paths above are under `app/src/main/kotlin/io/github/cysin/sslsockspro` except the
explicit native path. AIDL lives under `app/src/main/aidl`.

## Invariants

- The VPN owner must retain its TUN during worker/native failure. Only explicit
  disconnect, permission revocation, Android service destruction, or mode changes
  close it. Whole-process death needs Android's system lockdown.
- Protect gateway descriptors before connecting; verify callback UID and session.
  Do not protect arbitrary application sockets. Gateway resolution is the only
  physical-network DNS bootstrap.
- Native children are read-only installed executables. Never execute from app
  data. Parent-death monitoring must stop orphan listeners.
- Keep native start/stop and cleanup serialized across service instances.
  Binder/UI threads must not wait for native startup, health probes, child exits,
  or joins. Cancellation must interrupt pending startup and cancel DoH calls.
- Pass duplicated TUN descriptors; the owner retains the original. HEV
  borrows the worker descriptor; the worker closes it after HEV stops. Never
  detach a duplicate into HEV. Close all received SCM_RIGHTS descriptors.
- OpenVPN connection blocks inherit proxy defaults at parse time. Insert proxy
  options before blocks and force TCP for stunnel-carried OpenVPN. Do not add
  `ifconfig-noexec`: Android's IFCONFIG management events must populate the TUN.
- Proxy VPN defaults to IPv4 only (`proxyIpv6 = false`). Leave IPv6 addresses,
  routes, and DNS servers out of its TUN so Android blocks that family. Never
  call `allowFamily`, `allowBypass`, or `excludeRoute` to accommodate an exit
  without IPv6. A stunnel gateway's address family and the proxy's destination
  families are independent.
- OpenVPN establishes only its assigned address families, including IPv6-only
  assignments. Filter DNS servers to those families and require at least one;
  missing usable DNS is a permanent configuration error with the blocking TUN
  retained. Preserve the first actionable configuration/authentication error
  when native shutdown emits generic failures. Test dual-stack, IPv6-only, and
  missing-DNS cases on the phone.
- Do not execute OpenVPN scripts/plugins or honor alternate management/proxy/log
  options from imported profiles.
- UDP associations and persistent TCP DNS must not occupy handshake workers.
  Keep queues, buffers, session count, import sizes, and logs bounded.
- Outbound HTTP/SOCKS proxy handshakes use a separate bounded pool. Slow
  destinations must not hold up local authentication or DNS setup. Test both
  Android Network.getAllByName and the default InetAddress resolver with
  all-app routing and background traffic; raw UDP queries alone miss this case.
- DoH always uses the chosen local proxy, neutralizes query IDs, and strips EDNS
  identity options. Record filtering must not preserve an invalid AD assertion.
- Profile writes use a cross-process file lock and authenticated AtomicFile
  snapshot. Never replace a damaged store with an empty one automatically.
- UI profile drafts and document results survive rotation in a ViewModel, not a
  saved-state bundle containing plaintext credentials. Active profiles are
  immutable until disconnected. Permission dialogs are sequenced.

## Build and native changes

Use `python3 tools/bootstrap.py`, then `python3 tools/gradle.py ...`.
`build-dependencies.json` pins build tools; `native-dependencies.json` pins native
source archives and nested HEV submodules. Downloads are checksum verified;
parent sources are extracted before nested dependencies.

`tools/build_native.py` builds only ARM64, uses Android-specific OpenVPN
configuration, links socket protection into CLI engines, validates 16 KB LOAD
alignment, and fingerprints all inputs/artifacts. It runs from Gradle preBuild.
Change versions/hashes and build scripts together; do not edit generated `.native`
sources as the sole implementation of a fix. A changed fingerprint invalidates
the whole native cache.

Keep the JNI package/class name and ProGuard rule in sync. Bouncy Castle uses
reflection for provider classes and must remain functional under R8. dnsjava's
desktop JVM service-provider resources are excluded on Android; its optional
Lombok generated annotation is not a runtime dependency.

Create a private signing key with `tools/create_signing_key.py` and point
`SSLSOCKSPRO_SIGNING_PROPERTIES` to its external properties file. Keep the same
key for updates. Do not replace or rotate an existing key automatically.

## Verification and delivery

Run JVM tests and release lint/build. For native/network/lifecycle changes, run
the real-phone tests with a user-owned stunnel package and the disposable OpenVPN
fixture. Run white-box instrumentation on debug, then exercise the actual
optimized `minifiedDebug` APK through its ordinary UI and network path. R8 may
remove test-only APIs/dependencies, so a release instrumentation-runner failure
is not a successful device test or proof of an application startup failure.

The phone must be connected, authorized, and unlocked. Launch VPN permission from
an Activity with a result caller; standalone new-task confirmation immediately
loses its calling identity. Accept consent on the phone. Do not alter global
Private DNS, Wi-Fi, system VPN lockdown, or production servers to make a test pass.

`tools/device_test.py` stages runtime credentials only into private test APK storage.
The test-only provider checks the caller's signing certificate. Credentials
never appear in command arguments or the production APK.
The fixture uses host OpenVPN/stunnel, rootless dev-null servers, synthetic
certificates, and temporary ADB reverses. Its logs are ignored under `.tools`.
It tests authenticated data-channel packets rather than Internet routing.

Check APK ABI/minimum API/signature, native versions/alignment, profile import,
Keystore and backup integrity, TCP/UDP DNS, record suppression, HTTP/SOCKS framing,
partial writes/half closes, worker death/blocking TUN, reconnect, native process
cleanup, and UI navigation/rotation. Record actual successes and limitations in
VALIDATION.md. A 4 KB phone does not validate execution on a 16 KB phone.

Produce an APK checksum and corresponding source bundle with
`tools/package_release.py`. Include original license notices. Report remaining
device/server coverage gaps; do not claim universal anonymity or all-device
compatibility. Commit/publish only when the user requests it.
