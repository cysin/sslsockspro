# SSLSocks Pro agent handoff

Read README.md and VALIDATION.md before changing this application.

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
