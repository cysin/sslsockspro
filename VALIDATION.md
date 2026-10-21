# Validation record

## Privacy, performance and reliability overhaul (2026-10-21)

Branch `privacy-performance-hardening`, eight commits after `aa462be`. Verified on
the Linux x86-64 build host without a phone:

| Check | Result |
| --- | --- |
| JVM tests | 85 run, 0 failures; 1 skipped because this host's sandbox denies loopback UDP (the UDP DNS relay test runs on ordinary hosts and CI) |
| Release lint | 0 errors; 4 warnings: the existing ChromeOS ABI and Bouncy Castle EST helper warnings, plus Gradle 9.8.2 and kotlinx-serialization 1.12.0 being available (seen now that lint can query repositories) |
| Builds | debug, debug test, `minifiedDebug` and unsigned release succeed with Gradle dependency verification and lockfiles enforced |
| Release APK | 8.7 MB (was 15.2 MB); `classes.dex` 2.9 MB (was 9.2 MB, of which 7,455 Bouncy Castle classes were kept) |
| Native engines | MTE heap-tagging note in both executables, `_FORTIFY_SOURCE` checked calls in all three ELF files, non-executable stacks, 16 KB alignment; stunnel 4.95 MB and OpenVPN 5.55 MB after OpenSSL feature trimming |
| Signed package interop | A package from `tools/sign_package.py` verifies with the OpenSSL CLI and in the app's verifier (JVM test fixture) |
| SBOM | 130 components (120 release runtime artifacts, 88 with verified SHA-256, and 10 native sources) |

JVM tests now cover the connection state machine (revocation, worker death,
permanent errors, unconfirmed shutdown, always-on, debounced network changes,
soft handover, immediate reconnect when a network returns, captive portals,
challenges and notices), split storage with format-1 migration and AtomicFile
recovery, key parsing without JCA providers (RSA, EC, Ed25519, encrypted PEM and
PBES2 PKCS#8), gateway failover rendering, OpenVPN identity and TLS policy,
redaction, DoH padding/User-Agent/preemptive relay credentials, the relay
reactor (pipelined handshakes, SOCKS5 pipelining with credentials, address
types, synthetic names, the session limit, warm connections and stale-warm
retry, owner checks), DNS cache/synthetic resolution/backend probing, signed
manifests, OpenVPN challenge formats and the Keystore key migration rewrite.

**Not yet verified on a phone.** No device was connected during this work. Before
a release, run `tools/device_test.py` with the client package, the OpenVPN
fixture and `--benchmark-url`, and the ordinary-UI checks on `minifiedDebug`,
and record here:

- The loopback owner check: the worker log must not report that the platform
  cannot attribute loopback connections, and `adb shell` (another UID) must be
  refused by the internal stunnel and relay ports while the VPN is connected.
- Proxy VPN with MTU 8500, the non-blocking relay, warm connections, backend
  identification and proxy-side DNS: browsing, downloads and DNS.
- Wi-Fi/mobile handover without a full reconnect; reconnection after loss.
- OpenVPN through a Keystore key (PK_SIGN), the absence of identifying peer
  information at the fixture server, TLS 1.3 enforcement, and challenges.
- Non-dumpable native engines (`NativeComponentsTest`).
- `FLAG_SECURE` (screen capture is black), lock-screen notification text, the
  Quick Settings tile, launcher shortcuts targeting a non-exported activity, boot
  start of a local proxy, and opening/sharing packages from another app.
- Benchmarks compared with a baseline built from commit `da870eb`.

Earlier records below describe the previous implementation.

Baseline recorded on 2026-10-14, with disconnect regressions checked on
2026-10-15 against the updated source and ARM64 build. Production
credentials, phone identifiers, and private test logs remain outside Git and the
source package.

## System VPN dialog disconnect (2026-10-15)

Reproduced on the Android 16 phone with the previously installed optimized APK:
disconnecting from the actual system VPN dialog (including its byte counters)
removed Android's VPN network while the app stayed at Disconnecting.
Always-on and lockdown were disabled.

The system VPN Disconnect path revokes permission and stops the owner service.
Previously, onRevoke launched an asynchronous disconnect and then called the
framework stopSelf implementation. Service destruction could cancel the pending
worker acknowledgement, leaving STOPPING in the shared UI state even though the
running/VPN flags were false.

Revocation now marks the stop as intentional and uses framework teardown without
starting a cancellable disconnect task. Destruction resets transient states to
IDLE; an explicit revocation also clears stale errors. Ordinary errors remain
visible after unprotected validation failure. Selected profiles are unchanged.

Existing device disconnect assertions now require IDLE and an enabled Connect
button in addition to cleared running/VPN flags and removal of the system VPN
network. System-dialog checks use ordinary UI taps outside instrumentation:
calling onRevoke alone does not release Android's binding, and the in-process
accessibility harness could not reliably activate this phone's OEM dialog.

The new JVM lifecycle regression fails against the previous implementation
because STOPPING survives destruction. The corrected implementation passes all
24 JVM tests, including teardown, permission revocation, and preservation of
configuration errors. Release lint passed with no errors and the two existing
warnings. Debug, instrumentation, optimized, and signed release APK builds
succeeded.

The corrected debug APK returned to Disconnected with Connect available after
a real system-dialog disconnect. The opt-in saved-profile device regression
also passed three app-button disconnects and cancellation during startup.

The seven baseline phone tests were rerun against the corrected debug build.
Native engines, encrypted storage, the disposable OpenVPN fixture, and UI
rotation passed. The initial stunnel attempt received a connection reset using
the client package's obsolete server address. Rerunning with the address from
the phone's working saved profile passed local proxy operation, tunneled DNS,
all-app VPN DNS/HTTPS, worker-death blocking, recovery, and disconnect. The test
profile snapshot was restored; no production server configuration was changed.

The optimized non-debuggable APK passed three ordinary UI connect/system-dialog
disconnect cycles on the same phone. Each removed Android's CONNECTED VPN
network and returned to Disconnected with an enabled Connect button. A further
reconnect and app-button disconnect passed, and no native stunnel/OpenVPN
children remained. The optimized build was left installed with the original
profiles. Its installed APK checksum matched the tested build; the test APK was
removed. No global Private DNS, always-on, or lockdown setting was changed.

## Disconnect regression (2026-10-15)

Reproduced on the connected Android 16 phone with the previously installed
optimized APK: tapping the app's Disconnect button displayed Disconnected while
Android still reported an active CONNECTED VPN network. Always-on and lockdown
were disabled. The stale network persisted after native children exited.

HEV borrows externally supplied TUN descriptors and does not close them. The
worker now retains ownership instead of detaching an untracked duplicate, and
closes its descriptor after HEV stops. The owner waits for worker cleanup before
reporting Disconnected. A shutdown timeout retains the blocking owner TUN and
reports an actionable error. The UI disables repeated clicks while stopping.

Final-code checks passed: 21 JVM tests, release lint (the existing two warnings),
debug/test APK builds, and the optimized minifiedDebug build. On the debug APK,
three ordinary UI connect/disconnect cycles and startup cancellation removed the
system VPN network. The opt-in saved-profile instrumentation regression also
passed (one test covering three UI disconnects and startup cancellation).
Its first run failed because the test read the accessibility window before it
was available; the harness now waits for the Disconnect button.

The optimized non-debuggable APK also passed three ordinary UI connection and
disconnection cycles plus disconnect shortly after Connect. Every disconnect
removed Android's CONNECTED VPN network. No native stunnel/OpenVPN children
remained afterward. The optimized APK was left installed with the existing
profiles, its checksum matched the tested build, and the test APK was removed.
No global Private DNS, always-on, or lockdown setting was changed.

The saved-profile regression is opt-in with instrumentation argument
`savedProfileTest=true` and test class
`io.github.cysin.sslsockspro.DeviceTunnelTest#savedProfileDisconnectReleasesSystemVpn`.
It uses the selected saved proxy VPN profile and restores the profile snapshot.

## Results

| Check | Result |
| --- | --- |
| JVM tests | 24 passed; no failures or errors |
| Debug phone instrumentation | 7 baseline tests passed across the runs described above; opt-in saved-profile disconnect regression also passed |
| Signed release and optimized test APK builds | Successful |
| Release lint | 0 errors, 2 warnings described below |
| Release signature | Verified with Android apksigner |
| APK requirements | Minimum API 36, target API 37, ARM64 only |
| Native ELF LOAD segments | At least 16 KB alignment in all four packaged ELF files |
| Optimized phone startup and navigation | Passed all five pages |
| Optimized phone proxy VPN and Chrome hostname HTTPS | Connected; a fresh trace reported the configured server exit address |
| Optimized explicit disconnect | Passed; selected profile preserved and test APK removed |

The phone ran Android 16/API 36 with ARM64 and 4 KB pages. The optimized
`minifiedDebug` build is non-debuggable, uses R8/resource shrinking, and shares
the debug signing certificate so it can update the test installation without
erasing encrypted profiles. The independently signed release APK is delivered
with corresponding source and SHA-256 checksums.

## Test coverage

JVM tests cover ordered stunnel parsing, repeated socket options, section
defaults, IPv6 endpoints, unsafe verification/exec/provider directives, OpenVPN
connection blocks and proxy inheritance, inline certificates and peer
fingerprints, archive limits/traversal/links, authenticated backups, certificate
roles/expiry, key matching, and normalized private-key round trips.

Relay tests exercise HTTP CONNECT and SOCKS framing, early data, partial
transfers/half closes, IPv6 destination encoding, persistent TCP/UDP DNS,
dropping other UDP, and DNS setup while outbound proxy handshakes are stalled.

The seven phone tests cover:

- Execution of the packaged stunnel 5.82 and OpenVPN 2.7.8 binaries, using
  OpenSSL 4.0.3, and loading the HevSocks5Tunnel 2.18.0 JNI engine.
- Keystore encryption, concurrent atomic edits from separate store instances,
  portable backup/restore, wrong-password/tamper rejection, and damaged-store
  handling. Saved profiles and settings are restored after testing.
- A live, certificate-verified stunnel connection using a user-supplied client
  package. Checks include local listeners, proxied DoH A/AAAA answers, DNS
  type 64/65 suppression, raw VPN DNS, Android's VPN resolver and default
  resolver under all-app routing, and hostname HTTPS.
- IPv6 socket rejection with the proxy profile's IPv6 option disabled. The
  tested production proxy exit supports IPv4; no server IPv6 change was made.
- Native worker termination, retention of the owner's blocking TUN, failure
  of new TCP connections while the worker is unavailable, recovery, and
  explicit disconnect.
- Mutually authenticated OpenVPN directly and through stunnel. A disposable
  rootless `dev null` server receives IPv4/IPv6 UDP test packets. IPv6-only
  assignment works and blocks IPv4. Missing usable DNS preserves the blocking
  TUN and its actionable configuration error without automatic retries.
- Compose navigation, theme selection, private profile drafts and backup
  password state across rotation, and cancellation of document operations.

The optimized build was checked through its ordinary UI and Chrome rather than
white-box instrumentation. It loaded encrypted profiles, rendered all five
pages, connected the all-app IPv4 proxy VPN, loaded a fresh HTTPS hostname page
with the expected exit address, and disconnected cleanly.

## Limits of this validation

A real 16 KB-page device has not been tested; ELF alignment alone does not
validate execution on such a device. Android versions newer than the connected
Android 16 phone and other OEM lifecycle policies were not tested.

Sustained background/battery behavior, Wi-Fi/mobile handover, captive-portal
sign-in, system always-on lockdown across whole-app death, interactive OpenVPN
authentication, and production OpenVPN Internet forwarding require additional
device/server coverage. The disposable OpenVPN server validates authenticated
packet transport without Internet forwarding. The production proxy's IPv6
Internet exit was not tested because that server has IPv6 disabled.

R8 may remove or alter dependencies/APIs used only by white-box tests, so those
tests target the ordinary debug build. An instrumentation harness failure on a
minified APK is not evidence of successful testing or an app startup failure.
The optimized UI/network checks do not replace all debug assertions.

## Static checks

ARM64-only builds intentionally retain lint's ChromeOS x86 ABI warning.
Bouncy Castle includes an unused EST helper with an empty trust-manager method;
lint reports it from the dependency JAR. The application does not use that
helper or register Bouncy Castle as the HTTPS trust provider. DoH uses Android's
default certificate/hostname verification; stunnel/OpenVPN verify their
configured CA and peer identity.

dnsjava desktop JVM DNS service-provider descriptors are absent from the APK.
Bouncy Castle provider classes are retained for reflective algorithm loading.
No deployment PEM/private-key file is packaged into the application. Native
executables are installed read-only; runtime credentials are private and
removed when the connection stops. System/cloud backup and device-transfer
exclusions are explicit.

See README.md for routing coverage, DNS bootstrap disclosure, supported modes,
and the Android system-lockdown requirement. A VPN does not hide account
identity, GPS readings, or device fingerprints supplied by other applications.
