# Validation record

## Android 16 phone validation (2026-10-21)

Validated `privacy-performance-hardening` at `a17c695` (nine commits after
`aa462be`) plus the fixes below, on the connected Android 16/API 36 ARM64
phone with 4 KB pages. The user authorized committing and pushing these changes
after validation. Tests used the user's
saved profiles for local ports **33009** and **33008**. Raw phone evidence,
sealed snapshots and disposable packages remain in ignored local files; no
phone identifiers, production addresses, certificates or credentials are
recorded here.

The installed app and all new test/update APKs already had matching signing
certificates using the existing local key. The main app was updated in place;
no signing key was moved or replaced, main-app data was not cleared, and the
phone was not rebooted. Before the first upgraded launch, the debug APK was
installed manually and `no_backup/profiles.enc*` was copied both into the app's
private `files/pre-upgrade` directory and to a private host archive. Storage
then migrated from format 1 to 2.

The final device comparison read a disposable copy of that sealed snapshot and
passed: all profiles and credentials matched, and selection/settings matched
exactly. Profile comparison ignores ordering and `modifiedAt`, which ordinary
editor saves can change. The original 33009 selection and DNS choices were
restored. The final installed APK is the non-debuggable `minifiedDebug` build;
its checksum matches the built APK. The app ends Disconnected with no system
VPN network or native engine children.
The instrumentation package `io.github.cysin.sslsockspro.test` remains installed
at the user's explicit request; neither application was uninstalled.

| Automated/static check | Actual result |
| --- | --- |
| JVM tests after all fixes | **96 passed**, 0 failures/errors/skips. This run permitted loopback UDP; the earlier sandbox-dependent UDP skip did not occur. |
| Release lint | **0 errors**, 4 existing warnings: `AndroidGradlePluginVersion`, `NewerVersionAvailable`, `ChromeOsAbiSupport`, `TrustAllX509TrustManager`. |
| Builds | debug, debug androidTest, `minifiedDebug`, unsigned release passed; dependency verification and lockfiles remain enforced. Optimized APK is approximately 8.7 MB. |
| Full phone suite | `python3 tools/device_test.py --saved-profile-ports 33009,33008 --openvpn-fixture`: **10 passed, 2 conditional skips** (12 methods). This full run followed the owner-check and transport-label fixes. |
| Final UI/import fix coverage | Three additional JVM event-consumption tests, `UiDeviceTest` (navigation, theme, drafts/password state across recreation), actual optimized-package sharing and a final optimized VPN/Chrome connection passed. The final pre-upgrade snapshot comparison also passed. |
| Saved-profile network coverage | Both ports passed local-proxy operation, VPN with DoH and proxy-side DNS, VPN/default resolver and HTTPS checks, IPv6 blocking, worker-death blocking/recovery and explicit disconnect. |
| Disposable OpenVPN fixture | Direct and stunnel-carried authenticated packet transport, TLS 1.3, Keystore-held client key via PK_SIGN, IPv6-only assignment and missing-DNS blocking passed. Server logs contained no hardware-address, kernel-version or user-variable peer information. |
| Native engines | stunnel and OpenVPN both ran and rejected same-app reads of their process environment in the non-dumpable check; JNI loaded. Native sources were unchanged; Gradle's native pre-build verification passed with the existing 16 KB alignment, hardening and MTE checks. |

The full-suite skips were the user-disabled benchmark and the legacy live test
that needs a supplied client-package path; the saved-profile equivalent ran for
both requested profiles. After the final UI-only import fix, relevant UI,
sharing, storage-integrity and optimized connectivity checks were rerun rather
than claiming another full OpenVPN/network suite run.

### Nine ordinary-UI checks on the optimized APK

| # | Check | Result |
| --- | --- | --- |
| 1 | Migration, profiles, selection and settings | **Pass.** Both saved profiles worked; final sealed-snapshot comparison covered every saved profile/credential and exact selection/settings. |
| 2 | Each profile's VPN, Chrome and status | **Pass.** Chrome hostname HTTPS and Test connection worked with both profiles. Duration, traffic rates and current network rendered. These saved profiles did not trigger a backend-correction notice; backend detection has automated/JVM coverage. |
| 3 | Internal listener ownership | **Pass after fix.** Configured ports 33009/33008 were closed in VPN mode. Both internal listeners rejected shell-UID probes without data (observed 37–71 ms), relay diagnostics counted rejected local clients, and corrected runs had no owner-attribution fallback warning, including after network recovery. |
| 4 | Resolve names at the proxy server | **Pass.** Enabled through the ordinary 33008 editor, saved, reconnected, browsed HTTPS and ran Test connection, then restored the original option. Automated tests exercised both DNS modes on both profiles. |
| 5 | Network handover and full loss | **Pass after fixes.** User-operated mobile-to-Wi-Fi handover kept the connection and its uptime; Wi-Fi-only HTTPS/DNS passed. After about 16.7 seconds without a physical Internet network, restoration triggered connection in about 2 seconds; the internal owner checks remained effective. |
| 6 | Privacy surfaces | **Partial pass.** App screenshots were black; the actual recent-apps card hid its content. Profile input reported `TYPE_TEXT_FLAG_NO_SUGGESTIONS` and `IME_FLAG_NO_PERSONALIZED_LEARNING`. Lock-screen notification text was **not tested** because the user's original notification permission was denied/user-fixed; that setting was preserved. |
| 7 | Tile and launcher shortcuts | **Pass with a limitation.** Unlocked tile Disconnect and launcher Disconnect removed the VPN. Connect correctly opened the app while notification permission was denied. Actual launcher shortcuts worked with `ShortcutActivity` still non-exported. A locked tile tap kept the VPN connected, but manual unlocking did not execute that queued request on this phone; another unlocked tap was needed. Deferred execution after unlocking remains unresolved. |
| 8 | External client-package sharing | **Pass after fix.** Shared a disposable package from the phone's file manager. The import confirmation showed a fingerprint matching the throwaway operator key used by `tools/sign_package.py`. Cancelled the confirmation; no test profile was saved. |
| 9 | System VPN disconnect / optional boot start | **Disconnect passed.** The real Android VPN dialog removed the VPN, returned the app to Disconnected with Connect enabled, and left no native children. **Boot start skipped** at the user's request; no reboot performed. |

The user performed all Wi-Fi/mobile switches. The first Wi-Fi Chrome attempt
failed because that network had a pre-existing HTTP proxy pointing at the
configured local port, which is intentionally closed in VPN mode. The user
removed that proxy; Wi-Fi browsing then passed. No production server, Android
Private DNS, always-on VPN or lockdown setting was changed. Final checks match
the original values for Private DNS, always-on/lockdown and Wi-Fi state; the
phone is back on mobile data with Wi-Fi off. The user's intentional proxy
removal was not reversed.

### Failures found and corrected

After a blocking VPN was replaced during network recovery, Android briefly
could not attribute a self-connection. The original one-shot probe treated
that timing window as an unsupported platform and disabled the guard for the
session. `LoopbackOwnerProbe` now retries for up to two seconds and remembers
successful attribution for the worker's lifetime. Once verified, a later
timeout aborts startup instead of disabling the guard; interruption also aborts.
Four deterministic JVM cases and a repeated real-phone loss/recovery plus
shell-UID rejection check passed.

The status screen could display Mobile data while the active VPN advertised
Wi-Fi, because an unrelated mobile network remained validated. The screen now
prefers the active network's transport and observes VPN transport changes.
Three JVM cases and the Wi-Fi-only device/UI checks passed.

External sharing initially showed “The coroutine scope left the composition”.
Clearing the shared intent changed its own `LaunchedEffect` key and cancelled
the suspended document read. A stable collector now acknowledges an event
after reading it and preserves a newer event arriving during that read;
cancellation is propagated. Three JVM cases and actual file-manager sharing on
the corrected optimized APK passed.

The first OpenVPN fixture run also exposed an incorrect test assertion: it
rejected a private key still required by the fixture's stunnel configuration.
The assertion now permits stunnel-referenced credentials while checking that
OpenVPN-only files contain no private key. Cleanup includes assertion failures,
and a JVM case covers the shared-credential rewrite. No product key-migration
change or relaxation was needed.

### Measurements and remaining limits

**Throughput benchmark and before/after baseline: skipped at the user's
request.** No large-file URL was supplied or chosen, and no throughput or
speedup claim is made. These isolated Test connection observations only verify
connectivity; they are not a benchmark:

| Functional check | Observed DNS round trip |
| --- | --- |
| 33009, mobile data, final optimized build | 461 ms |
| 33009, Wi-Fi only | 278 ms |
| 33008, DoH | 398 ms |
| 33008, proxy-side DNS | 246 ms |

- Reboot/boot auto-start was skipped by user choice.
- No OpenVPN server with an OTP challenge was available. Challenge parsing has
  JVM coverage; actual interactive authentication remains untested.
- Lock-screen notification text and notification-permission-granted quick
  connection were not exercised with the user's denied notification setting.
- Locked-tile deferred action did not execute automatically after unlocking on
  this phone; use another unlocked tap. Recheck that interaction before claiming
  full quick-control coverage.
- No real 16 KB-page device, other OEM/version, sustained background/battery
  run, captive portal, whole-app-death lockdown test or large-file/MTU stress
  test was covered. The existing MTU 8500 passed ordinary traffic only.
- The disposable OpenVPN fixture validates authenticated packet transport,
  not production Internet forwarding; production proxy IPv6 egress was not
  tested. No production server changes were made to extend coverage.

The branch is ready for merge review with these limits recorded. Publication
should retain these limits and first recheck the locked-tile interaction;
missing OTP/notification/hardware coverage must not be described as passed.

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
