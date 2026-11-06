# TimerZ9Turbo

Android app for the Timer backend on Vivo/iQOO PD2352/V2352 devices. Requires
Shizuku running as shell (uid 2000) and an installed SU manager. The app ships
ARM64 Timer binaries for the existing 6.1.124/6.1.145 kernel mapping.

Features: manager selection, safemode, Timer execution/diagnostics, log export,
and About. Kernel profile editing, offsets extraction and OTA parsing are not
part of this app.

## Build and verify

```powershell
.\gradlew.bat :app:testDebugUnitTest :app:lintDebug :app:assembleRelease --no-configuration-cache
```

Uses the existing Android SDK configuration in ignored `local.properties` and
JDK 25 toolchain. APKs are under `build/app/outputs/apk/release/`.

## Runtime

- `TimerViewModel` and `TimerRepository` coordinate the app through Shizuku.
- `TimerUserService` stages the selected Timer asset and resolves ksud.
- A root manager must be selected explicitly; an unavailable selection is not
  replaced automatically by a different installed manager.
  The native script also requires the app-written `su_manager_pkg` and
  `ksud_path`; it has no default package or daemon-discovery fallback.
- The picker only checks for `libksud.so` by filename. Use Show all apps for a
  manager with a renamed payload; binary inspection happens only when running
  the selected manager.
- `KsudLibrary` prefers `libksud.so`; otherwise it requires one matching
  ARM64 ELF payload before copying it to `/data/local/tmp/ksud`.
- The temporary ksud is removed after each run, including failures/timeouts.
  The native script waits for the payload's `late-load` processes to finish
  before reporting the loaded result, because late-load may daemonize.
  Long-lived subcommands such as `sulogd` do not block completion or cleanup.
- The credential holder's normal parking message does not end log monitoring;
  the detached ksud worker may still be finishing at that point.
- Native helpers carry a `tzh-<owner PID>` name. When the run parks or finishes,
  it sends SIGSTOP only to its own helpers, retaining their mappings while
  preventing leftover helper loops from using CPU. The credential holder stays
  alive. Existing helpers from older binaries are not changed by this update.
- Executables are installed by temporary-file rename. Manager/debug preferences
  retain their existing storage key; existing saved user documents are untouched.
- Build 6 uses Timer-only AIDL and a new service component, replacing ignored
  CPU/profile/force-attack arguments and the obsolete status callback.

Native source is maintained separately at `../timer-native`. The packaged
binaries include the ksud completion wait; kernel offsets are unchanged.
Content detection and host tests do not validate an on-device exploit run.

The UI derives from GhostLock; upstream attribution and license links remain
in About. See [changelog](docs/project-changelog.md).
