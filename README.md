# timer-native

Native PoC for CVE-2026-98260 (posix CPU timer UAF) on the Vivo/iQOO
PD2352 family. Three ARM64 binaries are produced from one source, selected
by `uname -r` at runtime through `target-<release>.h`.

| binary         | kernel                          |
| -------------- | ------------------------------- |
| `timer-6.1.57` | 6.1.57-android14-11 V2352A      |
| `timer-6.1.124`| 6.1.124-android14-11 V2352A     |
| `timer-6.1.145`| 6.1.145-android14-11 V2352GA    |

Build:

```powershell
.\build-timer.cmd        # NDK 29, produces all three binaries and publishes them to the app assets
python verify-timer.py   # host-side checks; replays every recorded run
```

`verify-timer.py` needs no compiler. It pins the slide arithmetic, the task
cache window, the fake-cred fit, the plant count and the retry/cleanup rules,
then replays every recorded run in `../timerZ9Turbo-log` to confirm the printed
slide still maps `selinux_state`.

## What this tree fixes, and why

See [`FIX-NOTES.md`](FIX-NOTES.md) for the evidence behind each item. Short
version:

| Problem in the recorded runs | Fix |
|---|---|
| 4 runs parked before their first plant | the unreadable `panic_on_warn` read (`-1`) is no longer a gate |
| a 9th plant (one more WARN) in every later run | the gated duplicate `panic_on_warn` plant is gone |
| ~15 s of dead time per missed burst | the burst poll stops once the spray has drained |
| orphaned helper processes burning CPU | `target_gone()` + joining only the threads that were created |
| `no child heartbeat` with exit 0 | every child write is checked; EOF is reported as a dead pipe, not as a slow child; a signalled child is named |
| ~15 s of dead time per missed burst | the burst poll stops once the spray has drained |
| orphaned helper processes burning CPU | `target_gone()` + joining only the threads that were created |
| pipes/thread joins on failure paths | every path closes its fds and joins what it created |

### Why `no child heartbeat` needed a protocol fix

`n=0` in `no child heartbeat (n=0)` is `read()` returning **0 = EOF**, not a
timeout.  Every write end of the report pipe was therefore already closed.  The
child's three report writes were `(void)write(...)`, so with `SIGPIPE` ignored a
broken pipe came back as `EPIPE` (a return value nobody looked at) and the child
carried on to a clean `exit 0`.  The parent then reported a missing heartbeat and
the log contained no clue why.

Now:

- `send_report()` checks every write and logs `child ... write failed errno=`.
- The heartbeat is written before `close(3)`, not after.
- The parent distinguishes `child report pipe closed ... (n=0, EOF)` from
  `no child heartbeat within Nms (pipe still open)`.
- A failed wake names whether the reader was already gone.
- `waitpid` reports a signalled child as a signal instead of `status=0`.

The plant sequence in the fake path is down from 9 writes to 7:

```
vr-flags, vr-tagB, sys_exit funcs,      (de-tag)
fake_cred, selinux, fake_uid, fake_euid (endgame)
```

### About `panic_on_warn`

It is not written at all. The WARN that this CVE produces
(`timerqueue_del` on a double-deleted stale node) is raised while the plant's
target is **reaped** — `posix_cpu_timers_exit` from `release_task`. On a kernel
whose `panic_on_warn` is 1 the first plant is therefore already fatal before a
disarm write could land, so the only lever is to spend as few plants as
possible. On PD2352 the sysctl reads `-1` (SELinux denies it), and ten WARNs at
boot without a panic prove the boot value is 0.

## Differences from upstream on purpose

- Upstream selects a profile by exact `uname -r` match across a table. This
  tree keeps one small header per release and builds one binary per profile,
  which is what the app ships.
- Upstream derives the KASLR slide from the ftrace record with a 4-byte mask for
  android15-8 builds. **An unconditional mask is wrong on PD2352**: every
  recorded 6.1.145 slide is above 4 GiB (`0x1844e00000 .. 0x2f74000000`). This
  tree stores the full 8-byte record and does not mask.
- The fake path parks the process to hold the reclaimed cred page, so a run may
  still need a reboot even when every plant succeeded.
- `vr.ko` cannot be removed without unlocking the bootloader. While it is
  loaded any kernel-write exploit has to fight it; the de-tag writes are best
  effort, not a guarantee.

## Modes

```
timer               verify: zero the child's uid/gid -> uid 0 shell
timer shell         interactive root shell (shell domain)
timer fake          fake full-cap cred + SELinux off + KernelSU late-load
timer leak          leak child cred/task only, then exit
timer ids           read-only diagnostics (no UAF)
timer build         print the build tag and profile actually installed
```

## License

MIT for `timer.c`, `target-*.h` and the binaries; see `LICENSE` and `NOTICE`.
