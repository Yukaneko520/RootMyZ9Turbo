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
.\build-timer.cmd        # NDK 29, produces all three binaries
python verify-timer.py   # host-side arithmetic checks + log replay
```

`verify-timer.py` needs no compiler. It pins the KASLR-slide recovery, the
task-cache window and the fake-cred layout guard, and replays every recorded
run in `../timerZ9Turbo-log` to confirm the printed slide still maps
`selinux_state`.

## Changes ported from YuKongA/CVE-2026-98260

The upstream repository added three fixes after this tree was forked. All are
carried here, adapted to the PD2352 profiles.

### Recover from failed plants (`dae5eb0`, PR #2)

Failures used to abort the whole run, and the 15 s burst timeout was measured
in poll iterations (so spray load stretched it). Now:

- A failed plant that never started the target's exec is reaped and retried
  (`res->retry`); only a node that cannot be reaped safely is held.
- Every failure path closes its pipes and joins only the spray threads it
  actually created. Previously a join on an uncreated thread or a leaked pipe
  descriptor stalled the next plant.
- `wait_zombie` uses a 5 s wall-clock deadline.
- Spray helpers exit when the target is gone (`target_gone`) instead of
  spinning on its 50,000 VMAs forever, which leaked helper processes.
- `ensure_pool` needs at least 32 sockets per spray thread, and
  `write_ksu_script` reports a partial write instead of leaving a truncated
  script to be sourced later.
- `SIGPIPE` is ignored so a helper pipe losing its reader cannot kill the run.

This tree additionally stops polling as soon as every spray thread has
finished writing after the free was seen: no later write can claim the page,
so waiting out the remaining timeout only delays the retry.

### Fake cred layout on 6.1 (`35f474a`, PR #5)

- The fake cred is sized from `CRED_REQ` instead of a hardcoded `0xb8`, and
  the SELinux blob offset comes from the profile (`SELINUX_CRED_OFF`).
- 6.1's 4-byte `usage` field puts euid on the rb-erase target, so the euid
  zero write runs only for that layout.
- `fake_layout_supported()` refuses a cred layout the payload cannot
  synthesize instead of writing a malformed cred.
- `task_alloc_size()` accepts the whole `[TASK_ALLOC_BYTES, TASK_ALLOC_MAX]`
  range from the profile, so a vendor-extended task cache is still matched.
- The slab-own denominator is computed from `TIMER_ALLOC`.

### KASLR slide from the ftrace record (`ddea812`, PR #4)

Upstream masks the slide to 32 bits for android15-8 kernels, whose ftrace
record stores `call_site` in only 4 bytes. **An unconditional mask is wrong on
PD2352**: every recorded 6.1.145 run has a slide above 4 GiB
(0x1844e00000 .. 0x2f74000000), so masking misplaced every static address.

The record width is a per-build fact, so it now lives in the profile as
`TIMER_SITE_FIELD_BYTES` (8 on all three 6.1 profiles). `slide_from_site()`
still requires the recovered slide to be 2 MiB aligned and aborts the fake
path otherwise. This matters because a 4-byte-derived garbage record is itself
canonical and 2 MiB aligned, so no runtime heuristic can tell the two shapes
apart; only the build does.

`verify-timer.py` replays all 11 recorded runs and asserts the recovered slide
still reproduces the logged `selinux_state`, and separately proves that a
190 GiB slide survives the 8-byte path instead of being truncated.

## Differences from upstream on purpose

- Upstream selects a profile by exact `uname -r` match across a table. This
  tree keeps one small header per release and builds one binary per profile,
  which is what the app ships.
- Upstream's `late-load` has no `--kmi`; this tree already matched that. The
  app resolves the manager daemon and passes its package name.
- The fake path parks the process to hold the reclaimed cred page, so a run
  may still need a reboot even when every plant succeeded.

## License

MIT for `timer.c`, `target-*.h` and the binaries; see `LICENSE` and `NOTICE`.
