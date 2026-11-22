# Fix notes — stability pass on the PD2352 timer backend

Baseline: `c974203` (the build before the over-engineered `506ae11`).
Every claim below is tied to a recorded run in `../timerZ9Turbo-log`.

## What actually failed (38 recorded runs)

| Symptom | Runs | Cause |
|---|---|---|
| Park before any work | `010213` `010419` `010615` `010820` | `read_panic_on_warn()` returns `-1` when SELinux denies the read, and `if (read_panic_on_warn() != 0 && stage_write(...))` treats `-1` as "still set". |
| A 9th plant (one more WARN) in every later run | from `011900` on | the same `!= 0` gate always fired, so the second `panic_on_warn` plant ran every time. |
| `euid=-118`, `uid=-119`, `2000/2000` after a "done" write | `223620` `011900` `023944` `002036` `012408` `013001` | a plant can win the page and still miss the erase; the two credential repairs are then silently lost. Inherent to the design, but they are retried now. |
| 7-8 plants all OK, then `no child heartbeat`, child exits 0 | `013740` `022844` `023731` `134538` `140118` | **not** helper starvation (an earlier claim in this file, now withdrawn). `n=0` is EOF: every write end of the report pipe was already closed. Every child write was `(void)write(...)`, and with `SIGPIPE` ignored a broken pipe returns EPIPE instead of killing the child, so the child ran to completion and exited 0 while the parent saw nothing. The pipe is now checked and both sides name the errno. |
| ~15 s of dead time per missed burst | 16 of 273 recorded bursts, all `15001..15497 ms` | the poll keeps waiting after every spray thread finished writing; no further allocation of ours is possible then. |
| Panics | 6/38 | each plant leaves one stale node and therefore one `timerqueue_del` WARN. Fewer plants = fewer WARNs = fewer chances to panic. One panic (`023443`) happened before any plant, so a kernel-side actor (`vr.ko`) is also involved. |

## Changes

The trigger, victim selection and spray geometry are untouched. Only:

1. **`panic_on_warn` is never written.** The WARN is raised at reap time
   (`posix_cpu_timers_exit <- release_task`), so on `panic_on_warn=1` the first
   plant is already fatal before a disarm write could land. The sysctl reads
   `-1` here and ten boot WARNs prove the boot value is 0. Removing the write
   also removes the gate that parked four runs.
2. **Retry only when it is safe** (ported from upstream `dae5eb0`): a plant that
   never started the target's exec sets `retry`; a burst miss holds its zombie
   and may retry; a plant that leaves an uncontrolled node does not.
3. **All pipe/thread cleanup on every path**: fds initialised to `-1`,
   `close_pipe`, `close_timer_go`, join only created threads, `SIGPIPE` ignored.
4. **Helpers exit when their target dies** (`target_gone`), and spray threads
   exit when the run is cancelled.  This fixes the leftover CPU burners; it
   does **not** fix the missing child heartbeat (see the table above — that is
   a broken report pipe, not starvation).
5. **One 30 s deadline** covers the heartbeat and the report instead of a 5 s
   probe that discarded the pipe and then waited anyway.
6. **The burst poll stops when the spray drains**, so a miss costs ~200 ms
   instead of 15 s.
7. **6.1 fake-cred layout from the profile** (ported from upstream `35f474a`):
   `CRED_REQ`-sized fit check, `SELINUX_CRED_OFF`, `task_alloc_size()` window,
   slab-own denominator from `TIMER_ALLOC`, `fake_layout_supported()` guard.
8. **`write_ksu_script()` reports a partial write**; `ensure_pool()` fails early.
9. Removed the previous AI pass' unused machinery: taint polling, `SUMMARY`
   counters, plant budget, `why=` taxonomy, `TIMER_SITE_FIELD_BYTES` /
   `slide_from_site`, straddle and slab-own gates, and the reverse-engineering
   histogram dumps.

Net effect on the panic surface: **9 plants per fake run became 7**.

## Deliberately not done

- No change to when the spray starts or to the victim index. The timing
  experiments in `506ae11` were never verified on device and correlate with
  panics.
- No new kernel writes. The panic budget only goes down.
- `vr.ko` cannot be removed without unlocking the bootloader; the residual panic
  risk from a prerelease UAF is stated as-is rather than papered over.
