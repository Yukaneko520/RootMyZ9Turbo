# Reading a timer run log

The native backend now writes enough to diagnose a failure **from the log
alone**. `dmesg` is not required: it is lost on reboot and unreadable over adb,
and a panic that followed a burst miss left no trace in the previous runs.

## The one line to read first

```
[dbg] SUMMARY park plants=9 ok=8 miss=1 slab_busy=0 retryable=1 held=2 taint=0x100 taint_warn=1 pid=19258
```

| field | meaning |
|---|---|
| `plants` | total `run_plant` calls |
| `ok` | spray won the page (write landed) |
| `miss` | page was freed but our spray lost the race (`free_seen=1, hit=0`) |
| `slab_busy` | slab never returned to the buddy (`free_seen=0`) |
| `retryable` | plants that will be retried (`slab_shared` + `burst_missed`) |
| `held` | zombies kept alive because reaping was unsafe |
| `taint` | `/proc/sys/kernel/tainted` at exit |
| `taint_warn` | **1 means the kernel issued a WARN during this run** |

`taint_warn=1` is the crucial signal. Bit 8 (`0x100`, `TAINT_WARN`) is set by
`add_taint()` when `WARN_ON` fires — which is exactly what `timerqueue_del`
does when the stale node is erased a second time. Because
`/proc/sys/kernel/tainted` is readable from the shell domain, this is the only
way to prove a WARN happened without dmesg.

## Per-plant markers

```
[dbg] plant-entry taint=0x0 taint_warn=0 held=0
[+] plant1 free_seen=1 burst hit=0 after 15001ms
[dbg] plant1 failure-class=free_seen1_spray_lost
[-] plant1 burst missed; holding zombie, retryable
[dbg] post-plant TAINT CHANGED 0x0 -> 0x100 (new bits 0x100)
[-] stage panic_on_warn attempt=2 failed why=burst_missed elapsed=15123ms
```

- `plant-entry` / `post-plant` bracket every plant with a taint snapshot.
- `TAINT CHANGED` appears **only** when the kernel took a WARN during that
  plant, so it names the plant that caused it.
- `failure-class` separates the two ways a plant can end at `hit=0`:
  - `free_seen1_spray_lost` — the page was freed but another caller took it.
    The stale node now lives in memory we do not control.
  - `free_seen0_slab_busy` — the slab never freed; the node is still intact.
- `why=` on a failed stage is one of:
  `trigger_never_ready`, `victim_not_captured`, `bad_base`,
  `victim_index_missing`, `slab_shared`, `unusable_site0`,
  `fake_cred_spills`, `fake_cred_straddles`, `blob_no_fit`,
  `timer_go_failed`, `no_zombie`, `exec_succeeded`, `burst_missed`.

## Guard around the panic path

```
[ksu] panic_on_warn=-1
[+] stage panic_on_warn done in 1442ms (...)
[dbg] panic_on_warn after write=0
```

The write target is `PANIC_ON_WARN_STATIC + slide`, so a wrong slide would
silently leave the sysctl set and the next `timerqueue_del` WARN would panic.
The backend now re-reads the sysctl and parks instead of continuing if it is
still non-zero.

## Terminal markers

- `[dbg] parking reason=<why>` — the run stopped deliberately.
- `[dbg] SUMMARY done ...` — the run finished normally.
- `[+] Timer helper cleanup: scanned=N matched=M killed=K` — `scanned` proves
  `/proc` was actually enumerated, so `matched=0` cannot be confused with a
  failed scan.

## What to collect if it panics again

Root will not be available during the panic, so the log is the primary
artifact. Before rebooting, if possible:

```sh
adb shell cat /proc/sys/kernel/tainted      # 0x100 => WARN happened
adb shell cat /proc/sys/kernel/panic_on_warn
```

After reboot the only surviving evidence is the app's exported log directory
(`Z9tb/.../timerz9turbo-timer-0.log.txt`). The `SUMMARY` and `TAINT CHANGED`
lines in that file are what identify the offending plant.
