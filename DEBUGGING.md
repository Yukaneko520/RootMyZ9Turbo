# Reading a timer run log

The backend writes enough to diagnose a failure **from the log alone**; `dmesg`
is not required because it is lost on reboot and unreadable over adb.

## The lines to read first

```
[+] pid=14171 cpu=2 nice=-20
[ids] page_alloc=272 page_free=270 pairs=4
[base] made=512 best=0xffffff7f80000000 count=487
[cred] attempt=0 child=14206 R=0xffffff8935a71a80 ... task_recs=1
[+] spray pool=2048 sockets, 256 per thread
[+] vr de-tag: task=... (flags -> tagB -> tp)
[+] stage fake_cred target=... mode=fake attempt=1
[+] plant1 target=... zombie code=2 status=9
[+] plant1 free_seen=1 burst hit=1 after 428ms
[+] plant1 reaped status=0x9
[+] child heartbeat: wake received
[+] child report uid=0 euid=0 ...
[+] Timer helper cleanup: scanned=1081 matched=8 killed=8
```

## Per-plant fields

| field | meaning |
|---|---|
| `zombie code=2 status=9` | the target was SIGKILLed by the killer helper, as intended |
| `zombie code=1 status=NN` | the exec happened instead; no stale node, the plant retries |
| `free_seen=1` | the victim slab returned to the buddy list |
| `free_seen=0` | somebody else still held a timer in that slab |
| `burst hit=1` | one of our spray threads took the page, so the node is ours |
| `burst hit=0` | the page went to a foreign caller; the plant holds its zombie and retries |
| `reaped status=0x9` | the plant completed and the node is controlled |
| `slab_own=N/M` | how many of the block's timers are ours (`M = 0x2000 / TIMER_ALLOC`) |

A `free_seen=0` plant that still reports `hit=1` is normal on this device: the
page can be reclaimed before the free record is drained.

## Where a run stops

| last line | meaning |
|---|---|
| `trigger never ready; retryable` | the target's exec thread never armed; nothing was planted |
| `victim not captured` | the timers were not in the trace buffer; retried |
| `bad base` | the linear-map vote failed; retried |
| `timer go failed` | the go byte never reached the target; reaped and retried |
| `no zombie; reaping and retrying` | the target never reached its exec; reaped and retried |
| `exec succeeded; retryable` | the target ran the binary instead of being killed; reaped |
| `burst missed; holding zombie, retryable` | the page went elsewhere; the zombie is kept, then a new plant is drawn |
| `not retryable` | the failed attempt left a node we do not control; the run stops |
| `no KASLR slide` | the calibration site was unusable, so no static address may be written |

## Terminal markers

- `[!] <reason> -- parking without reap (zombie held)` — the run stopped
  deliberately and the process stays parked to hold the reclaimed page. Reboot.
- `[+] done` — a non-fake run finished and everything was reaped.
- `[+] Timer helper cleanup: scanned=N matched=M killed=K` — `scanned` proves
  `/proc` was really enumerated, so `matched=0` cannot be a failed scan.

## The child never reported

`n=0` is not a timeout.  It is `read()` returning 0, i.e. **EOF**: every write
end of the report pipe is closed, so no byte can ever arrive.

| log line | meaning |
|---|---|
| `[+] child report pipe closed before the heartbeat (n=0, EOF)` | the pipe was already dead; the child could not have written anything |
| `[!] no child heartbeat within Nms (pipe still open)` | a real timeout; the child is alive but slow or blocked |
| `[-] child ... write failed ret= errno=` | the child reached the write and it failed (`EPIPE` = no reader) |
| `[!] child wake write failed ... reader already gone` | the parent could not wake the child at all |
| `[!] child killed by signal N (...)`, | the child died from a signal instead of exiting |
| `[+] child exit status=N` | a real exit code (only printed when `WIFEXITED`) |

A child that exits 0 while the parent saw no heartbeat means the child kept
running after a failed write, because `SIGPIPE` is ignored and the old code did
not check the return value.  Every write is checked now.

## What to collect if it panics again

Root will not be available during the panic, so the exported app log is the
primary artifact. Before rebooting, if possible:

```sh
adb shell cat /proc/sys/kernel/tainted      # bit 0x200 => a WARN happened
adb shell cat /proc/sys/kernel/panic_on_warn
```

Note that a stale-node WARN is raised while the plant's target is reaped, so a
kernel with `panic_on_warn=1` would lose the run at the first plant regardless
of any userspace disarm attempt. The recorded panics include one (`023443`) that
died before the first plant, which points at `vr.ko` and cannot be fixed from
userspace.
