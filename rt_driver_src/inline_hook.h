#ifndef INLINE_HOOK_H
#define INLINE_HOOK_H

#include "kernel.h"
#include <linux/perf_event.h>

/* ================================================================
 * ARM64 内联 Hook
 *   目标点写入 16 字节绝对跳转 stub:
 *     LDR X16, #8 ; BR X16 ; .quad handler
 *   跳板(trampoline) = 被覆盖的原始指令 + 跳回 target+16
 *   调用 trampoline 等价于执行被 hook 点的原始逻辑
 * ================================================================ */

#define HOOK_PATCH_SIZE   16     /* 跳转 stub 长度 */
#define HOOK_SAVE_INSN    4      /* 覆盖 4 条 ARM64 指令 */
#define HOOK_TRAMP_SIZE   (HOOK_SAVE_INSN*4 + HOOK_PATCH_SIZE) /* 32 字节 */

struct inline_hook {
    unsigned long target;          /* 被 hook 的内核函数地址 */
    unsigned long handler;         /* 我们的回调 */
    unsigned long trampoline;      /* 可执行跳板（vmalloc） */
    u32  saved[HOOK_SAVE_INSN];    /* 原始指令备份 */
    bool installed;
    spinlock_t lock;
};

/* 构造 16 字节绝对跳转 stub */
static inline void build_branch_stub(u32 *stub, unsigned long addr)
{
    stub[0] = 0x58000050;              /* LDR X16, #8  */
    stub[1] = 0xD61F0200;              /* BR  X16      */
    *(unsigned long *)&stub[2] = addr; /* .quad addr   */
}

/* 刷新指令缓存（数据缓存写回 + 指令缓存失效） */
static inline void flush_arm64_cache(unsigned long addr, size_t len)
{
    unsigned long end = addr + len;
    unsigned long p;
    for (p = addr & ~(unsigned long)(cache_line_size() - 1); p < end;
         p += cache_line_size()) {
        __asm__ volatile("dc cvau, %0" :: "r"(p) : "memory");
    }
    __asm__ volatile("dsb ish" ::: "memory");
    for (p = addr & ~(unsigned long)(cache_line_size() - 1); p < end;
         p += cache_line_size()) {
        __asm__ volatile("ic ivau, %0" :: "r"(p) : "memory");
    }
    __asm__ volatile("dsb ish; isb" ::: "memory");
}

/* 安装 inline hook，成功后 hook->trampoline 可当作原函数调用 */
static inline int inline_hook_install(struct inline_hook *h,
                                      unsigned long target,
                                      unsigned long handler)
{
    u32 stub[4];
    int ret;

    if (!h || !target || !handler) return -EINVAL;
    if (h->installed) return -EALREADY;

    spin_lock_init(&h->lock);
    spin_lock(&h->lock);

    h->target  = target;
    h->handler = handler;

    /* 1. 分配可执行跳板 */
    h->trampoline = (unsigned long)vmalloc(HOOK_TRAMP_SIZE);
    if (!h->trampoline) { spin_unlock(&h->lock); return -ENOMEM; }
    memset((void *)h->trampoline, 0, HOOK_TRAMP_SIZE);

    /* 2. 备份原始指令 */
    memcpy(h->saved, (void *)target, HOOK_SAVE_INSN * 4);

    /* 3. 跳板 = 原始指令 + 跳回 target+16 */
    memcpy((void *)h->trampoline, (void *)target, HOOK_SAVE_INSN * 4);
    build_branch_stub((u32 *)(h->trampoline + HOOK_SAVE_INSN * 4),
                      target + HOOK_PATCH_SIZE);

    /* 4. 跳板设为可执行（先保证可写以写入内容，再转可执行） */
    if (S.set_memory_rw)
        S.set_memory_rw(h->trampoline, HOOK_TRAMP_SIZE / PAGE_SIZE + 1);
    flush_arm64_cache(h->trampoline, HOOK_TRAMP_SIZE);
    if (S.set_memory_x)
        S.set_memory_x(h->trampoline, HOOK_TRAMP_SIZE / PAGE_SIZE + 1);

    /* 5. 目标点写跳转 stub（走只读 text 安全写入） */
    build_branch_stub(stub, handler);
    ret = patch_text(target, stub, HOOK_PATCH_SIZE);
    if (ret != 0) {
        vfree((void *)h->trampoline);
        h->trampoline = 0;
        spin_unlock(&h->lock);
        pr_err("rt_driver: hook patch_text failed: %d\n", ret);
        return ret;
    }

    h->installed = true;
    spin_unlock(&h->lock);
    pr_info("rt_driver: inline hook 0x%lx -> 0x%lx (tramp 0x%lx)\n",
            target, handler, h->trampoline);
    return 0;
}

/* 卸载 inline hook，恢复原始指令并释放跳板 */
static inline int inline_hook_remove(struct inline_hook *h)
{
    int ret;
    if (!h || !h->installed) return 0;

    spin_lock(&h->lock);
    ret = patch_text(h->target, h->saved, HOOK_SAVE_INSN * 4);
    flush_arm64_cache(h->target, HOOK_PATCH_SIZE);
    if (h->trampoline) {
        vfree((void *)h->trampoline);
        h->trampoline = 0;
    }
    h->installed = false;
    spin_unlock(&h->lock);
    pr_info("rt_driver: inline hook removed @0x%lx\n", h->target);
    return ret;
}

#endif
