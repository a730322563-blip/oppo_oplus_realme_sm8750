#include "kernel.h"
#include "comm.h"
#include "inline_hook.h"
#include "hw_breakpoint.h"
#include "pte_track.h"
#include "module_utils.h"
#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/cache.h>

/* ================= 全局符号 ================= */
kallsyms_lookup_name_t g_kln = NULL;
struct dyn_syms S;
u32 g_sym_mask = 0;

/* ================================================================
 * 只读 text 安全写入
 * ================================================================ */
int patch_text(unsigned long dst, const void *src, size_t len)
{
    unsigned long page = dst & PAGE_MASK;
    int pages = ((dst + len - page) + PAGE_SIZE - 1) / PAGE_SIZE;
    bool used_setmem = false;
    int ret = 0;

    if (!dst || !src || !len) return -EINVAL;

    /* 路径A: set_memory_rw */
    if (S.set_memory_rw) {
        ret = S.set_memory_rw(page, pages);
        if (ret == 0) used_setmem = true;
    }
    /* 路径B: 手改页表 */
    if (!used_setmem) {
        ret = kernel_text_unprotect(page);
        if (ret) return ret;
    }

    memcpy((void *)dst, src, len);

    /* 刷指令缓存 */
    flush_arm64_cache(dst, len);

    /* 恢复只读/可执行 */
    if (used_setmem) {
        if (S.set_memory_ro) S.set_memory_ro(page, pages);
        if (S.set_memory_x)  S.set_memory_x(page, pages);
    } else {
        kernel_text_reprotect(page);
    }
    return 0;
}

int patch_insn(unsigned long addr, u32 insn)
{
    return patch_text(addr, &insn, sizeof(u32));
}

/* ================================================================
 * 符号解析（路径A：kprobe 拿 kallsyms_lookup_name）
 * ================================================================ */
static int obtain_kallsyms(void)
{
    struct kprobe kp = { .symbol_name = "kallsyms_lookup_name" };
    int ret = register_kprobe(&kp);
    if (ret < 0) return ret;
    g_kln = (kallsyms_lookup_name_t)kp.addr;
    unregister_kprobe(&kp);
    return g_kln ? 0 : -ENOENT;
}

#define TRY_RESOLVE(field, sym, bit) do {                          \
    S.field = (void *)g_kln(sym);                                  \
    if (S.field) g_sym_mask |= (bit);                              \
    else pr_warn("rt_driver: symbol %s not found\n", sym);         \
} while (0)

int sym_resolve_all(void)
{
    if (!g_kln) return -ENODEV;
    memset(&S, 0, sizeof(S));

    TRY_RESOLVE(find_get_pid,        "find_get_pid",        SYM_FIND_GET_PID);
    TRY_RESOLVE(get_pid_task,        "get_pid_task",        SYM_GET_PID_TASK);
    TRY_RESOLVE(put_pid,             "put_pid",             SYM_PUT_PID);
    TRY_RESOLVE(get_task_mm,         "get_task_mm",         SYM_GET_TASK_MM);
    TRY_RESOLVE(mmput,               "mmput",               SYM_MMPUT);
    TRY_RESOLVE(put_task_struct,     "put_task_struct",     SYM_PUT_TASK_STRUCT);
    TRY_RESOLVE(pte_offset_map_lock, "pte_offset_map_lock", SYM_PTE_OFFSET_MAP_LOCK);
    TRY_RESOLVE(pte_unmap_unlock,    "pte_unmap_unlock",    SYM_PTE_UNMAP_UNLOCK);
    TRY_RESOLVE(set_memory_rw,       "set_memory_rw",       SYM_SET_MEMORY_RW);
    TRY_RESOLVE(set_memory_ro,       "set_memory_ro",       SYM_SET_MEMORY_RO);
    TRY_RESOLVE(set_memory_x,        "set_memory_x",        SYM_SET_MEMORY_X);
    TRY_RESOLVE(register_user_hw_breakpoint_ptr,
                 "register_user_hw_breakpoint", SYM_REG_USER_HWBP);
    TRY_RESOLVE(unregister_hw_breakpoint_ptr,
                 "unregister_hw_breakpoint", SYM_UNREG_HWBP);

    /* PTE 必需符号缺失则失败 */
    if (!(g_sym_mask & SYM_FIND_GET_PID) ||
        !(g_sym_mask & SYM_GET_PID_TASK) ||
        !(g_sym_mask & SYM_GET_TASK_MM) ||
        !(g_sym_mask & SYM_PTE_OFFSET_MAP_LOCK)) {
        pr_err("rt_driver: essential symbols missing mask=0x%x\n", g_sym_mask);
        return -ENOENT;
    }
    pr_info("rt_driver: symbols resolved mask=0x%x\n", g_sym_mask);
    return 0;
}

/* 路径B：用户态注入符号地址 */
int sym_inject(const char *name, unsigned long addr)
{
    struct { const char *n; size_t off; } map[] = {
        {"find_get_pid",        offsetof(struct dyn_syms, find_get_pid)},
        {"get_pid_task",        offsetof(struct dyn_syms, get_pid_task)},
        {"put_pid",             offsetof(struct dyn_syms, put_pid)},
        {"get_task_mm",         offsetof(struct dyn_syms, get_task_mm)},
        {"mmput",               offsetof(struct dyn_syms, mmput)},
        {"put_task_struct",     offsetof(struct dyn_syms, put_task_struct)},
        {"pte_offset_map_lock", offsetof(struct dyn_syms, pte_offset_map_lock)},
        {"pte_unmap_unlock",    offsetof(struct dyn_syms, pte_unmap_unlock)},
        {"set_memory_rw",       offsetof(struct dyn_syms, set_memory_rw)},
        {"set_memory_ro",       offsetof(struct dyn_syms, set_memory_ro)},
        {"set_memory_x",        offsetof(struct dyn_syms, set_memory_x)},
        {NULL, 0},
    };
    int i;
    for (i = 0; map[i].n; i++) {
        if (strcmp(map[i].n, name) == 0) {
            *(unsigned long *)((char *)&S + map[i].off) = addr;
            pr_info("rt_driver: inject %s=0x%lx\n", name, addr);
            return 0;
        }
    }
    return -ENOENT;
}

/* ================================================================
 * ioctl
 * ================================================================ */
static long rt_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    switch (cmd) {
    case PTE_INSTALL: {
        struct pte_install_args a;
        if (copy_from_user(&a, (void __user *)arg, sizeof(a))) return -EFAULT;
        return pte_install(a.pid, a.target_addr);
    }
    case PTE_SET_TARGET: {
        u64 addr;
        if (get_user(addr, (u64 __user *)arg)) return -EFAULT;
        g_state.target_addr = addr;
        return 0;
    }
    case PTE_REMOVE:
        pte_remove();
        return 0;
    case PTE_GET_HITS:
        return put_user(g_state.hits, (u64 __user *)arg);
    case PTE_SET_PAUSE: {
        u32 p;
        if (get_user(p, (u32 __user *)arg)) return -EFAULT;
        g_state.paused = p ? true : false;
        return 0;
    }
    case PTE_SET_REGS: {
        u64 vals[6];
        if (copy_from_user(vals, (void __user *)arg, sizeof(vals))) return -EFAULT;
        return pte_set_regs(vals);
    }
    case HWBP_INSTALL: {
        struct hwbp_install_args a;
        if (copy_from_user(&a, (void __user *)arg, sizeof(a))) return -EFAULT;
        return hwbp_install(a.pid, a.addr, a.bp_type);
    }
    case HWBP_REMOVE:
        hwbp_remove();
        return 0;
    case HWBP_GET_HITS:
        return put_user(g_hwbp.hits, (u64 __user *)arg);
    case SYM_INJECT: {
        struct sym_inject_args a;
        if (copy_from_user(&a, (void __user *)arg, sizeof(a))) return -EFAULT;
        a.name[sizeof(a.name)-1] = 0;
        return sym_inject(a.name, a.addr);
    }
    case DRIVER_STATUS: {
        struct driver_status st;
        memset(&st, 0, sizeof(st));
        st.sym_resolved = g_sym_mask;
        st.pte_active   = g_state.installed;
        st.hwbp_active  = g_hwbp.installed;
        st.hidden       = g_hide.hidden;
        st.pte_hits     = g_state.hits;
        if (copy_to_user((void __user *)arg, &st, sizeof(st))) return -EFAULT;
        return 0;
    }
    default:
        return -ENOTTY;
    }
}

static int rt_open(struct inode *i, struct file *f)  { return 0; }
static int rt_release(struct inode *i, struct file *f) { return 0; }

static const struct file_operations rt_fops = {
    .owner          = THIS_MODULE,
    .open           = rt_open,
    .release        = rt_release,
    .unlocked_ioctl = rt_ioctl,
    .compat_ioctl   = rt_ioctl,   /* 32 位进程兼容 */
};

static struct miscdevice rt_misc = {
    .minor = MISC_DYNAMIC_MINOR,
    .name  = DEVICE_NAME,
    .fops  = &rt_fops,
};

/* ================================================================
 * init / exit —— 严格按顺序，失败逐级回滚
 * ================================================================ */
static int __init rt_init(void)
{
    int ret;

    memset(&g_state, 0, sizeof(g_state));
    memset(&g_hwbp, 0, sizeof(g_hwbp));
    memset(&g_hide, 0, sizeof(g_hide));

    /* 1. kallsyms */
    ret = obtain_kallsyms();
    if (ret) {
        pr_err("rt_driver: obtain kallsyms failed: %d (need loader inject)\n", ret);
        /* 不直接失败：允许外部通过 SYM_INJECT 注入后再使用 */
    }

    /* 2. 解析符号 */
    if (g_kln) {
        ret = sym_resolve_all();
        if (ret) pr_warn("rt_driver: partial symbol resolve, mask=0x%x\n", g_sym_mask);
    }

    /* 3. 注册设备 */
    ret = misc_register(&rt_misc);
    if (ret) {
        pr_err("rt_driver: misc_register failed: %d\n", ret);
        return ret;
    }

    /* 4. 抑制运行时安全检查（加载时校验需外部加载器绕过） */
    suppress_security_check();

    /* 5. 隐藏模块（设备可用之后再隐藏） */
    module_hide();

    pr_info("rt_driver v2.0 ready /dev/%s mask=0x%x\n", DEVICE_NAME, g_sym_mask);
    return 0;
}

static void __exit rt_exit(void)
{
    /* 逆序清理 */
    pte_remove();
    hwbp_remove();
    module_unhide();
    misc_deregister(&rt_misc);
    pr_info("rt_driver: unloaded clean\n");
}

module_init(rt_init);
module_exit(rt_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("rt");
MODULE_DESCRIPTION("PTE/HWBP track driver - CFI bypass, dyn syms, hidden");
MODULE_VERSION("2.0");
