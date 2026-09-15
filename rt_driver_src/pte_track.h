#ifndef PTE_TRACK_H
#define PTE_TRACK_H

#include "kernel.h"
#include "comm.h"

/* ================================================================
 * PTE 页表追踪（驱动级）
 *   清目标页 PTE present 位 -> 访问触发 translation fault
 *   kprobe 挂 do_page_fault：改 V3/V4/V5、恢复 present、开单步
 *   kprobe 挂 do_debug_exception：单步后重新清 present
 * 全部内核符号走动态解析 + CFI 绕过，带完整回滚保护
 * ================================================================ */

struct pte_state {
    bool              installed;
    bool              paused;
    int               pid;
    unsigned long     target_addr;
    u64               hits;
    struct mm_struct *mm;
    spinlock_t        lock;
    u64               reg_val[3][2];
    bool              reg_set;
    bool              kp_fault_ok;
    bool              kp_debug_ok;
};

static struct pte_state g_state;

static int fault_pre_handler(struct kprobe *p, struct pt_regs *regs);
static int debug_pre_handler(struct kprobe *p, struct pt_regs *regs);

static struct kprobe kp_fault = {
    .symbol_name = "do_page_fault",
    .pre_handler = fault_pre_handler,
};
static struct kprobe kp_debug = {
    .symbol_name = "do_debug_exception",
    .pre_handler = debug_pre_handler,
};

/* ---- 页表遍历（动态符号 + 崩溃保护） ---- */
static int pte_walk(struct mm_struct *mm, unsigned long addr,
                    pte_t **ptep, spinlock_t **ptlp)
{
    pgd_t *pgd; p4d_t *p4d; pud_t *pud; pmd_t *pmd;

    if (!mm || !ptep || !ptlp) return -EINVAL;
    *ptep = NULL; *ptlp = NULL;

    pgd = pgd_offset(mm, addr);
    if (!pgd || pgd_none(*pgd) || pgd_bad(*pgd)) return -EFAULT;
    p4d = p4d_offset(pgd, addr);
    if (p4d_none(*p4d) || p4d_bad(*p4d)) return -EFAULT;
    pud = pud_offset(p4d, addr);
    if (pud_none(*pud) || pud_bad(*pud)) return -EFAULT;
    pmd = pmd_offset(pud, addr);
    if (pmd_none(*pmd) || pmd_bad(*pmd)) return -EFAULT;
    if (!S.pte_offset_map_lock) return -ENOSYS;

    *ptep = (pte_t *)CFI_CALL4(S.pte_offset_map_lock, mm, pmd, addr, ptlp);
    if (!*ptep) return -EFAULT;
    return 0;
}

static void pte_done(pte_t *ptep, spinlock_t *ptlp)
{
    if (ptep && S.pte_unmap_unlock)
        CFI_VOID2(S.pte_unmap_unlock, ptep, ptlp);
}

static inline void pte_clear_present(pte_t *ptep)
{
    set_pte(ptep, __pte(pte_val(*ptep) & ~PTE_PRESENT));
}
static inline void pte_set_present(pte_t *ptep)
{
    set_pte(ptep, __pte(pte_val(*ptep) | PTE_PRESENT));
}

/* ---- 改 V3/V4/V5 ---- */
static void modify_target_regs(void)
{
    struct user_fpsimd_state *st = &current->thread.uw.fpsimd_state;
    u64 *v = (u64 *)st->vregs;
    if (!g_state.reg_set) {
        v[6]=v[7]=v[8]=v[9]=v[10]=v[11]=0;
    } else {
        v[6]=g_state.reg_val[0][0]; v[7]=g_state.reg_val[0][1];
        v[8]=g_state.reg_val[1][0]; v[9]=g_state.reg_val[1][1];
        v[10]=g_state.reg_val[2][0]; v[11]=g_state.reg_val[2][1];
    }
    set_thread_flag(TIF_FOREIGN_FPSTATE);
}

/* ---- do_page_fault 回调 ---- */
static int fault_pre_handler(struct kprobe *p, struct pt_regs *regs)
{
    unsigned long far;
    struct pt_regs *tgt;
    pte_t *ptep = NULL;
    spinlock_t *ptlp = NULL;

    if (!g_state.installed || g_state.paused) return 0;

    far = regs->regs[0];
    if ((far & PAGE_MASK) != (g_state.target_addr & PAGE_MASK)) return 0;
    if (current->pid != g_state.pid) return 0;

    tgt = (struct pt_regs *)regs->regs[2];
    if (!tgt) return 0;

    spin_lock(&g_state.lock);

    modify_target_regs();

    if (g_state.mm &&
        pte_walk(g_state.mm, g_state.target_addr, &ptep, &ptlp) == 0) {
        pte_set_present(ptep);
        pte_done(ptep, ptlp);
    }
    tgt->pstate |= PSR_SS_BIT;
    g_state.hits++;

    spin_unlock(&g_state.lock);
    return 0;
}

/* ---- do_debug_exception 回调（单步后重新无效化） ---- */
static int debug_pre_handler(struct kprobe *p, struct pt_regs *regs)
{
    unsigned long esr = regs->regs[1];
    struct pt_regs *tgt;
    pte_t *ptep = NULL;
    spinlock_t *ptlp = NULL;

    if (!g_state.installed || g_state.paused) return 0;
    if ((esr >> 26) != 0x33) return 0;
    if (current->pid != g_state.pid) return 0;

    tgt = (struct pt_regs *)regs->regs[2];
    if (!tgt) return 0;

    spin_lock(&g_state.lock);
    tgt->pstate &= ~PSR_SS_BIT;
    if (g_state.mm &&
        pte_walk(g_state.mm, g_state.target_addr, &ptep, &ptlp) == 0) {
        pte_clear_present(ptep);
        pte_done(ptep, ptlp);
    }
    spin_unlock(&g_state.lock);
    return 0;
}

/* ---- 安装 ---- */
static int pte_install(int pid, unsigned long target_addr)
{
    struct pid *p = NULL;
    struct task_struct *task = NULL;
    struct mm_struct *mm = NULL;
    pte_t *ptep = NULL;
    spinlock_t *ptlp = NULL;
    int ret;

    if (g_state.installed) return -EALREADY;
    if (!S.find_get_pid || !S.get_pid_task || !S.get_task_mm)
        return -ENOSYS;

    p = (struct pid *)CFI_CALL1(S.find_get_pid, pid);
    if (!p) return -ESRCH;
    task = (struct task_struct *)CFI_CALL2(S.get_pid_task, p, PIDTYPE_PID);
    CFI_VOID1(S.put_pid, p);
    if (!task) return -ESRCH;

    mm = (struct mm_struct *)CFI_CALL1(S.get_task_mm, task);
    CFI_VOID1(S.put_task_struct, task);
    if (!mm) return -ESRCH;

    ret = pte_walk(mm, target_addr, &ptep, &ptlp);
    if (ret != 0) { CFI_VOID1(S.mmput, mm); return ret; }
    pte_clear_present(ptep);
    pte_done(ptep, ptlp);

    ret = register_kprobe(&kp_fault);
    if (ret != 0) goto fail_restore;
    g_state.kp_fault_ok = true;

    ret = register_kprobe(&kp_debug);
    if (ret != 0) goto fail_kp1;
    g_state.kp_debug_ok = true;

    spin_lock_init(&g_state.lock);
    g_state.installed   = true;
    g_state.paused      = true;
    g_state.pid         = pid;
    g_state.target_addr = target_addr;
    g_state.hits        = 0;
    g_state.mm          = mm;

    pr_info("rt_driver: PTE installed pid=%d addr=0x%lx\n", pid, target_addr);
    return 0;

fail_kp1:
    unregister_kprobe(&kp_fault);
    g_state.kp_fault_ok = false;
fail_restore:
    if (pte_walk(mm, target_addr, &ptep, &ptlp) == 0) {
        pte_set_present(ptep);
        pte_done(ptep, ptlp);
    }
    CFI_VOID1(S.mmput, mm);
    pr_err("rt_driver: PTE install failed: %d\n", ret);
    return ret;
}

/* ---- 移除（完整清理） ---- */
static void pte_remove(void)
{
    pte_t *ptep = NULL;
    spinlock_t *ptlp = NULL;

    if (!g_state.installed) return;

    g_state.installed = false;  /* 先关，防止回调再进 */

    if (g_state.kp_debug_ok) {
        unregister_kprobe(&kp_debug);
        g_state.kp_debug_ok = false;
    }
    if (g_state.kp_fault_ok) {
        unregister_kprobe(&kp_fault);
        g_state.kp_fault_ok = false;
    }

    if (g_state.mm) {
        if (pte_walk(g_state.mm, g_state.target_addr, &ptep, &ptlp) == 0) {
            pte_set_present(ptep);
            pte_done(ptep, ptlp);
        }
        CFI_VOID1(S.mmput, g_state.mm);
        g_state.mm = NULL;
    }
    pr_info("rt_driver: PTE removed hits=%llu\n", g_state.hits);
}

static inline int pte_set_regs(u64 *vals)
{
    int i;
    spin_lock(&g_state.lock);
    for (i = 0; i < 3; i++) {
        g_state.reg_val[i][0] = vals[i*2];
        g_state.reg_val[i][1] = vals[i*2+1];
    }
    g_state.reg_set = true;
    spin_unlock(&g_state.lock);
    return 0;
}

#endif
