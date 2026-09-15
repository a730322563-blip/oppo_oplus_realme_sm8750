#ifndef HW_BREAKPOINT_H
#define HW_BREAKPOINT_H

#include "kernel.h"
#include <linux/hw_breakpoint.h>
#include <linux/perf_event.h>

/* ================================================================
 * 硬件断点（perf_event 框架，符号动态解析）
 *   - 执行断点命中 CalShoot 入口时回调
 *   - 回调里改写 V3/V4/V5 浮点寄存器
 *   - 作为 PTE 之外的备用追踪后端
 * ================================================================ */

struct hwbp_ctx {
    struct perf_event *bp;
    struct perf_event_attr attr;
    bool installed;
    int  target_pid;
    unsigned long target_addr;
    spinlock_t lock;
    u64  hits;
    /* 要写入的 V3/V4/V5（每个 16 字节 = 2×u64） */
    u64  reg_val[3][2];
    bool reg_set;
    bool paused;
};

static struct hwbp_ctx g_hwbp;

/* 断点命中回调：改浮点寄存器 */
static void hwbp_handler(struct perf_event *bp,
                         struct perf_sample_data *data,
                         struct pt_regs *regs)
{
    struct user_fpsimd_state *st;

    if (!g_hwbp.installed || g_hwbp.paused)
        return;

    st = &current->thread.uw.fpsimd_state;
    {
        u64 *vregs = (u64 *)st->vregs;
        if (!g_hwbp.reg_set) {
            vregs[6] = vregs[7] = 0;
            vregs[8] = vregs[9] = 0;
            vregs[10] = vregs[11] = 0;
        } else {
            vregs[6]  = g_hwbp.reg_val[0][0];
            vregs[7]  = g_hwbp.reg_val[0][1];
            vregs[8]  = g_hwbp.reg_val[1][0];
            vregs[9]  = g_hwbp.reg_val[1][1];
            vregs[10] = g_hwbp.reg_val[2][0];
            vregs[11] = g_hwbp.reg_val[2][1];
        }
        set_thread_flag(TIF_FOREIGN_FPSTATE);
    }
    g_hwbp.hits++;
}

static inline int hwbp_install(int pid, unsigned long addr, u32 bp_type)
{
    int ret;
    struct pid *pidp = NULL;
    struct task_struct *tsk = NULL;

    if (g_hwbp.installed) return -EALREADY;
    if (!S.register_user_hw_breakpoint_ptr) {
        pr_err("rt_driver: hwbp symbol missing\n");
        return -ENOSYS;
    }

    /* 找到目标进程 task_struct */
    if (S.find_get_pid && S.get_pid_task) {
        pidp = (struct pid *)CFI_CALL1(S.find_get_pid, pid);
        if (pidp) {
            tsk = (struct task_struct *)CFI_CALL2(S.get_pid_task, pidp, PIDTYPE_PID);
            CFI_VOID1(S.put_pid, pidp);
        }
    }

    spin_lock_init(&g_hwbp.lock);
    memset(&g_hwbp.attr, 0, sizeof(g_hwbp.attr));

    hw_breakpoint_init(&g_hwbp.attr);
    g_hwbp.attr.bp_addr = addr;
    switch (bp_type) {
    case 1:  g_hwbp.attr.bp_type = HW_BREAKPOINT_R;  break;
    case 2:  g_hwbp.attr.bp_type = HW_BREAKPOINT_W;  break;
    case 3:  g_hwbp.attr.bp_type = HW_BREAKPOINT_RW; break;
    default: g_hwbp.attr.bp_type = HW_BREAKPOINT_X;  break;
    }
    g_hwbp.attr.bp_len = HW_BREAKPOINT_LEN_4;
    g_hwbp.target_pid  = pid;
    g_hwbp.target_addr = addr;
    g_hwbp.hits = 0;
    g_hwbp.paused = true;

    g_hwbp.bp = (struct perf_event *)CFI_CALL4(
        S.register_user_hw_breakpoint_ptr,
        &g_hwbp.attr, hwbp_handler, NULL, tsk);
    if (IS_ERR(g_hwbp.bp)) {
        ret = (int)PTR_ERR(g_hwbp.bp);
        g_hwbp.bp = NULL;
        if (tsk && S.put_task_struct) CFI_VOID1(S.put_task_struct, tsk);
        pr_err("rt_driver: register hwbp failed: %d\n", ret);
        return ret;
    }

    ret = perf_event_enable(g_hwbp.bp);
    if (ret) {
        CFI_VOID1(S.unregister_hw_breakpoint_ptr, g_hwbp.bp);
        g_hwbp.bp = NULL;
        if (tsk && S.put_task_struct) CFI_VOID1(S.put_task_struct, tsk);
        return ret;
    }

    g_hwbp.installed = true;
    pr_info("rt_driver: hwbp installed pid=%d addr=0x%lx type=%u\n",
            pid, addr, bp_type);
    return 0;
}

static inline void hwbp_remove(void)
{
    if (!g_hwbp.installed) return;
    if (g_hwbp.bp) {
        perf_event_disable(g_hwbp.bp);
        CFI_VOID1(S.unregister_hw_breakpoint_ptr, g_hwbp.bp);
        g_hwbp.bp = NULL;
    }
    g_hwbp.installed = false;
    pr_info("rt_driver: hwbp removed, hits=%llu\n", g_hwbp.hits);
}

static inline void hwbp_set_regs(u64 *vals)
{
    int i;
    for (i = 0; i < 3; i++) {
        g_hwbp.reg_val[i][0] = vals[i*2];
        g_hwbp.reg_val[i][1] = vals[i*2+1];
    }
    g_hwbp.reg_set = true;
}

#endif
