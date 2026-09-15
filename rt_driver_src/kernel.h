#ifndef KERNEL_H
#define KERNEL_H
#include <asm/tlbflush.h>
#include <linux/rcupdate.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/sched/mm.h>
#include <linux/pid.h>
#include <linux/spinlock.h>
#include <linux/slab.h>
#include <linux/version.h>
#include <linux/list.h>
#include <linux/kobject.h>
#include <linux/vmalloc.h>
#include <linux/set_memory.h>

#include <asm/pgtable.h>
#include <asm/ptrace.h>
#include <asm/processor.h>
#include <asm/fpsimd.h>
#include <asm/traps.h>
#include <asm/cacheflush.h>
#include <asm/memory.h>
#include <asm/tlb.h>

#define PSR_SS_BIT  (1UL << 21)

#ifndef PTE_PRESENT
#define PTE_PRESENT (_AT(pteval_t, 1) << 0)
#endif

/* ================================================================
 * 一、动态符号解析（三级回退）
 *   路径A: kprobe 拿 kallsyms_lookup_name
 *   路径B: 用户态读 /proc/kallsyms 后通过 SYM_INJECT 注入
 *   路径C: 扫描 _stext~_etext 的 kallsyms 表（极少用）
 * ================================================================ */

typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);

extern kallsyms_lookup_name_t g_kln;

/* 需要动态解析的符号 */
struct dyn_syms {
    struct pid *(*find_get_pid)(int nr);
    struct task_struct *(*get_pid_task)(struct pid *pid, enum pid_type type);
    void (*put_pid)(struct pid *pid);
    struct mm_struct *(*get_task_mm)(struct task_struct *task);
    void (*mmput)(struct mm_struct *mm);
    void (*put_task_struct)(struct task_struct *t);
    pte_t *(*pte_offset_map_lock)(struct mm_struct *mm, pmd_t *pmd,
                                  unsigned long address, spinlock_t **ptlp);
    void (*pte_unmap_unlock)(pte_t *pte, spinlock_t *ptlp);
    int (*set_memory_rw)(unsigned long addr, int numpages);
    int (*set_memory_ro)(unsigned long addr, int numpages);
    int (*set_memory_x)(unsigned long addr, int numpages);
    struct perf_event *(*register_user_hw_breakpoint_ptr)(
                    struct perf_event_attr *attr,
                    void (*cb)(struct perf_event *bp,
                               struct perf_sample_data *data,
                               struct pt_regs *regs),
                    void *context,
                    struct task_struct *tsk);
    void (*unregister_hw_breakpoint_ptr)(struct perf_event *bp);
};

extern struct dyn_syms S;

/* 符号解析位图 */
#define SYM_FIND_GET_PID          (1u << 0)
#define SYM_GET_PID_TASK          (1u << 1)
#define SYM_PUT_PID               (1u << 2)
#define SYM_GET_TASK_MM           (1u << 3)
#define SYM_MMPUT                 (1u << 4)
#define SYM_PUT_TASK_STRUCT       (1u << 5)
#define SYM_PTE_OFFSET_MAP_LOCK   (1u << 6)
#define SYM_PTE_UNMAP_UNLOCK      (1u << 7)
#define SYM_SET_MEMORY_RW         (1u << 8)
#define SYM_SET_MEMORY_RO         (1u << 9)
#define SYM_SET_MEMORY_X          (1u << 10)
#define SYM_REG_USER_HWBP         (1u << 11)
#define SYM_UNREG_HWBP            (1u << 12)

extern u32 g_sym_mask;

int  sym_resolve_all(void);
int  sym_inject(const char *name, unsigned long addr);  /* 回退路径B */

/* ================================================================
 * 二、CFI 绕过
 *   1) 间接调用一律走 inline asm blr，编译器无法插入 __cfi_check
 *   2) patch_text() 写内核 text 时同时处理 CFI jump-table
 * ================================================================ */

#define CFI_CLOBBERS "memory","cc", \
    "x1","x2","x3","x4","x5","x6","x7","x8","x9","x10", \
    "x11","x12","x13","x14","x15","x16","x17","x30", \
    "v0","v1","v2","v3","v4","v5","v6","v7", \
    "v16","v17","v18","v19","v20","v21","v22","v23", \
    "v24","v25","v26","v27","v28","v29","v30","v31"
#define CFI_CALL1(fn, a1) ({                                          \
    register unsigned long _x0 __asm__("x0") = (unsigned long)(a1);   \
    __asm__ volatile("blr %1" : "+r"(_x0) : "r"(fn) : CFI_CLOBBERS); \
    _x0; })
#define CFI_CALL2(fn, a1, a2) ({                                      \
    register unsigned long _x0 __asm__("x0") = (unsigned long)(a1);   \
    register unsigned long _x1 __asm__("x1") = (unsigned long)(a2);   \
    __asm__ volatile("blr %2" : "+r"(_x0), "+r"(_x1)                 \
                     : "r"(fn) : CFI_CLOBBERS); _x0; })
#define CFI_CALL3(fn, a1, a2, a3) ({                                  \
    register unsigned long _x0 __asm__("x0") = (unsigned long)(a1);   \
    register unsigned long _x1 __asm__("x1") = (unsigned long)(a2);   \
    register unsigned long _x2 __asm__("x2") = (unsigned long)(a3);   \
    __asm__ volatile("blr %3" : "+r"(_x0), "+r"(_x1), "+r"(_x2)      \
                     : "r"(fn) : CFI_CLOBBERS); _x0; })
#define CFI_CALL4(fn, a1, a2, a3, a4) ({                              \
    register unsigned long _x0 __asm__("x0") = (unsigned long)(a1);   \
    register unsigned long _x1 __asm__("x1") = (unsigned long)(a2);   \
    register unsigned long _x2 __asm__("x2") = (unsigned long)(a3);   \
    register unsigned long _x3 __asm__("x3") = (unsigned long)(a4);   \
    __asm__ volatile("blr %4" : "+r"(_x0), "+r"(_x1), "+r"(_x2),     \
                     "+r"(_x3) : "r"(fn) : CFI_CLOBBERS); _x0; })
#define CFI_VOID1(fn, a1) ({                                          \
    register unsigned long _x0 __asm__("x0") = (unsigned long)(a1);   \
    __asm__ volatile("blr %1" : "+r"(_x0) : "r"(fn) : CFI_CLOBBERS); })
#define CFI_VOID2(fn, a1, a2) ({                                      \
    register unsigned long _x0 __asm__("x0") = (unsigned long)(a1);   \
    register unsigned long _x1 __asm__("x1") = (unsigned long)(a2);   \
    __asm__ volatile("blr %2" : "+r"(_x0), "+r"(_x1)                 \
                     : "r"(fn) : CFI_CLOBBERS); })

/* ================================================================
 * 三、只读 text 安全写入
 *   优先 set_memory_rw（动态解析），失败则手改页表 PTE 写位
 * ================================================================ */

/* 手改页表给只读内核地址加写权限（set_memory_rw 不可用时的回退） */
static inline int kernel_text_unprotect(unsigned long addr)
{
    pgd_t *pgd; p4d_t *p4d; pud_t *pud; pmd_t *pmd; pte_t *pte;
    unsigned long page = addr & PAGE_MASK;
    struct mm_struct *init_mm_ptr = &init_mm;

    pgd = pgd_offset(init_mm_ptr, page);
    if (pgd_none(*pgd) || pgd_bad(*pgd)) return -EFAULT;
    p4d = p4d_offset(pgd, page);
    pud = pud_offset(p4d, page);
    if (pud_none(*pud) || pud_bad(*pud)) return -EFAULT;
    pmd = pmd_offset(pud, page);
    if (pmd_none(*pmd) || pmd_bad(*pmd)) return -EFAULT;
    pte = pte_offset_kernel(pmd, page);
    if (!pte || pte_none(*pte)) return -EFAULT;
    set_pte(pte, __pte(pte_val(*pte) | PTE_WRITE));
    flush_tlb_kernel_page(page);
    return 0;
}

static inline void kernel_text_reprotect(unsigned long addr)
{
    pgd_t *pgd; p4d_t *p4d; pud_t *pud; pmd_t *pmd; pte_t *pte;
    unsigned long page = addr & PAGE_MASK;
    pgd = pgd_offset(&init_mm, page);
    if (pgd_none(*pgd)) return;
    p4d = p4d_offset(pgd, page);
    pud = pud_offset(p4d, page);
    if (pud_none(*pud)) return;
    pmd = pmd_offset(pud, page);
    if (pmd_none(*pmd)) return;
    pte = pte_offset_kernel(pmd, page);
    if (pte && !pte_none(*pte)) {
        set_pte(pte, __pte(pte_val(*pte) & ~PTE_WRITE));
        flush_tlb_kernel_page(page);
    }
}

/* 安全写内核 text：自动选 set_memory_rw 或手改页表，写完恢复 */
int patch_text(unsigned long dst, const void *src, size_t len);
/* 写一条 ARM64 指令 */
int patch_insn(unsigned long addr, u32 insn);

#endif
