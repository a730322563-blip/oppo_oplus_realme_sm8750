#ifndef COMM_H
#define COMM_H

#include <linux/types.h>

#define DEVICE_NAME "rt_driver"
#define DEVICE_PATH "/dev/rt_driver"

/* ================================================================
 * ioctl 命令码 —— 保持与菜单 Track.cpp 兼容 (0x810~0x815)
 * 结构体全部 8 字节对齐，避免 32/64 位 ABI 错位
 * ================================================================ */

#define PTE_INSTALL     0x810   /* 安装 PTE 追踪 */
#define PTE_SET_TARGET  0x811   /* 更新目标地址 */
#define PTE_REMOVE      0x812   /* 移除 PTE 追踪 */
#define PTE_GET_HITS    0x813   /* 读取命中次数 */
#define PTE_SET_PAUSE   0x814   /* 暂停/恢复 */
#define PTE_SET_REGS    0x815   /* 写入 V3/V4/V5 (6×u64) */

/* 硬件断点 */
#define HWBP_INSTALL    0x820   /* 安装硬件断点 */
#define HWBP_REMOVE     0x821   /* 移除硬件断点 */
#define HWBP_GET_HITS   0x822

/* 符号地址注入（符号解析回退路径：用户态读 /proc/kallsyms 后传入） */
#define SYM_INJECT      0x830
#define SYM_BATCH       0x831   /* 批量注入 */

/* 自检 */
#define DRIVER_STATUS   0x840

struct pte_install_args {
    int32_t  pid;
    uint32_t _pad;
    uint64_t target_addr;
} __attribute__((aligned(8)));

struct pte_set_regs_args {
    uint64_t v3_lo, v3_hi;
    uint64_t v4_lo, v4_hi;
    uint64_t v5_lo, v5_hi;
} __attribute__((aligned(8)));

struct hwbp_install_args {
    int32_t  pid;
    uint32_t bp_type;   /* 0=exec 1=load 2=store 3=load/store */
    uint64_t addr;
    uint64_t len;
} __attribute__((aligned(8)));

struct sym_inject_args {
    uint64_t addr;
    char     name[56];
} __attribute__((aligned(8)));

struct driver_status {
    uint32_t sym_resolved;   /* 符号解析位图 */
    uint32_t pte_active;
    uint32_t hwbp_active;
    uint32_t hidden;
    uint64_t pte_hits;
} __attribute__((aligned(8)));

#endif
