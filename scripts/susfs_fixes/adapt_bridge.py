#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
adapt_bridge.py — SukiSU main 分支适配 SUSFS 外部补丁签名（方案 B 构建期适配脚本）

职责：把 kernel/hook/syscall_event_bridge.c 整体替换为适配版
      （单文件版：模板内嵌于本脚本 TEMPLATE 常量），使桥内调用对齐
      10_enable_susfs_for_ksu.patch 替换后的官方 KernelSU 签名。

特性：
  1. 幂等：替换后文件带 SUSFS_BRIDGE_ADAPTED 标记，重复运行直接跳过。
  2. 锚点校验：替换前校验原文件仍为已知的 main 结构（含旧签名调用特征），
     任一锚点缺失即判定 main 已更新结构，脚本以退出码 2 失败并列出差异，
     构建流程必须因此中断，提示人工复查适配模板（持续随 main 更新的复查点）。
  3. 无副作用：不修改其它文件，不触碰补丁产物（.rej/.orig）。

用法：
  python3 adapt_bridge.py <KernelSU源码根目录>
    例如 KernelSU 源码解压于 kernel/KernelSU 时：
      python3 adapt_bridge.py kernel/KernelSU

退出码：
  0  成功替换 / 无需替换 / 已适配（幂等跳过）
  1  参数或文件缺失等可诊断错误
  2  原桥文件结构与适配模板预期不符（main 结构变化），需人工复查
"""
import os
import re
import sys

ADAPT_MARK = "SUSFS_BRIDGE_ADAPTED"
BRIDGE_REL = os.path.join("kernel", "hook", "syscall_event_bridge.c")
# 单文件版：模板内嵌于 TEMPLATE 常量，不再依赖 files/ 目录

# main 旧结构锚点：适配模板所基于的调用特征，缺任一说明 main 已改结构
ANCHORS = [
    "ksu_hook_execve_common",
    "ksu_handle_stat_sucompat",
    "ksu_handle_faccessat_sucompat",
    "ksu_su_compat_enabled",
    "ksu_handle_setresuid",
    "ksu_execveat_hook_ksud",
    "ksu_sulog_capture_root_execve",
]


def fail(msg, code=1):
    sys.stderr.write("[adapt_bridge] %s\n" % msg)
    sys.exit(code)


# 内嵌适配模板（原 files/syscall_event_bridge.c.susfs）：
# 10_enable 补丁后的官方签名对齐版桥源码。内嵌后可单文件部署，无需 files/ 目录。
TEMPLATE = r"""/*
 * syscall_event_bridge.c — SukiSU main 分支适配 SUSFS 外部补丁签名版
 *
 * 生成方式：由 scripts/susfs_fixes/adapt_bridge.py 在构建时校验并整体替换
 * 原始文件 kernel/hook/syscall_event_bridge.c（方案 B：main + 适配 bridge.c）。
 *
 * 背景：10_enable_susfs_for_ksu.patch 按官方 KernelSU(weishu) tag 编写，会把
 * sucompat.h / ksud.h / adb_root.h / setuid_hook.h / event.h 的声明替换成官方
 * 新签名（struct static_key_true、struct filename * / struct user_arg_ptr 风格），
 * 而 SukiSU main 自带的桥接文件仍按 pt_regs 风格调用旧 API，导致编译失败。
 *
 * 本文件保持 main 的 5 个桥入口（ksu_hook_newfstatat / ksu_hook_faccessat /
 * ksu_hook_execve / ksu_hook_execveat / ksu_hook_setresuid）与 syscall_hook_manager.c
 * 的约定不变，函数体内全部对齐补丁后的官方签名调用范式。
 *
 * 标记：SUSFS_BRIDGE_ADAPTED
 */
#include "linux/compiler.h"
#include "linux/cred.h"
#include "linux/jump_label.h"
#include "linux/printk.h"
#include "linux/string.h"
#include "selinux/selinux.h"
#include <asm/syscall.h>
#include <linux/compat.h>
#include <linux/fs.h>
#include <linux/ptrace.h>
#include <linux/sched/task_stack.h>
#include <linux/static_key.h>
#include <linux/uaccess.h>

#include "arch.h"
#include "klog.h" // IWYU pragma: keep
#include "hook/tp_marker.h"
#include "feature/sucompat.h"
#include "hook/setuid_hook.h"
#include "policy/app_profile.h"
#include "runtime/ksud.h"
#include "sulog/event.h"
#include "hook/syscall_hook.h"
#include "hook/syscall_event_bridge.h"
#include "feature/adb_root.h"
#include "policy/allowlist.h"

#define SUSFS_BRIDGE_SU_PATH "/system/bin/su"

/* 补丁后 sucompat.h 未声明的官方函数 / 补丁后 ksud_integration.c 暴露的 static key */
extern int ksu_handle_post_execveat_sucompat(int *fd, struct filename **filename_ptr,
                                             void *argv_user, void *envp_user,
                                             int *__never_use_flags, int *retval);
extern struct static_key_true is_first_zygote;
extern struct static_key_true is_init_second_stage_not_executed;
extern int ksu_handle_setresuid(uid_t ruid, uid_t euid, uid_t suid);

/*
 * 与补丁后 sucompat.c 中 userspace_stack_buffer / sh_user_path / ksud_user_path
 * 等价的本地实现（官方版是 static，无法跨编译单元引用，此处复刻）。
 */
static void __user *susfs_bridge_userspace_stack_buffer(const void *d, size_t len)
{
    char __user *p = (void __user *)current_user_stack_pointer() - len;

    return copy_to_user(p, d, len) ? NULL : p;
}

static char __user *susfs_bridge_sh_user_path(void)
{
    static const char sh_path[] = "/system/bin/sh";

    return susfs_bridge_userspace_stack_buffer(sh_path, sizeof(sh_path));
}

static char __user *susfs_bridge_ksud_user_path(void)
{
    static const char ksud_path[] = KSUD_PATH;

    return susfs_bridge_userspace_stack_buffer(ksud_path, sizeof(ksud_path));
}

static int ksu_handle_init_mark_tracker(const char __user **filename_user)
{
    char path[64];
    unsigned long addr;
    const char __user *fn;
    long ret;

    if (unlikely(!filename_user))
        return 0;

    addr = untagged_addr((unsigned long)*filename_user);
    fn = (const char __user *)addr;
    ret = strncpy_from_user(path, fn, sizeof(path));
    if (ret < 0)
        return 0;

    path[sizeof(path) - 1] = '\0';
    if (unlikely(strcmp(path, KSUD_PATH) == 0)) {
        pr_info("hook_manager: escape to root for init executing ksud: %d\n", current->pid);
        escape_to_root_for_init();
    } else if (likely(strstr(path, "/app_process") == NULL && strstr(path, "/adbd") == NULL &&
                      strstr(path, "/stub_zygote") == NULL)) {
        pr_info("hook_manager: unmark %d exec %s\n", current->pid, path);
        ksu_clear_task_tracepoint_flag_if_needed(current);
    }

    return 0;
}

/* newfstatat / faccessat：补丁后官方语义为 su -> sh（ksu_handle_stat / ksu_handle_faccessat
 * 把 filename->name 改成 /system/bin/sh 后继续原流程）。桥在 syscall 层无法传递内核态
 * filename，因此采用 regs 改写等价实现：命中 /system/bin/su 时把用户可见路径指针改写为 sh。 */
static long __nocfi ksu_hook_stat_common(int orig_nr, const struct pt_regs *regs)
{
    if (static_branch_likely(&ksu_su_compat_enabled) &&
        unlikely(__ksu_is_allow_uid_for_current(current_uid().val))) {
        const char __user **filename_user = (const char __user **)&PT_REGS_PARM2(regs);
        char path[sizeof(SUSFS_BRIDGE_SU_PATH) + 1];

        memset(path, 0, sizeof(path));
        if (strncpy_from_user_nofault(path, *filename_user, sizeof(path)) > 0 &&
            unlikely(!memcmp(path, SUSFS_BRIDGE_SU_PATH, sizeof(SUSFS_BRIDGE_SU_PATH)))) {
            *filename_user = susfs_bridge_sh_user_path();
        }
    }

    return ksu_syscall_table[orig_nr](regs);
}

long __nocfi ksu_hook_newfstatat(int orig_nr, const struct pt_regs *regs)
{
    return ksu_hook_stat_common(orig_nr, regs);
}

long __nocfi ksu_hook_faccessat(int orig_nr, const struct pt_regs *regs)
{
    return ksu_hook_stat_common(orig_nr, regs);
}

DEFINE_STATIC_KEY_TRUE(ksud_execve_key);

void ksu_stop_ksud_execve_hook()
{
    static_branch_disable(&ksud_execve_key);
}

static long __nocfi ksu_hook_execve_common(int orig_nr, const struct pt_regs *regs, bool execveat)
{
    const char __user **filename_user =
        execveat ? (const char __user **)&PT_REGS_PARM2(regs) : (const char __user **)&PT_REGS_SYSCALL_PARM1(regs);
    const char __user *const __user *argv_user = execveat ? (const char __user *const __user *)PT_REGS_PARM3(regs) :
                                                            (const char __user *const __user *)PT_REGS_PARM2(regs);
    const char __user *const __user *envp_user = execveat ? (const char __user *const __user *)PT_REGS_SYSCALL_PARM4(regs) :
                                                            (const char __user *const __user *)PT_REGS_PARM3(regs);
    struct user_arg_ptr argv, envp;
    struct filename *filename;
    int fd = execveat ? (int)PT_REGS_PARM1(regs) : 0;
    int flags = execveat ? (int)PT_REGS_PARM5(regs) : 0;
    long ret;
    int retval;

#ifdef CONFIG_COMPAT
    argv.is_compat = in_compat_syscall();
    envp.is_compat = in_compat_syscall();
#endif
    argv.ptr.native = argv_user;
    envp.ptr.native = envp_user;

    /* 1) ksud 启动检测（init second_stage / zygote）：对齐官方 ksu_handle_execveat_ksud
     *    语义，仅在相关 static key 未关闭时构造参数调用（幂等，key 关闭后零开销）。 */
    if (static_branch_unlikely(&is_first_zygote) ||
        static_branch_unlikely(&is_init_second_stage_not_executed)) {
        filename = getname(*filename_user);
        if (!IS_ERR(filename)) {
            ksu_handle_execveat_ksud(&fd, &filename, &argv, &envp, &flags);
            putname(filename);
        }
    }

    /* 2) init 进程 mark tracker（保留 main 行为）；adb root / init-escape 已由官方
     *    ksu_handle_execveat_sucompat -> ksu_handle_execveat_init 内部处理。 */
    if (current->pid != 1 && is_init(current_cred()))
        ksu_handle_init_mark_tracker(filename_user);

    /* 3) sucompat：官方签名。命中 su 时返回 0（filename->name 已被改写为 ksud_path），
     *    桥把用户可见路径指针改写为 ksud 后放行原 syscall，再补 post hook。 */
    if (static_branch_likely(&ksu_su_compat_enabled)) {
        filename = getname(*filename_user);
        if (!IS_ERR(filename)) {
            if (ksu_handle_execveat_sucompat(&fd, &filename, &argv, &envp, &flags) == 0) {
                *filename_user = susfs_bridge_ksud_user_path();
                ret = ksu_syscall_table[orig_nr](regs);
                retval = (int)ret;
                (void)ksu_handle_post_execveat_sucompat(&fd, &filename, &argv, &envp, &flags, &retval);
                putname(filename);
                return ret;
            }
            putname(filename);
        }
    }

    ret = ksu_syscall_table[orig_nr](regs);
    return ret;
}

long __nocfi ksu_hook_execve(int orig_nr, const struct pt_regs *regs)
{
    return ksu_hook_execve_common(orig_nr, regs, false);
}

long __nocfi ksu_hook_execveat(int orig_nr, const struct pt_regs *regs)
{
    return ksu_hook_execve_common(orig_nr, regs, true);
}

long __nocfi ksu_hook_setresuid(int orig_nr, const struct pt_regs *regs)
{
    uid_t old_uid = current_uid().val;
    long ret = ksu_syscall_table[orig_nr](regs);

    if (ret < 0)
        return ret;

    /* 补丁后 ksu_handle_setresuid 为官方 3 参签名 (ruid, euid, suid)，
     * 声明已从 setuid_hook.h 移除，见文件顶部 extern。 */
    ksu_handle_setresuid(old_uid, current_uid().val, (uid_t)PT_REGS_PARM3(regs));
    return ret;
}
"""

def main():
    if len(sys.argv) != 2:
        fail("用法: python3 adapt_bridge.py <KernelSU源码根目录>")
    root = sys.argv[1]
    if not os.path.isdir(root):
        fail("目录不存在: %s" % root)

    bridge_path = os.path.join(root, BRIDGE_REL)
    if not os.path.isfile(bridge_path):
        sys.stderr.write("[adapt_bridge] 未找到 %s，跳过适配（非 SukiSU main 结构）\n" % bridge_path)
        return 0

    with open(bridge_path, "r", encoding="utf-8", errors="replace") as f:
        old = f.read()

    if ADAPT_MARK in old:
        sys.stderr.write("[adapt_bridge] 桥文件已适配（%s），幂等跳过\n" % ADAPT_MARK)
        return 0

    # 锚点校验：必须同时具备模板依赖的全部旧签名特征
    missing = [a for a in ANCHORS if a not in old]
    if missing:
        sys.stderr.write(
            "[adapt_bridge] 原桥文件结构已与适配模板预期不符，缺失锚点: %s\n"
            "[adapt_bridge] SukiSU main 可能已更新桥实现，请人工复查\n"
            "[adapt_bridge] 适配模板: %s\n" % (", ".join(missing), TEMPLATE_REL)
        )
        return 2

    new = TEMPLATE
    if ADAPT_MARK not in new:
        fail("适配模板缺少适配标记 %s，拒绝替换" % ADAPT_MARK)

    with open(bridge_path, "w", encoding="utf-8") as f:
        f.write(new)

    # 替换结果自检
    with open(bridge_path, "r", encoding="utf-8", errors="replace") as f:
        check = f.read()
    required = [ADAPT_MARK, "ksu_hook_execve_common", "ksu_handle_execveat_sucompat",
                "ksu_handle_post_execveat_sucompat", "ksu_handle_execveat_ksud",
                "susfs_bridge_ksud_user_path"]
    missing_new = [r for r in required if r not in check]
    if missing_new:
        fail("替换后自检失败，缺失: %s（文件可能被并发修改）" % ", ".join(missing_new))

    sys.stderr.write("[adapt_bridge] 已整体替换 %s -> 适配版（%d 字节）\n" % (bridge_path, len(new)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
