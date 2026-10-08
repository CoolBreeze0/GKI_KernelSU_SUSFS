#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
adapt_bridge.py — SukiSU main 分支适配 SUSFS 外部补丁签名（方案 B 构建期适配脚本）

职责：把 kernel/hook/syscall_event_bridge.c 整体替换为适配版
      （scripts/susfs_fixes/files/syscall_event_bridge.c.susfs），使桥内调用对齐
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
TEMPLATE_REL = os.path.join("files", "syscall_event_bridge.c.susfs")

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

    template_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), TEMPLATE_REL)
    if not os.path.isfile(template_path):
        fail("适配模板缺失: %s" % template_path)
    with open(template_path, "r", encoding="utf-8") as f:
        new = f.read()
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
