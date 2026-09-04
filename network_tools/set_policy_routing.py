#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
极简 IPv4 源策略路由设置（无状态、无回滚）

用法:
    sudo ./set_policy_routing.py <interface> [table_id]

示例:
    sudo ./set_policy_routing.py eth1 203

功能:
    指定网卡的源 IPv4 -> 专用路由表 -> 指定网卡

特点:
    - 自动识别网卡真实 IPv4 CIDR，不假设 /24
    - 自动计算真实网络地址
    - 自动获取该接口默认网关
    - 路由表先准备好，再添加策略规则
    - rp_filter 设置为 loose (2)，仅修改目标接口
    - 无状态、无回滚，适合简单部署场景
"""

from __future__ import annotations

import argparse
import ipaddress
import os
import shutil
import subprocess
import sys
from typing import Optional


DEFAULT_TABLE = 203
PRIO_MIN = 10000
PRIO_MAX = 19999


def log(message: str) -> None:
    print(f"[{os.path.basename(sys.argv[0])}] {message}")


def warn(message: str) -> None:
    print(f"[{os.path.basename(sys.argv[0])}] warning: {message}", file=sys.stderr)


def die(message: str, code: int = 1) -> None:
    print(f"[{os.path.basename(sys.argv[0])}] error: {message}", file=sys.stderr)
    raise SystemExit(code)


def run(
    args: list[str],
    *,
    check: bool = True,
    capture_output: bool = True,
) -> subprocess.CompletedProcess[str]:
    """执行系统命令。"""
    try:
        return subprocess.run(
            args,
            check=check,
            text=True,
            capture_output=capture_output,
        )
    except FileNotFoundError:
        die(f"命令未找到: {args[0]}")
    except PermissionError:
        die(f"没有权限执行命令: {args[0]}")


def need_root() -> None:
    if os.geteuid() != 0:
        die("请使用 root 执行 (sudo)")


def need_command(name: str) -> None:
    if shutil.which(name) is None:
        die(f"命令未找到: {name}")


def interface_exists(interface: str) -> bool:
    result = run(["ip", "link", "show", interface], check=False)
    return result.returncode == 0


def get_cidr(interface: str) -> str:
    """获取接口第一个 IPv4 global 地址，例如 192.168.1.10/24。"""
    result = run(
        ["ip", "-4", "-o", "addr", "show", "dev", interface, "scope", "global"],
        check=False,
    )
    if result.returncode != 0:
        return ""

    for line in result.stdout.splitlines():
        fields = line.split()
        # ip -4 -o addr 输出中地址通常位于第 4 列：inet <cidr>
        try:
            inet_index = fields.index("inet")
        except ValueError:
            continue
        if inet_index + 1 < len(fields):
            return fields[inet_index + 1]

    return ""


def get_gateway(interface: str) -> Optional[str]:
    """获取该接口的 IPv4 默认网关。没有则返回 None。"""
    result = run(
        ["ip", "-4", "route", "show", "default", "dev", interface],
        check=False,
    )
    if result.returncode != 0:
        return None

    for line in result.stdout.splitlines():
        fields = line.split()
        for index, field in enumerate(fields):
            if field == "via" and index + 1 < len(fields):
                return fields[index + 1]
    return None


def find_free_priority() -> Optional[int]:
    """在指定范围内寻找空闲的 IPv4 rule priority。"""
    result = run(["ip", "-4", "rule", "show"], check=False)
    if result.returncode != 0:
        return None

    used: set[int] = set()
    for line in result.stdout.splitlines():
        if not line.strip():
            continue
        first = line.split()[0].rstrip(":")
        try:
            used.add(int(first))
        except ValueError:
            continue

    for priority in range(PRIO_MIN, PRIO_MAX + 1):
        if priority not in used:
            return priority
    return None


def delete_existing_rule(source_ip: str, table: int) -> None:
    """删除已有相同的 source-policy rule。"""
    run(
        [
            "ip",
            "-4",
            "rule",
            "del",
            "from",
            f"{source_ip}/32",
            "table",
            str(table),
        ],
        check=False,
    )


def add_rule(source_ip: str, table: int, priority: int) -> None:
    result = run(
        [
            "ip",
            "-4",
            "rule",
            "add",
            "pref",
            str(priority),
            "from",
            f"{source_ip}/32",
            "table",
            str(table),
        ],
        check=False,
    )
    if result.returncode != 0:
        message = result.stderr.strip() or "未知错误"
        die(f"添加策略规则失败: {message}")


def replace_connected_route(
    network: ipaddress.IPv4Network,
    interface: str,
    source_ip: str,
    table: int,
) -> None:
    result = run(
        [
            "ip",
            "-4",
            "route",
            "replace",
            str(network),
            "dev",
            interface,
            "scope",
            "link",
            "src",
            source_ip,
            "table",
            str(table),
        ],
        check=False,
    )
    if result.returncode != 0:
        message = result.stderr.strip() or "未知错误"
        die(f"添加直连路由失败: {message}")


def replace_default_route(
    interface: str,
    source_ip: str,
    gateway: Optional[str],
    table: int,
) -> None:
    if gateway:
        command = [
            "ip",
            "-4",
            "route",
            "replace",
            "default",
            "via",
            gateway,
            "dev",
            interface,
            "src",
            source_ip,
            "table",
            str(table),
        ]
        error_name = "添加默认路由（网关）"
    else:
        command = [
            "ip",
            "-4",
            "route",
            "replace",
            "default",
            "dev",
            interface,
            "src",
            source_ip,
            "table",
            str(table),
        ]
        error_name = "添加默认路由（设备）"

    result = run(command, check=False)
    if result.returncode != 0:
        message = result.stderr.strip() or "未知错误"
        die(f"{error_name}失败: {message}")


def set_rp_filter(interface: str) -> None:
    """将目标接口的 rp_filter 设置为 loose (2)。失败不影响主路由配置。"""
    try:
        result = subprocess.run(
            [
                "sysctl",
                "-q",
                "-w",
                f"net.ipv4.conf.{interface}.rp_filter=2",
            ],
            check=False,
            text=True,
            capture_output=True,
        )
    except FileNotFoundError:
        warn("未找到 sysctl，无法设置 rp_filter")
        return
    except PermissionError:
        warn("没有权限设置 rp_filter")
        return

    if result.returncode != 0:
        message = result.stderr.strip() or "未知错误"
        warn(f"设置 rp_filter 失败，不影响路由功能: {message}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="极简 IPv4 源策略路由设置（无状态、无回滚）",
        epilog=(
            "示例:\n"
            "  sudo ./set_policy_routing.py eth1 203\n"
            "  sudo ./set_policy_routing.py enp8s0\n\n"
            "说明:\n"
            "  interface 为目标网卡；table_id 为策略路由表 ID，默认 203。"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("interface", help="目标: 网卡名称，例如 eth1")
    parser.add_argument(
        "table_id",
        nargs="?",
        type=int,
        default=DEFAULT_TABLE,
        help=f"配置: 策略路由表 ID（1-252，默认 {DEFAULT_TABLE}）",
    )

    # 按仓库规范：无参数运行时显示帮助，而不是输出参数缺失错误。
    if len(sys.argv) == 1:
        parser.print_help()
        raise SystemExit(0)

    return parser.parse_args()


def main() -> None:
    # 先解析参数，使 -h 或无参数时可以直接显示帮助，不要求 root 权限。
    args = parse_args()

    need_root()
    need_command("ip")
    need_command("sysctl")

    interface = args.interface
    table = args.table_id

    if not (1 <= table <= 252):
        die("表ID须在 1-252 之间")

    if not interface_exists(interface):
        die(f"接口不存在: {interface}")

    cidr_text = get_cidr(interface)
    if not cidr_text:
        die(f"接口 {interface} 没有 IPv4 全局地址")

    try:
        cidr = ipaddress.IPv4Interface(cidr_text)
    except ValueError as exc:
        die(f"无法解析接口 IPv4 地址 {cidr_text}: {exc}")

    source_ip = str(cidr.ip)
    network = cidr.network
    gateway = get_gateway(interface)

    log(
        f"接口={interface} 源IP={source_ip} CIDR={cidr} "
        f"网络={network} 网关={gateway or '无'} 表={table}"
    )

    # 1. 先准备好路由表，避免 rule 生效后 table 仍处于半配置状态。
    replace_connected_route(network, interface, source_ip, table)
    replace_default_route(interface, source_ip, gateway, table)

    # 2. 最后切换策略规则，保证启用时 table 已完整。
    delete_existing_rule(source_ip, table)
    priority = find_free_priority()
    if priority is None:
        die(f"在 {PRIO_MIN}-{PRIO_MAX} 中无空闲优先级")
    add_rule(source_ip, table, priority)

    # 3. 仅修改目标接口的 rp_filter 为 loose (2)。
    set_rp_filter(interface)

    log("完成")
    print()
    print("验证命令：")
    print("  ip -4 rule show")
    print(f"  ip -4 route show table {table}")
    print(f"  ip -4 route get 8.8.8.8 from {source_ip}")


if __name__ == "__main__":
    main()
