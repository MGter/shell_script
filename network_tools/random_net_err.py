#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
文件名: random_net_err.py
功能: 弱网/丢包烤机测试工具
描述: 通过 Linux tc netem 在指定网卡上注入延时、丢包、损坏、重复等异常；支持随机烤机与固定参数两种模式
依赖:
    1. tc (iproute2，系统工具，需 root 权限)
    2. Python3 标准库
创建人: MGter
"""

import os
import sys
import time
import signal
import random
import argparse
import subprocess
from datetime import datetime


def show_help():
    """显示帮助信息"""
    print("""
用法: sudo python3 random_net_err.py -n <网卡> [模式与参数...] [-h]

必选:
  -n <网卡>       网卡名称，与 ip link 显示一致

模式 (二选一，默认 random):
  -m random        周期性随机弱网 (默认)
  -m fixed         按下方参数注入固定弱网，至少指定一项

随机模式 (-m random) 专用:
  -o <日志>        日志文件 (默认: ./net_err.log)
  -s <小时>        开始时刻 0-23 (默认: 0)
  -e <小时>        结束时刻 0-23 (默认: 8)，须大于 -s
  -a               全天随机，忽略 -s / -e
  -c <秒>          主循环检查间隔 (默认: 30)

固定模式 (-m fixed) 专用，可组合多项:
  --delay <ms>     延时 (毫秒)
  --loss <%>       丢包率
  --corrupt <%>    包损坏率
  --duplicate <%>  重复报文率
  --reorder <%>    乱序率
  -d <秒>          持续时长，0 表示直到 Ctrl+C (默认: 0)

通用:
  -h               显示帮助

说明:
  需 root 执行；退出时自动 tc qdisc del 恢复网卡
  未指定 -m 且给出 --delay/--loss 等参数时，自动视为 fixed 模式

示例:
  sudo python3 random_net_err.py -n eth2
  sudo python3 random_net_err.py -n eth0 -a -c 60
  sudo python3 random_net_err.py -n eth2 -m fixed --loss 5
  sudo python3 random_net_err.py -n eth2 -m fixed --delay 200 --loss 10 -d 300
  sudo python3 random_net_err.py -n bond0 --loss 3 --corrupt 2
""")


def validate_args(args):
    """校验命令行参数"""
    if not (0 <= args.start_hour <= 23 and 0 <= args.end_hour <= 23):
        print("[错误] -s / -e 须在 0-23 之间")
        return False
    if args.check_interval <= 0:
        print("[错误] -c 须大于 0")
        return False
    if not args.all_day and args.mode == 'random' and args.start_hour >= args.end_hour:
        print("[错误] 随机模式须满足 start < end，或使用 -a 全天模式")
        return False
    if not os.path.exists("/sys/class/net/" + args.netcard):
        print("[错误] 网卡不存在: " + args.netcard)
        return False
    if args.mode == 'random' and args.has_fixed_params and args.mode_explicit:
        print("[警告] 已指定 -m random，--delay/--loss 等固定参数将被忽略")
    if args.mode == 'fixed':
        if not args.has_fixed_params:
            print("[错误] fixed 模式至少指定一项: --delay / --loss / --corrupt / --duplicate / --reorder")
            return False
        if args.duration < 0:
            print("[错误] -d 不能为负数")
            return False
        for name, val in (
            ('delay', args.delay),
            ('loss', args.loss),
            ('corrupt', args.corrupt),
            ('duplicate', args.duplicate),
            ('reorder', args.reorder),
        ):
            if val is None:
                continue
            if name == 'delay' and val < 0:
                print("[错误] --delay 不能为负数")
                return False
            if name != 'delay' and not (0 <= val <= 100):
                print("[错误] --" + name + " 须在 0-100 之间")
                return False
    return True


def detect_mode(args):
    """根据参数推断运行模式"""
    fixed_flags = (
        args.delay is not None
        or args.loss is not None
        or args.corrupt is not None
        or args.duplicate is not None
        or args.reorder is not None
    )
    args.has_fixed_params = fixed_flags
    if args.mode_explicit:
        return args.mode
    if fixed_flags:
        return 'fixed'
    return 'random'


# 无参数或帮助模式时先显示帮助
if len(sys.argv) == 1 or '-h' in sys.argv:
    show_help()
    sys.exit(0)

parser = argparse.ArgumentParser(add_help=False)
parser.add_argument('-n', dest='netcard', required=True)
parser.add_argument('-m', dest='mode', choices=['random', 'fixed'], default='random')
parser.add_argument('-o', dest='logfile', default='./net_err.log')
parser.add_argument('-s', dest='start_hour', type=int, default=0)
parser.add_argument('-e', dest='end_hour', type=int, default=8)
parser.add_argument('-a', dest='all_day', action='store_true')
parser.add_argument('-c', dest='check_interval', type=int, default=30)
parser.add_argument('--delay', dest='delay', type=float, default=None)
parser.add_argument('--loss', dest='loss', type=float, default=None)
parser.add_argument('--corrupt', dest='corrupt', type=float, default=None)
parser.add_argument('--duplicate', dest='duplicate', type=float, default=None)
parser.add_argument('--reorder', dest='reorder', type=float, default=None)
parser.add_argument('-d', dest='duration', type=int, default=0)

try:
    args = parser.parse_args()
except SystemExit:
    print("\n提示: -n 是必选参数")
    show_help()
    sys.exit(1)

args.mode_explicit = '-m' in sys.argv
args.mode = detect_mode(args)

if not validate_args(args):
    sys.exit(1)


class WeakNetMaker:
    """通过 tc netem 在指定网卡上制造弱网条件"""

    def __init__(self, logfile: str = "./net_err.log", netcard: str = "eth0"):
        self.logfile = logfile
        self.netcard = netcard
        self._cleaned = False

        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)

        self.print_log("logfile: " + logfile)
        self.print_log("netcard: " + netcard)
        self.print_log("net_error Start")

    def _signal_handler(self, signum, frame):
        self.print_log("Received termination signal, recovering network settings.")
        self.cleanup()
        sys.exit(0)

    def print_log(self, info: str):
        info = datetime.now().strftime("%Y-%m-%d %H:%M:%S") + ": " + info
        print(info)
        with open(self.logfile, 'a', encoding='utf-8') as file:
            file.write(info + '\n')

    def cleanup(self):
        """恢复网卡 tc 规则，可安全重复调用"""
        if self._cleaned:
            return
        self._cleaned = True
        self.net_recover(silent=True)
        self.print_log("net_error Stop")

    def _run_tc(self, tc_args, silent: bool = False) -> int:
        cmd = ["tc"] + tc_args
        if not silent:
            self.print_log(" ".join(cmd))
        kwargs = {}
        if silent:
            kwargs["stdout"] = subprocess.DEVNULL
            kwargs["stderr"] = subprocess.DEVNULL
        ret = subprocess.call(cmd, **kwargs)
        if ret != 0 and not silent:
            self.print_log("[错误] tc 执行失败, returncode=" + str(ret))
        return ret

    def _clear_qdisc(self, silent: bool = False):
        return self._run_tc(
            ["qdisc", "del", "dev", self.netcard, "root"],
            silent=silent,
        )

    def net_recover(self, silent: bool = False):
        if not silent:
            self.print_log("Recover from net control")
        self._clear_qdisc(silent=True)

    def _apply_netem(self, netem_opts: str) -> bool:
        self._clear_qdisc(silent=True)
        ret = self._run_tc(
            ["qdisc", "add", "dev", self.netcard, "root", "netem"] + netem_opts.split(),
        )
        return ret == 0

    def net_apply_custom(
        self,
        delay_ms=None,
        loss_pct=None,
        corrupt_pct=None,
        duplicate_pct=None,
        reorder_pct=None,
    ) -> bool:
        """按指定参数组合注入 netem 规则"""
        parts = []
        if delay_ms is not None:
            parts.append("delay " + str(delay_ms) + "ms")
        if loss_pct is not None:
            parts.append("loss " + str(loss_pct) + "%")
        if corrupt_pct is not None:
            parts.append("corrupt " + str(corrupt_pct) + "%")
        if duplicate_pct is not None:
            parts.append("duplicate " + str(duplicate_pct) + "%")
        if reorder_pct is not None:
            parts.append("reorder " + str(reorder_pct) + "%")
        if not parts:
            return False
        return self._apply_netem(" ".join(parts))

    def net_delay_ms(self, delay_time_ms: float = 100, be_random: bool = False):
        if be_random:
            delay_time_ms = random.uniform(0, 5000)
        self._apply_netem("delay " + str(delay_time_ms) + "ms")

    def net_packet_loss(self, loss_rate: float = 20, be_random: bool = False):
        if be_random:
            loss_rate = random.uniform(0, 20)
        self._apply_netem("loss " + str(loss_rate) + "%")

    def net_packet_corrupt(self, corrupt_rate: float = 10, be_random: bool = False):
        if be_random:
            corrupt_rate = random.uniform(0, 50)
        self._apply_netem("corrupt " + str(corrupt_rate) + "%")

    def net_packet_repeat(self, repeat_rate: float = 10, be_random: bool = False):
        if be_random:
            repeat_rate = random.uniform(0, 20)
        self._apply_netem("duplicate " + str(repeat_rate) + "%")

    def net_all_random(self):
        netem_opts = (
            "delay " + str(round(random.uniform(0, 5000))) + "ms "
            + "loss " + str(round(random.uniform(0, 10))) + "% "
            + "corrupt " + str(round(random.uniform(0, 10))) + "% "
            + "duplicate " + str(round(random.uniform(0, 10))) + "% "
            + "reorder " + str(round(random.uniform(0, 10))) + "% "
        )
        self._apply_netem(netem_opts)

    def fixed_mode(
        self,
        duration: int = 0,
        delay_ms=None,
        loss_pct=None,
        corrupt_pct=None,
        duplicate_pct=None,
        reorder_pct=None,
    ):
        """注入固定弱网参数；duration>0 则到时自动恢复退出"""
        desc = []
        if delay_ms is not None:
            desc.append("delay=" + str(delay_ms) + "ms")
        if loss_pct is not None:
            desc.append("loss=" + str(loss_pct) + "%")
        if corrupt_pct is not None:
            desc.append("corrupt=" + str(corrupt_pct) + "%")
        if duplicate_pct is not None:
            desc.append("duplicate=" + str(duplicate_pct) + "%")
        if reorder_pct is not None:
            desc.append("reorder=" + str(reorder_pct) + "%")
        self.print_log("Fixed net err start: " + ", ".join(desc))
        if duration > 0:
            self.print_log("Will last for " + str(duration) + " seconds")
        else:
            self.print_log("Will last until Ctrl+C")

        try:
            if not self.net_apply_custom(
                delay_ms, loss_pct, corrupt_pct, duplicate_pct, reorder_pct,
            ):
                self.print_log("[错误] 固定弱网规则下发失败")
                sys.exit(1)
            if duration > 0:
                time.sleep(duration)
            else:
                while True:
                    time.sleep(60)
        finally:
            self.cleanup()

    def random_mode(
        self,
        start_hour: int = 0,
        end_hour: int = 8,
        all_day: bool = False,
        check_interval: int = 30,
    ):
        """在指定时段内周期性注入随机弱网"""
        if all_day:
            self.print_log("Random net err start (all day)")
        else:
            self.print_log(
                "Random net err start at " + str(start_hour)
                + " o'clock, end at " + str(end_hour) + " o'clock"
            )

        being_err = False
        duration_time = 0.0
        start_time = datetime.now()

        try:
            while True:
                cur_time = datetime.now()
                in_window = all_day or (
                    cur_time.hour >= start_hour and cur_time.hour < end_hour
                )

                if (not being_err) and in_window:
                    start_time = cur_time
                    self.net_all_random()
                    duration_time = random.uniform(5 * 60, 30 * 60)
                    self.print_log(
                        "This net err rule will last for "
                        + str(int(duration_time)) + " seconds"
                    )
                    being_err = True

                if being_err:
                    elapsed = (cur_time - start_time).total_seconds()
                    if elapsed >= duration_time:
                        self.net_recover(silent=True)
                        being_err = False
                    elif (not all_day) and cur_time.hour >= end_hour:
                        self.net_recover(silent=True)
                        being_err = False

                if being_err and duration_time - elapsed < check_interval:
                    time.sleep(max(1, int(duration_time - elapsed)))
                else:
                    time.sleep(check_interval)
        finally:
            self.cleanup()


def main():
    maker = WeakNetMaker(logfile=args.logfile, netcard=args.netcard)
    if args.mode == 'fixed':
        maker.fixed_mode(
            duration=args.duration,
            delay_ms=args.delay,
            loss_pct=args.loss,
            corrupt_pct=args.corrupt,
            duplicate_pct=args.duplicate,
            reorder_pct=args.reorder,
        )
    else:
        maker.random_mode(
            start_hour=args.start_hour,
            end_hour=args.end_hour,
            all_day=args.all_day,
            check_interval=args.check_interval,
        )


if __name__ == "__main__":
    print("[配置]")
    print("  网卡: " + args.netcard)
    print("  模式: " + args.mode)
    print("  日志: " + args.logfile)

    if args.mode == 'random':
        if args.all_day:
            print("  时段: 全天")
        else:
            print("  时段: " + str(args.start_hour) + ":00 - " + str(args.end_hour) + ":00")
        print("  检查间隔: " + str(args.check_interval) + "秒")
    else:
        if args.delay is not None:
            print("  延时: " + str(args.delay) + " ms")
        if args.loss is not None:
            print("  丢包: " + str(args.loss) + "%")
        if args.corrupt is not None:
            print("  损坏: " + str(args.corrupt) + "%")
        if args.duplicate is not None:
            print("  重复: " + str(args.duplicate) + "%")
        if args.reorder is not None:
            print("  乱序: " + str(args.reorder) + "%")
        hold = "直到 Ctrl+C" if args.duration == 0 else str(args.duration) + "秒"
        print("  持续: " + hold)

    main()
