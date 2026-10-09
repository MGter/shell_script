#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ffmpeg多端口UDP推流工具 (Python版)

后台把TS流文件循环推到UDP，支持端口递增多路推流。
是 ffmpeg_push.sh 的等价升级版: 参数兼容，并额外提供状态查看、日志跟踪、
残留进程清理、Windows 支持。

状态文件保存在脚本同目录的 .ffmpeg_push/ 下:
    .ffmpeg_push/pid/<任务名>.pid    进程号 + 启动时间 + 实际执行的命令
    .ffmpeg_push/logs/<任务名>.log   ffmpeg 的全部输出
任务名 = 文件名_端口，例如 input_30000、input_30001
"""

import os
import re
import sys
import json
import time
import shutil
import signal
import threading
import subprocess
from datetime import datetime
from pathlib import Path

# ------------------------------------------------------------ 固定参数
PKT_SIZE = 1316              # -pkt_size 1316 = 7 * 188
STATE_DIR = ".ffmpeg_push"   # 状态目录，放在脚本同目录
FILE_DIR = "file"            # -f 只写文件名时，也会到这个子目录里找
FFMPEG = os.environ.get("FFMPEG", "ffmpeg")
BAD_NAME = re.compile(r"[^0-9A-Za-z._-]+")
IPV4 = re.compile(r"^\d+\.\d+\.\d+\.\d+$")

BASE_DIR = Path(__file__).resolve().parent
PID_DIR = BASE_DIR / STATE_DIR / "pid"
LOG_DIR = BASE_DIR / STATE_DIR / "logs"


def show_help():
    print("""
用法: python3 ffmpeg_push.py [-f <文件>] [-i <IP>] [-p <端口>] [-n <次数>] [--local-ip <IP>] [-s] [-h]

选项:
  -f <文件>          输入: TS流文件路径 (必选)
  -i <IP>            目标: 推流IP地址 (必选)
  -p <端口>          目标: 推流起始端口 (必选)
  -n <次数>          配置: 推流数量，端口依次递增 (默认: 1)
  --local-ip <IP>    配置: 本机发送地址，对应 ffmpeg -localaddr (默认: 不绑定)
  -s                 操作: 停止所有推流进程
  --status           操作: 查看推流状态
  --logs             操作: 查看日志 (配合 --follow 实时跟踪)
  --follow           配置: 日志实时跟踪
  --name <名字>      配置: 只查看指定任务 (配合 --logs/--status)
  --lines <行数>     配置: --logs 显示最后N行 (默认: 30)
  --dry-run          配置: 只打印命令，不启动
  --force            配置: 任务已在运行时也重新启动
  --foreground       配置: 前台运行，Ctrl+C 停止
  -h                 显示帮助信息

实际执行的命令 (-c copy 纯转发，不转码):
  ffmpeg -stream_loop -1 -re -i <文件> -c copy -f mpegts -pkt_size 1316 \\
         [-localaddr <本机地址>] udp://<目标IP>:<端口>

示例:
  # 推 5 路，端口 30000-30004
  python3 ffmpeg_push.py -f input.ts -i 127.0.0.1 -p 30000 -n 5

  # 指定本机发送地址，推单路
  python3 ffmpeg_push.py -f input.ts -i 192.165.52.185 -p 40000 --local-ip 192.165.153.122

  # 只看将要执行的命令
  python3 ffmpeg_push.py -f input.ts -i 127.0.0.1 -p 30000 --dry-run

  # 查看状态 / 日志 / 停止
  python3 ffmpeg_push.py --status
  python3 ffmpeg_push.py --logs --follow
  python3 ffmpeg_push.py -s
""")


# ------------------------------------------------------------ 工具函数

def safe_name(name):
    return BAD_NAME.sub("_", str(name)).strip("_") or "task"


def now_str():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def fmt_cmd(cmd):
    if os.name == "nt" and hasattr(subprocess, "list2cmdline"):
        return subprocess.list2cmdline(cmd)
    return " ".join(_quote(c) for c in cmd)      # shlex.join 要 3.8+，这里手动拼


def _quote(text):
    if re.match(r"^[0-9A-Za-z_.,:/=@+-]+$", str(text)):
        return str(text)
    return "'" + str(text).replace("'", "'\\''") + "'"


def resolve_file(name):
    """-f 的查找顺序: 当前目录/绝对路径 -> 脚本目录 -> 脚本目录/file/。"""
    text = str(name or "").strip()
    if not text:
        return None
    p = Path(text)
    candidates = [p] if p.is_absolute() else [p, BASE_DIR / p, BASE_DIR / FILE_DIR / p]
    if not p.suffix:
        candidates.append(BASE_DIR / FILE_DIR / (p.name + ".ts"))
    for c in candidates:
        if c.is_file():
            return os.path.normpath(str(c))

    folder = BASE_DIR / FILE_DIR
    avail = []
    if folder.is_dir():
        avail = sorted(x.name for x in folder.iterdir() if x.is_file())[:12]
    hint = ("\n" + FILE_DIR + "/ 里现有: " + ", ".join(avail)) if avail else ""
    print("[错误] 找不到文件: " + text + hint)
    return None


def pid_path(name):
    return PID_DIR / (safe_name(name) + ".pid")


def log_path(name):
    return LOG_DIR / (safe_name(name) + ".log")


def read_pid(path):
    try:
        with open(str(path), "r", encoding="utf-8") as fh:
            info = json.loads(fh.read())
        info["pid"] = int(info["pid"])
        return info
    except (OSError, ValueError, KeyError, TypeError):
        return None


def write_pid(path, info):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(str(path), "w", encoding="utf-8", newline="\n") as fh:
        fh.write(json.dumps(info, ensure_ascii=False, indent=2))


def unlink(path):
    """删文件，不存在就算了 (Path.unlink(missing_ok=) 要 3.8+)。"""
    try:
        path.unlink()
    except OSError:
        pass


def pid_alive(pid):
    """跨平台判断进程是否还活着 (Windows 上不能用 os.kill(pid, 0)，那会杀掉进程)。"""
    if not pid or pid <= 0:
        return False
    if os.name == "nt":
        import ctypes
        from ctypes import wintypes

        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        k32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        k32.OpenProcess.restype = wintypes.HANDLE
        k32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
        k32.WaitForSingleObject.restype = wintypes.DWORD
        k32.CloseHandle.argtypes = [wintypes.HANDLE]
        SYNCHRONIZE, QUERY_LIMITED = 0x00100000, 0x1000
        WAIT_TIMEOUT = 0x102
        handle = k32.OpenProcess(SYNCHRONIZE | QUERY_LIMITED, False, int(pid))
        if not handle:
            return ctypes.get_last_error() == 5      # 5 = 权限不足，说明进程还在
        try:
            return k32.WaitForSingleObject(handle, 0) == WAIT_TIMEOUT
        finally:
            k32.CloseHandle(handle)
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def wait_dead(pid, timeout):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not pid_alive(pid):
            return True
        time.sleep(0.1)
    return not pid_alive(pid)


def terminate_win(pid):
    """taskkill 被拒 (权限/沙箱) 时的兜底。"""
    import ctypes
    from ctypes import wintypes

    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    k32.OpenProcess.restype = wintypes.HANDLE
    k32.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
    k32.TerminateProcess.restype = wintypes.BOOL
    k32.CloseHandle.argtypes = [wintypes.HANDLE]
    handle = k32.OpenProcess(0x0001, False, int(pid))       # PROCESS_TERMINATE
    if not handle:
        return False
    try:
        return bool(k32.TerminateProcess(handle, 1))
    finally:
        k32.CloseHandle(handle)


def kill_pid(pid):
    """停掉一个进程，返回最终是否真的停了。

    POSIX: 先 SIGTERM 让它自己收尾，5 秒不退再 SIGKILL。
    Windows: 先 taskkill /T /F (连子进程一起)，失败用 TerminateProcess 兜底。
    """
    if os.name == "nt":
        try:
            subprocess.run(["taskkill", "/PID", str(pid), "/T", "/F"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except OSError:
            pass
        if wait_dead(pid, 2.0):
            return True
        terminate_win(pid)
        return wait_dead(pid, 3.0)
    try:
        os.kill(pid, signal.SIGTERM)
    except OSError:
        pass
    if wait_dead(pid, 5.0):
        return True
    try:
        os.kill(pid, signal.SIGKILL)
    except OSError:
        pass
    return wait_dead(pid, 3.0)


def scan_states(name=None):
    """扫描状态目录里所有任务，返回 [(名字, 状态, pid, info)]。

    启动参数不同的任务名字也不同 (文件名_端口)，所以扫目录就能看到全部遗留任务。
    """
    out = []
    if not PID_DIR.is_dir():
        return out
    for f in sorted(PID_DIR.glob("*.pid")):
        task_name = f.stem
        if name and task_name != safe_name(name):
            continue
        info = read_pid(f)
        if not info:
            unlink(f)
            continue
        alive = pid_alive(info["pid"])
        out.append((info.get("name") or task_name,
                    "running" if alive else "stale",
                    info["pid"], info))
    return out


def display_width(text):
    """粗略显示宽度: 中日韩字符按 2 列算。"""
    return sum(2 if ord(ch) > 0x2E7F else 1 for ch in str(text))


def pad(text, width):
    return str(text) + " " * max(0, width - display_width(text))


# ------------------------------------------------------------ 子命令

def build_cmd(input_file, ip, port, local_ip):
    """拼 ffmpeg 命令。-pkt_size / -localaddr 这类协议选项必须写在输出 URL 之前。"""
    cmd = [FFMPEG, "-stream_loop", "-1", "-re", "-i", input_file,
           "-c", "copy", "-f", "mpegts", "-pkt_size", str(PKT_SIZE)]
    if local_ip:
        cmd += ["-localaddr", local_ip]
    cmd += ["udp://%s:%d" % (ip, port)]
    return cmd


def cmd_start(args):
    input_file = resolve_file(args.file)
    if not input_file:
        return 1
    if not IPV4.match(args.ip):
        print("[错误] -i 必须是 IPv4 地址，例如 127.0.0.1 (不要带 udp://)")
        return 1
    if args.local_ip and not IPV4.match(args.local_ip):
        print("[错误] --local-ip 必须是 IPv4 地址")
        return 1
    if not 1 <= args.port <= 65535:
        print("[错误] -p 端口必须在 1-65535 之间，现在是 %d" % args.port)
        return 1
    if args.count < 1:
        print("[错误] -n 次数至少是 1，现在是 %d" % args.count)
        return 1
    if args.port + args.count - 1 > 65535:
        print("[错误] 端口不够用: %d + %d 会超过 65535" % (args.port, args.count))
        return 1

    stem = Path(input_file).stem
    tasks = []
    for i in range(args.count):
        port = args.port + i
        name = safe_name("%s_%d" % (stem, port))
        tasks.append({"name": name, "input": input_file, "ip": args.ip,
                      "port": port, "local_ip": args.local_ip,
                      "url": "udp://%s:%d" % (args.ip, port)})

    if args.dry_run:
        for t in tasks:
            print("# %s   日志: %s" % (t["name"], log_path(t["name"])))
            print(fmt_cmd(build_cmd(t["input"], t["ip"], t["port"], t["local_ip"])))
        return 0

    if not args.foreground and not (shutil.which(FFMPEG) or Path(FFMPEG).exists()):
        print("[错误] 找不到 ffmpeg (FFMPEG=%s): 请装好 ffmpeg 或设置 FFMPEG 环境变量" % FFMPEG)
        return 127
    if args.foreground:
        return run_foreground(tasks)

    print("[配置] 文件: %s" % input_file)
    print("[配置] 目标: %s:%d - %d" % (args.ip, args.port, args.port + args.count - 1))
    print("[配置] 数量: %d   本机地址: %s" % (args.count, args.local_ip or "不绑定"))
    print("----------------------------------------")

    started = failed = 0
    for t in tasks:
        cmd = build_cmd(t["input"], t["ip"], t["port"], t["local_ip"])
        pf, lf = pid_path(t["name"]), log_path(t["name"])
        info = read_pid(pf) if pf.is_file() else None
        if info and pid_alive(info["pid"]) and not args.force:
            print("[跳过] %s: 已在运行 (pid %s)，要重启请加 --force" % (t["name"], info["pid"]))
            continue

        lf.parent.mkdir(parents=True, exist_ok=True)
        try:
            with open(str(lf), "a", encoding="utf-8", errors="replace", newline="\n") as fh:
                fh.write("\n===== %s 启动 =====\n%s\n" % (now_str(), fmt_cmd(cmd)))
                fh.flush()
                kwargs = dict(stdin=subprocess.DEVNULL, stdout=fh,
                              stderr=subprocess.STDOUT, close_fds=True)
                if os.name == "nt":
                    # 脱离控制台: 关掉终端 / 退出登录都不会把 ffmpeg 带走
                    kwargs["creationflags"] = (subprocess.DETACHED_PROCESS
                                               | subprocess.CREATE_NEW_PROCESS_GROUP)
                else:
                    kwargs["start_new_session"] = True
                proc = subprocess.Popen(cmd, **kwargs)
        except OSError as exc:
            print("[错误] 启动失败 %s: %s" % (t["name"], exc))
            failed += 1
            continue

        write_pid(pf, {"pid": proc.pid, "name": t["name"], "input": t["input"],
                       "url": t["url"], "local_ip": t["local_ip"],
                       "started_at": now_str(), "cmd": cmd})

        time.sleep(0.15)
        if proc.poll() is None:
            print("[启动] %-24s pid=%-7s -> %s" % (t["name"], proc.pid, t["url"]))
            started += 1
        else:
            print("[错误] %s: ffmpeg 立即退出 (code=%s)，请看日志: %s"
                  % (t["name"], proc.poll(), lf))
            failed += 1

    print("----------------------------------------")
    if started:
        print("[完成] 已启动 %d 路 (后台运行)。查看状态: python3 %s --status"
              % (started, os.path.basename(__file__)))
        print("[提示] 停止推流: python3 %s -s" % os.path.basename(__file__))
    return 1 if failed else 0


def cmd_stop(args):
    states = scan_states(args.name)
    if not states:
        print("[提示] 没有正在推流的任务")
        return 0

    stopped = failed = 0
    for name, state, pid, _info in states:
        pf = pid_path(name)
        if state == "stale":
            unlink(pf)
            print("[清理] %s: 残留 pid 文件 (进程 %s 已不存在)" % (name, pid))
            continue
        if not kill_pid(pid):
            print("[错误] 停止失败 %s (pid %s): 进程还在，pid 文件保留" % (name, pid))
            failed += 1
            continue
        unlink(pf)
        print("[停止] %s (pid %d)" % (name, pid))
        stopped += 1

    if stopped:
        print("[完成] 已停止 %d 路" % stopped)
    return 1 if failed else 0


def cmd_status(args):
    states = scan_states(args.name)
    if not states:
        print("[提示] 没有任务")
        return 0

    rows = []
    for name, state, pid, info in states:
        rows.append((name,
                     "运行中" if state == "running" else "残留",
                     str(pid),
                     info.get("started_at", "-"),
                     info.get("url", "-"),
                     Path(info.get("input", "")).name or "-"))

    head = ("名称", "状态", "PID", "启动时间", "目标", "输入文件")
    widths = [max(display_width(head[i]),
                  max(display_width(r[i]) for r in rows)) for i in range(len(head))]
    line = "  ".join(pad(head[i], widths[i]) for i in range(len(head)))
    print(line)
    print("-" * len(line))
    for r in rows:
        print("  ".join(pad(r[i], widths[i]) for i in range(len(r))))

    running = sum(1 for r in rows if r[1] == "运行中")
    print("\n共 %d 路，运行中 %d 路。日志目录: %s" % (len(rows), running, LOG_DIR))
    return 0


def cmd_logs(args):
    states = scan_states(args.name)
    if not states:
        print("[提示] 没有任务")
        return 0
    if args.follow and len(states) > 1:
        print("[错误] 有多路任务，--follow 请用 --name 指定一路。可用: %s"
              % ", ".join(s[0] for s in states))
        return 2

    for name, _state, _pid, _info in states:
        lf = log_path(name)
        if not lf.is_file():
            print("[提示] %s: 还没有日志 (%s)" % (name, lf))
            continue
        with open(str(lf), "r", encoding="utf-8", errors="replace") as fh:
            if len(states) > 1:
                print("\n===== %s =====" % name)
            sys.stdout.write("".join(fh.readlines()[-max(1, args.lines):]))
            sys.stdout.flush()
            if args.follow:
                print("\n--- 实时跟踪 %s (Ctrl+C 退出) ---" % name)
                try:
                    while True:
                        chunk = fh.readline()
                        if chunk:
                            sys.stdout.write(chunk)
                            sys.stdout.flush()
                        else:
                            time.sleep(0.3)
                except KeyboardInterrupt:
                    print()
    return 0


# ------------------------------------------------------ 前台运行 (systemd)

def run_foreground(tasks):
    procs = []
    lock = threading.Lock()
    rcs = {}
    stopping = threading.Event()

    def supervise(task):
        cmd = build_cmd(task["input"], task["ip"], task["port"], task["local_ip"])
        kwargs = {}
        if os.name == "nt":
            kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
        else:
            kwargs["start_new_session"] = True
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                universal_newlines=True, bufsize=1, **kwargs)
        with lock:
            procs.append(proc)
        for line in proc.stdout:
            if not stopping.is_set():
                print("[%s] %s" % (task["name"], line.rstrip()), flush=True)
        rcs[task["name"]] = proc.wait()

    print("[提示] 前台运行中，Ctrl+C 停止 ...")
    threads = [threading.Thread(target=supervise, args=(t,), daemon=True) for t in tasks]

    # systemd 停服务发的是 SIGTERM，默认处理会直接结束进程、跳过 finally，
    # 把 ffmpeg 子进程留成孤儿。这里把 SIGTERM/SIGINT 都转成 KeyboardInterrupt，
    # 走同一条清理路径。signal.signal 只能在主线程调用，此处正是主线程。
    old_handlers = {}

    def on_signal(signum, frame):
        raise KeyboardInterrupt

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            old_handlers[sig] = signal.signal(sig, on_signal)
        except (ValueError, OSError, AttributeError):
            pass

    for t in threads:
        t.start()
    try:
        while any(t.is_alive() for t in threads):
            for t in threads:
                t.join(0.3)
    except KeyboardInterrupt:
        print("\n[提示] 收到停止信号，正在停止 ...", file=sys.stderr)
        stopping.set()
        terminate_all(procs, lock)
    finally:
        terminate_all(procs, lock)
        for t in threads:
            t.join(5)
        for sig, handler in old_handlers.items():
            try:
                signal.signal(sig, handler)
            except (ValueError, OSError):
                pass

    bad = [("%s=%s" % (n, c)) for n, c in rcs.items() if c not in (0, None)]
    if bad and not stopping.is_set():       # 主动停止时子进程必然非零码，别报成异常
        print("[错误] 异常退出: " + ", ".join(bad))
        return 1
    return 0


def terminate_all(procs, lock):
    with lock:
        snapshot = list(procs)
    for p in snapshot:
        if p.poll() is None:
            try:
                if os.name == "nt" and hasattr(signal, "CTRL_BREAK_EVENT"):
                    p.send_signal(signal.CTRL_BREAK_EVENT)
                else:
                    p.terminate()
            except (OSError, ValueError):
                pass
    deadline = time.monotonic() + 5
    for p in snapshot:
        while p.poll() is None and time.monotonic() < deadline:
            time.sleep(0.05)
        if p.poll() is None:
            try:
                p.kill()
            except OSError:
                pass


if __name__ == "__main__":
    if len(sys.argv) == 1 or "-h" in sys.argv or "--help" in sys.argv:
        show_help()
        sys.exit(0)

    import argparse

    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("-f", dest="file", help="输入: TS流文件路径")
    parser.add_argument("-i", dest="ip", help="目标: 推流IP地址")
    parser.add_argument("-p", dest="port", type=int, help="目标: 推流起始端口")
    parser.add_argument("-n", dest="count", type=int, default=1, help="配置: 推流数量")
    parser.add_argument("--local-ip", dest="local_ip", default="", help="配置: 本机发送地址")
    parser.add_argument("-s", dest="stop", action="store_true", help="操作: 停止所有推流")
    parser.add_argument("--status", dest="status", action="store_true", help="操作: 查看状态")
    parser.add_argument("--logs", dest="logs", action="store_true", help="操作: 查看日志")
    parser.add_argument("--follow", dest="follow", action="store_true", help="配置: 日志实时跟踪")
    parser.add_argument("--name", dest="name", default=None, help="配置: 指定任务名")
    parser.add_argument("--lines", dest="lines", type=int, default=30, help="配置: 日志行数")
    parser.add_argument("--dry-run", dest="dry_run", action="store_true", help="配置: 只打印命令")
    parser.add_argument("--force", dest="force", action="store_true", help="配置: 强制重启")
    parser.add_argument("--foreground", dest="foreground", action="store_true", help="配置: 前台运行")
    args = parser.parse_args()

    if args.stop:
        sys.exit(cmd_stop(args))
    if args.status:
        sys.exit(cmd_status(args))
    if args.logs:
        sys.exit(cmd_logs(args))

    # 启动模式: -f / -i / -p 必选
    missing = [opt for opt, val in (("-f", args.file), ("-i", args.ip), ("-p", args.port)) if not val]
    if missing:
        print("[错误] 缺少必要参数: %s" % ", ".join(missing))
        show_help()
        sys.exit(1)
    sys.exit(cmd_start(args))
