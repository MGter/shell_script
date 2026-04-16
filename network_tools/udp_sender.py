#!/usr/bin/env python3
"""
UDP发送工具 - 支持TS流按码率发送和PCAP回放
依赖: pip install scapy (仅PCAP模式需要)
"""

import os
import sys
import socket
import time

def show_help():
    print("""
用法: python3 udp_sender.py [-f <文件>] [-i <IP>] [-p <端口>] [-b <码率>] [-n <次数>] [-t <间隔>] [--preserve-timing] [-h]

选项:
  -f <文件>          输入: TS流文件或PCAP文件 (必选)
  -i <IP>            目标: 发送IP地址 (必选)
  -p <端口>          目标: 发送端口 (必选)
  -b <码率>          配置: TS模式比特率 bps (TS文件必选)
  -n <次数>          配置: 循环次数，-1为无限 (默认: 1)
  -t <间隔>          配置: PCAP模式循环间隔秒数 (默认: 1.0)
  --preserve-timing  配置: PCAP模式保留原始包时序
  -h                 显示帮助信息

模式说明:
  .ts文件  → 按码率发送，需指定 -b
  .pcap文件 → 回放模式，可选 --preserve-timing

示例:
  # TS流按码率发送
  python3 udp_sender.py -f test.ts -i 127.0.0.1 -p 5000 -b 16600000
  python3 udp_sender.py -f test.ts -i 192.168.1.1 -p 30000 -b 8000000 -n 5

  # PCAP回放
  python3 udp_sender.py -f test.pcap -i 192.165.56.184 -p 13000
  python3 udp_sender.py -f test.pcap -i 127.0.0.1 -p 5000 -n -1 -t 2.0
  python3 udp_sender.py -f test.pcap -i 127.0.0.1 -p 5000 --preserve-timing
""")

def send_ts(input_file, ip, port, bitrate, loop=1, packet_size=1316):
    """TS流按码率发送"""
    print(f"[模式] TS流按码率发送")
    print(f"[配置] 文件: {input_file}")
    print(f"[配置] 目标: {ip}:{port}")
    print(f"[配置] 码率: {bitrate} bps ({bitrate/8/1024:.1f} KB/s)")
    print(f"[配置] 循环: {'无限' if loop == -1 else f'{loop}次'}")
    print("[提示] Ctrl+C 停止\n")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    with open(input_file, 'rb') as f:
        data = f.read()

    bytes_per_second = bitrate / 8
    time_per_packet = packet_size / bytes_per_second
    loop_count = 1 if loop == -1 else loop

    current_loop = 0
    try:
        while loop == -1 or current_loop < loop_count:
            current_loop += 1
            print(f"[循环 {current_loop}] {'(无限)' if loop == -1 else f'({current_loop}/{loop})'}")

            start_time = time.time()
            for i in range(0, len(data), packet_size):
                packet = data[i:i + packet_size]
                sock.sendto(packet, (ip, port))
                time.sleep(time_per_packet)

            duration = time.time() - start_time
            print(f"[完成] {duration:.2f}秒")

    except KeyboardInterrupt:
        print("\n[停止] 用户中断")
    finally:
        sock.close()
        print(f"\n[结束] 完成 {current_loop} 次")

def send_pcap(pcap_file, ip, port, loop_count=1, interval=1.0, preserve_timing=False):
    """PCAP文件回放"""
    try:
        from scapy.all import rdpcap
        from scapy.layers.inet import UDP
    except ImportError:
        print("[错误] PCAP模式需要scapy，请执行: pip install scapy")
        return

    print(f"[模式] PCAP回放")
    print(f"[读取] {pcap_file}")
    try:
        packets = rdpcap(pcap_file)
        print(f"[统计] 总包数: {len(packets)}")
    except Exception as e:
        print(f"[错误] 读取失败: {e}")
        return

    udp_packets = [pkt for pkt in packets if pkt.haslayer(UDP)]
    print(f"[统计] UDP包数: {len(udp_packets)}")

    if not udp_packets:
        print("[错误] 未找到UDP包")
        return

    print(f"[配置] 目标: {ip}:{port}")
    print(f"[配置] 循环: {'无限' if loop_count == -1 else f'{loop_count}次'}")
    print(f"[配置] 时序: {'保留' if preserve_timing else '快速'}")
    print("[提示] Ctrl+C 停止\n")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    current_loop = 0

    try:
        while loop_count == -1 or current_loop < loop_count:
            current_loop += 1
            print(f"[循环 {current_loop}] {'(无限)' if loop_count == -1 else f'({current_loop}/{loop_count})'}")

            packet_count = 0
            start_time = time.time()
            loop_start_time = time.time()

            if preserve_timing:
                first_packet_time = float(udp_packets[0].time)

            for i, packet in enumerate(udp_packets):
                try:
                    udp_layer = packet[UDP]
                    payload = bytes(udp_layer.payload)

                    if preserve_timing and i > 0:
                        packet_time = float(packet.time)
                        time_since_first = packet_time - first_packet_time
                        elapsed = time.time() - loop_start_time
                        wait_time = time_since_first - elapsed
                        if wait_time > 0:
                            time.sleep(wait_time)

                    sock.sendto(payload, (ip, port))
                    packet_count += 1

                    if not preserve_timing and i % 100 == 0 and i > 0:
                        time.sleep(0.001)

                    if (i + 1) % 100 == 0:
                        print(f"  进度: {i + 1}/{len(udp_packets)}")

                except Exception as e:
                    print(f"[错误] 包 {i}: {e}")
                    continue

            duration = time.time() - start_time
            pps = packet_count / duration if duration > 0 else 0
            print(f"[完成] {packet_count}包, {duration:.2f}秒, {pps:.1f}包/秒")

            if loop_count == -1 or current_loop < loop_count:
                if interval > 0:
                    print(f"[等待] {interval}秒...")
                    time.sleep(interval)

    except KeyboardInterrupt:
        print("\n[停止] 用户中断")
    finally:
        sock.close()
        print(f"\n[结束] 完成 {current_loop} 次循环")

if __name__ == "__main__":
    if len(sys.argv) == 1 or '-h' in sys.argv:
        show_help()
        sys.exit(0)

    import argparse
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument('-f', dest='file', required=True)
    parser.add_argument('-i', dest='ip', required=True)
    parser.add_argument('-p', dest='port', type=int, required=True)
    parser.add_argument('-b', dest='bitrate', type=int)
    parser.add_argument('-n', dest='loop', type=int, default=1)
    parser.add_argument('-t', dest='interval', type=float, default=1.0)
    parser.add_argument('--preserve-timing', dest='preserve', action='store_true')

    args = parser.parse_args()

    # 检查文件
    if not os.path.exists(args.file):
        print(f"[错误] 文件不存在: {args.file}")
        sys.exit(1)

    # 根据文件类型选择模式
    if args.file.endswith('.ts'):
        if not args.bitrate:
            print("[错误] TS文件需要指定码率 -b")
            sys.exit(1)
        send_ts(args.file, args.ip, args.port, args.bitrate, args.loop)
    elif args.file.endswith('.pcap'):
        send_pcap(args.file, args.ip, args.port, args.loop, args.interval, args.preserve)
    else:
        print("[错误] 支持的文件格式: .ts, .pcap")
        sys.exit(1)