#!/usr/bin/env python3
"""
PCAP文件回放工具 - 读取PCAP文件，提取UDP包发送到目标地址
依赖: pip install scapy
"""

import socket
import sys
import time

def show_help():
    print("""
用法: python3 pcap_sender.py [-f <文件>] [-i <IP>] [-p <端口>] [-n <次数>] [-t <间隔>] [--preserve-timing] [-h]

选项:
  -f <文件>          PCAP文件路径
  -i <IP>            目标IP地址
  -p <端口>          目标端口
  -n <次数>          循环次数，-1为无限 (默认: 1)
  -t <间隔>          循环间隔秒数 (默认: 1.0)
  --preserve-timing  保留原始包时序
  -h                 显示帮助

示例:
  python3 pcap_sender.py -f test.pcap -i 192.165.56.184 -p 13000
  python3 pcap_sender.py -f test.pcap -i 127.0.0.1 -p 5000 -n -1 -t 2.0
  python3 pcap_sender.py -f test.pcap -i 127.0.0.1 -p 5000 --preserve-timing
""")

def replay_pcap(pcap_file, target_ip, target_port, loop_count=1, interval=1.0, preserve_timing=False):
    """回放PCAP文件"""
    # 延迟导入scapy，避免无参数时加载
    try:
        from scapy.all import rdpcap
        from scapy.layers.inet import UDP
    except ImportError:
        print("[错误] 缺少scapy库，请执行: pip install scapy")
        return

    # 检查文件
    import os
    if not os.path.exists(pcap_file):
        print(f"[错误] 文件不存在: {pcap_file}")
        return

    # 读取PCAP文件
    print(f"[读取] {pcap_file}")
    try:
        packets = rdpcap(pcap_file)
        print(f"[统计] 总包数: {len(packets)}")
    except Exception as e:
        print(f"[错误] 读取失败: {e}")
        return

    # 提取UDP包
    udp_packets = [pkt for pkt in packets if pkt.haslayer(UDP)]
    print(f"[统计] UDP包数: {len(udp_packets)}")

    if not udp_packets:
        print("[错误] 未找到UDP包")
        return

    # 显示配置
    print(f"[配置] 目标: {target_ip}:{target_port}")
    print(f"[配置] 循环: {'无限' if loop_count == -1 else f'{loop_count}次'}")
    print(f"[配置] 时序: {'保留' if preserve_timing else '快速'}")
    print("[提示] Ctrl+C 停止\n")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    current_loop = 0

    try:
        while loop_count == -1 or current_loop < loop_count:
            current_loop += 1
            print(f"[循环 {current_loop}] {'(无限模式)' if loop_count == -1 else f'({current_loop}/{loop_count})'}")

            packet_count = 0
            start_time = time.time()
            loop_start_time = time.time()

            if preserve_timing:
                first_packet_time = float(udp_packets[0].time)

            for i, packet in enumerate(udp_packets):
                try:
                    udp_layer = packet[UDP]
                    payload = bytes(udp_layer.payload)

                    # 保留时序模式
                    if preserve_timing and i > 0:
                        packet_time = float(packet.time)
                        time_since_first = packet_time - first_packet_time
                        elapsed = time.time() - loop_start_time
                        wait_time = time_since_first - elapsed
                        if wait_time > 0:
                            time.sleep(wait_time)

                    # 发送
                    sock.sendto(payload, (target_ip, target_port))
                    packet_count += 1

                    # 快速模式下微小延迟
                    if not preserve_timing and i % 100 == 0 and i > 0:
                        time.sleep(0.001)

                    # 进度显示
                    if (i + 1) % 100 == 0:
                        print(f"  进度: {i + 1}/{len(udp_packets)}")

                except Exception as e:
                    print(f"[错误] 包 {i}: {e}")
                    continue

            # 统计
            duration = time.time() - start_time
            pps = packet_count / duration if duration > 0 else 0
            print(f"[完成] {packet_count}包, {duration:.2f}秒, {pps:.1f}包/秒")

            # 循环间隔
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
    # 无参数或帮助模式时显示帮助
    if len(sys.argv) == 1 or '-h' in sys.argv:
        show_help()
        sys.exit(0)

    import argparse
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument('-f', dest='file', required=True)
    parser.add_argument('-i', dest='ip', required=True)
    parser.add_argument('-p', dest='port', type=int, required=True)
    parser.add_argument('-n', dest='loop', type=int, default=1)
    parser.add_argument('-t', dest='interval', type=float, default=1.0)
    parser.add_argument('--preserve-timing', dest='preserve', action='store_true')

    args = parser.parse_args()
    replay_pcap(args.file, args.ip, args.port, args.loop, args.interval, args.preserve)