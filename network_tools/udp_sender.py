#!/usr/bin/env python3
"""
UDP TS流发送工具 - 按指定码率发送TS文件
"""

import os
import sys
import socket
import time

def show_help():
    print("""
用法: python3 udp_sender.py [-f <文件>] [-i <IP>] [-p <端口>] [-b <码率>] [-n <次数>] [-h]

选项:
  -f <文件>   输入: TS流文件路径 (必选)
  -i <IP>     目标: 发送IP地址 (必选)
  -p <端口>   目标: 发送端口 (必选)
  -b <码率>   配置: 比特率 bps (必选)
  -n <次数>   配置: 循环次数，-1为无限 (默认: 1)
  -h          显示帮助信息

示例:
  python3 udp_sender.py -f test.ts -i 127.0.0.1 -p 5000 -b 16600000
  python3 udp_sender.py -f test.ts -i 192.168.1.1 -p 30000 -b 8000000 -n 5
""")

def send_udp(input_file, ip, port, bitrate, loop=1, packet_size=1316):
    """按码率发送UDP"""

    if not os.path.exists(input_file):
        print(f"[错误] 文件不存在: {input_file}")
        return False

    if not input_file.endswith('.ts'):
        print("[警告] 文件不是.ts格式")

    if port < 1 or port > 65535:
        print("[错误] 端口范围: 1-65535")
        return False

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

if __name__ == "__main__":
    # 无参数或帮助模式
    if len(sys.argv) == 1 or '-h' in sys.argv:
        show_help()
        sys.exit(0)

    import argparse
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument('-f', dest='file', required=True)
    parser.add_argument('-i', dest='ip', required=True)
    parser.add_argument('-p', dest='port', type=int, required=True)
    parser.add_argument('-b', dest='bitrate', type=int, required=True)
    parser.add_argument('-n', dest='loop', type=int, default=1)

    args = parser.parse_args()
    send_udp(args.file, args.ip, args.port, args.bitrate, args.loop)