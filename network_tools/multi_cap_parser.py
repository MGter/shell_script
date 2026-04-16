#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
文件名: multi_cap_parser.py
功能: 多端口网络抓包及TS流分析工具
描述: 配置指定参数，可以实现并行抓包+解析ts文件时间戳，用以对比
依赖:
    1. tcpdump, ffprobe (系统工具)
    2. scapy (pip install scapy)
创建人: MGter
"""

import os
import sys
import time
import argparse
import subprocess
from pathlib import Path
from scapy.all import rdpcap
from scapy.layers.inet import UDP

def show_help():
    """显示帮助信息"""
    print("""
用法: python3 multi_cap_parser.py [-i <IP>] [-p <端口>] [-d <时长>] [-t <任务名>] [-o <目录>] [-h]

选项:
  -i <IP>       目标IP地址
  -p <端口>     目标端口列表，逗号分隔 (例: 30000,30001,30002)
  -d <时长>     抓包持续时间，秒 (默认: 10)
  -t <任务名>   任务名称 (默认: task00)
  -o <目录>     输出目录 (默认: ./captures)
  -h            显示帮助

示例:
  python3 multi_cap_parser.py -i 192.165.58.221 -p 30000,30001,30002 -d 15
  python3 multi_cap_parser.py -i 127.0.0.1 -p 5000 -d 5 -t mytest
""")

def capture(duration: int, ip: str, port: int, output: str) -> bool:
    """执行网络抓包"""
    try:
        pattern = f"dst host {ip} and port {port}"
        cmd = ["timeout", str(duration), "tcpdump", "-i", "any", pattern, "-w", output]
        print(f"[抓包] {ip}:{port} -> {output}")
        subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
        return True
    except Exception as e:
        print(f"[错误] 抓包失败: {e}")
        return False

def extract_udp_payload(input_pcap: str, output_file: str) -> bool:
    """从PCAP文件提取UDP负载"""
    try:
        packets = rdpcap(input_pcap)
        with open(output_file, 'wb') as f:
            for pkt in packets:
                if pkt.haslayer(UDP):
                    f.write(bytes(pkt[UDP].payload))
        print(f"[提取] {input_pcap} -> {output_file}")
        return True
    except Exception as e:
        print(f"[错误] 提取失败 {input_pcap}: {e}")
        return False

def parse_video_frameinfo(ts_file: str, output_csv: str) -> bool:
    """解析TS文件时间戳"""
    try:
        with open(output_csv, 'w') as out_file:
            subprocess.run(
                ["ffprobe", "-loglevel", "error", "-select_streams", "v:0",
                 "-show_entries", "frame=pict_type,pts_time", "-of", "csv=p=0", str(ts_file)],
                stdout=out_file, stderr=subprocess.DEVNULL, check=True
            )
        print(f"[解析] {ts_file} -> {output_csv}")
        return True
    except subprocess.CalledProcessError:
        print(f"[错误] 解析失败 {ts_file}")
        return False

def main(ip: str, ports: list, duration: int, task_name: str, save_path: str):
    pcap_list = []
    ts_list = []

    # 设置工作目录
    os.makedirs(save_path, exist_ok=True)
    os.chdir(save_path)
    print(f"[目录] {os.getcwd()}")

    # 阶段1: 启动抓包
    print(f"\n[阶段1] 启动抓包，目标: {ip}")
    for port in ports:
        output_file = f"{task_name}_{ip}_{port}.pcap"
        capture(duration, ip, port, output_file)
        pcap_list.append(output_file)

    # 阶段2: 等待抓包完成
    print(f"\n[阶段2] 等待抓包完成 ({duration}秒)")
    for i in range(duration + 1):
        time.sleep(1)
        print(f"  进度: {i}/{duration}")

    # 阶段3: 提取UDP负载
    print(f"\n[阶段3] 提取UDP负载")
    for pcap_file in pcap_list:
        ts_file = Path(pcap_file).with_suffix(".ts")
        extract_udp_payload(pcap_file, str(ts_file))
        ts_list.append(ts_file)

    # 阶段4: 解析时间戳
    print(f"\n[阶段4] 解析时间戳")
    for ts_file in ts_list:
        csv_file = Path(ts_file).with_suffix(".csv")
        parse_video_frameinfo(str(ts_file), str(csv_file))

    # 阶段5: 文件归类
    print(f"\n[阶段5] 文件归类")
    os.makedirs("00_pcap_file", exist_ok=True)
    os.makedirs("01_ts_file", exist_ok=True)
    subprocess.run("mv *.pcap 00_pcap_file/", shell=True)
    subprocess.run("mv *.ts 01_ts_file/", shell=True)
    subprocess.run("rm -f nohup.out", shell=True)

    print(f"\n[完成] 处理 {len(pcap_list)} 个端口")

if __name__ == "__main__":
    # 无参数时显示帮助
    if len(sys.argv) == 1:
        show_help()
        sys.exit(0)

    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument('-i', dest='ip', required=True)
    parser.add_argument('-p', dest='ports', required=True)
    parser.add_argument('-d', dest='duration', type=int, default=10)
    parser.add_argument('-t', dest='task', default='task00')
    parser.add_argument('-o', dest='output', default='./captures')
    parser.add_argument('-h', dest='help', action='store_true')

    args = parser.parse_args()

    if args.help:
        show_help()
        sys.exit(0)

    # 解析端口列表
    ports = [int(p.strip()) for p in args.ports.split(',')]

    print(f"[配置]")
    print(f"  IP: {args.ip}")
    print(f"  端口: {ports}")
    print(f"  时长: {args.duration}秒")
    print(f"  任务: {args.task}")
    print(f"  输出: {args.output}")

    main(args.ip, ports, args.duration, args.task, args.output)