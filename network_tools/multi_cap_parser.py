#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
文件名: multi_cap_parser.py
功能: 多端口网络抓包及TS流分析工具
描述: 配置指定参数，可以实现并行抓包+解析ts文件时间戳，用以对比
注意: 
    1. 本应用依赖系统工具tcpdump和ffprobe，建议使用yum或者apt进行下载
    2. 本应用依赖Python3的scapy库，建议使用pip install scapy进行下载
创建人: MGter
创建时间: 2025年7月9日13:46:35
最后修改时间: 2025年7月9日13:46:35
版本: 1.0.0
"""

import os
import time
import subprocess
from pathlib import Path
from typing import List
from scapy.all import *
from scapy.layers.inet import UDP

# 配置参数
config = {
    "taskName": "task00",      # 任务名称
    "duration": 10,           # 抓包持续时间(秒)
    "dstIp": "192.165.58.221", # 目标IP地址
    "dstPort": [              # 目标端口列表
        30000,
        30001,
        30002,
        30003
    ]
}

def capture(duration: int, ip: str, port: int, output: str) -> bool:
    """
    执行网络抓包操作
    :param duration: 抓包持续时间(秒)
    :param ip: 目标IP地址
    :param port: 目标端口
    :param output: 输出文件名
    :return: 执行结果
    """
    try:
        pattern = f"dst host {ip} and port {port}"
        cmd = [
            "timeout", str(duration),
            "tcpdump", "-i", "any", pattern,
            "-w", output
        ]
        
        print(f"[抓包命令] {' '.join(cmd)}")
        
        subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True  
        )
        return True
    except Exception as e:
        print(f"抓包失败: {e}")
        return False

def extract_udp_payload(input_pcap: str, output_file: str) -> bool:
    """
    从PCAP文件中提取UDP负载
    :param input_pcap: 输入的PCAP文件
    :param output_file: 输出的TS文件
    :return: 执行结果
    """
    try:
        packets = rdpcap(input_pcap)
        with open(output_file, 'wb') as f:
            for pkt in packets:
                if pkt.haslayer(UDP):
                    payload = bytes(pkt[UDP].payload)
                    f.write(payload)
        
        print(f"[提取UDP] 成功从 {input_pcap} 提取负载到 {output_file}")
        return True
    
    except Exception as e:
        print(f"[错误] 处理 {input_pcap} 时出错: {e}")
        return False
    
def parse_video_frameinfo(ts_file: str, output_csv: str) -> bool:
    try:
        with open(output_csv, 'w') as out_file:
            subprocess.run(
                [
                    "ffprobe",
                    "-loglevel", "error",
                    "-select_streams", "v:0",
                    "-show_entries", "frame=pict_type,pts_time",
                    "-of", "csv=p=0",
                    str(ts_file)
                ],
                stdout=out_file,
                stderr=subprocess.DEVNULL,
                check=True
            )
        return True
    except subprocess.CalledProcessError:
        return False

def main():
    # 初始化参数
    save_path = "./captures"       # 抓包文件保存路径
    duration = config["duration"]  # 抓包持续时间
    pcap_list = []                 # 保存生成的pcap文件名
    ts_list = []                   # 保存生成的ts文件名
    
    # 设置工作目录
    os.makedirs(save_path, exist_ok=True)
    os.chdir(save_path)
    print(f"[目录设置] 当前工作目录已切换到: {os.getcwd()}")
    
    # 阶段1: 启动抓包任务
    print(f"[抓包启动] 开始对 {config['dstIp']} 的多个端口进行抓包...")
    for port in config["dstPort"]:
        output_file = f"{config['taskName']}_{config['dstIp']}_{port}.pcap"
        print(f"[抓包任务] 目标: {config['dstIp']}:{port}, 持续时间: {duration}秒, 输出文件: {output_file}")
        capture(duration, config["dstIp"], port, output_file)
        pcap_list.append(output_file)

    # 阶段2: 等待抓包完成
    print(f"[等待抓包] 抓包进行中，等待 {duration} 秒...")
    for i in range(duration + 1):
        time.sleep(1)
        print(f"[抓包进度] 已等待 {i}/{duration} 秒...")
    print("[抓包状态] 所有抓包任务已完成")
    
    # 阶段3: 提取PCAP中的ts
    print("[提取开始] 开始从PCAP文件中提取UDP负载...")
    for pcap_file in pcap_list:
        pcap_path = Path(pcap_file)
        ts_file = pcap_path.with_suffix(".ts")  # 生成TS文件名
        print(f"[正在提取] 正在处理: {pcap_path} -> {ts_file}")
        extract_udp_payload(str(pcap_path), ts_file)
        ts_list.append(ts_file)
    print(f"[提取结束] 共处理 {len(ts_list)} 个文件")

    # 阶段4: 从TS中解析时间戳
    print("[解析阶段] 准备从TS文件中解析时间戳...")
    for ts_file in ts_list:
        ts_path = Path(ts_file)
        output_file = ts_path.with_suffix(".csv")
        print(f"[正在解析] 正在处理: {ts_path} -> {output_file}")
        parse_video_frameinfo(ts_path, output_file)
    print(f"[解析结束] 共处理 {len(ts_list)} 个文件")

    # 阶段5: 整理类型，清理文件
    print("[清理阶段] 将文件重新归类...")
    os.makedirs("00_pcap_file", exist_ok=True)
    cmd = "mv *pcap 00_pcap_file"
    subprocess.run(cmd, shell=True, check=True)
    os.makedirs("01_ts_file", exist_ok=True)
    cmd = "mv *ts 01_ts_file"
    subprocess.run(cmd, shell=True, check=True)
    cmd = "rm nohup.out -f"
    subprocess.run(cmd, shell=True, check=True)
    print("[清理结束] 文件归类完成...")

if __name__ == "__main__":
    print("[程序启动] 网络抓包与解析工具开始运行")
    main()
    print("[程序结束] 所有处理已完成")
