#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
文件名: pcap_udp_extractor.py
功能: 提取pcap文件中的udp负载
使用方式：python3 pcap_udp_extractor.py input.pcap output.ts
注意: 
    1. 本应用依赖Python3的scapy库，建议使用pip install scapy进行下载
创建人: MGter
创建时间: 2025年7月9日13:46:35
最后修改时间: 2025年7月9日13:46:35
版本: 1.0.0
"""

# pip install scapy

import os
import sys
from pathlib import Path
from typing import List
from scapy.all import *
from scapy.layers.inet import UDP

def print_help():
    """打印帮助信息"""
    print("用法: python script.py <输入文件> <输出文件>")
    print("功能: 从输入文件中提取UDP负载并保存到输出文件")
    print("参数:")
    print("  <输入文件>  要处理的输入文件路径")
    print("  <输出文件>  保存提取结果的输出文件路径")
    print("示例:")
    print("  python3 script.py input.pcap output.ts")

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


def main():
    # 检查参数数量
    if len(sys.argv) < 3:
        print("[错误] 参数数量不正确")
        print_help()
        return
    
    input_file = sys.argv[1]
    output_file = sys.argv[2]

    # 检查输入文件是否存在
    if not os.path.exists(input_file):
        print(f"[错误] 输入文件 {input_file} 不存在")
        print_help()
        return
    
    extract_udp_payload(input_file, output_file)
    print(f"[完成] UDP负载提取完成，结果保存在 {output_file}")


if __name__ == "__main__":
    main()
