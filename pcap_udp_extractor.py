#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
文件名: pcap_udp_extractor.py
功能: 
描述: 提取pcap文件中的udp负载
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
    input_file = sys.argv[1]
    if not os.path.exists(input_file):
        print(f"[错误] 输入文件 {input_file} 不存在")
        return
    output_file = sys.argv[2]
    output_file = "output.ts"
    extract_udp_payload(input_file, output_file)
    print("[完成] 提取UDP负载完成")


if __name__ == "__main__":
    main()
