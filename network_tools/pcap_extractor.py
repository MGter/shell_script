#!/usr/bin/env python3
"""
PCAP UDP负载提取工具 - 从PCAP文件提取UDP负载保存为TS
依赖: pip install scapy
"""

import os
import sys

def show_help():
    print("""
用法: python3 pcap_udp_extractor.py [-i <输入>] [-o <输出>] [-h]

选项:
  -i <文件>  输入: PCAP文件路径 (必选)
  -o <文件>  输出: 提取的TS文件路径 (默认: output.ts)
  -h         显示帮助信息

示例:
  python3 pcap_udp_extractor.py -i test.pcap -o output.ts
  python3 pcap_udp_extractor.py -i capture.pcap
""")

def extract_udp_payload(input_file, output_file):
    """提取UDP负载"""
    try:
        from scapy.utils import PcapReader
        from scapy.layers.inet import UDP
    except ImportError:
        print("[错误] 缺少scapy库，请执行: pip install scapy")
        return False

    if not os.path.exists(input_file):
        print(f"[错误] 文件不存在: {input_file}")
        return False

    count_udp = 0
    count_total = 0

    print(f"[读取] {input_file}")

    try:
        with PcapReader(input_file) as pcap, open(output_file, 'wb') as f:
            for pkt in pcap:
                count_total += 1
                if UDP in pkt:
                    f.write(bytes(pkt[UDP].payload))
                    count_udp += 1

                if count_total % 10000 == 0:
                    print(f"  已处理 {count_total} 包, UDP {count_udp}", end='\r')

        print()
        print(f"[完成] 总包: {count_total}, UDP: {count_udp}")
        print(f"[输出] {output_file}")
        return True

    except Exception as e:
        print(f"[错误] {e}")
        return False

if __name__ == "__main__":
    # 无参数或帮助模式
    if len(sys.argv) == 1 or '-h' in sys.argv:
        show_help()
        sys.exit(0)

    import argparse
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument('-i', dest='input', required=True)
    parser.add_argument('-o', dest='output', default='output.ts')

    args = parser.parse_args()
    extract_udp_payload(args.input, args.output)