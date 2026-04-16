#!/usr/bin/env python3
"""
系统信息检查工具 - 收集OS、CPU、内存、磁盘、网卡、GPU等信息，输出JSON
"""

import sys
import json
import os

def show_help():
    print("""
用法: python3 sysinfo_checker.py [-o <输出文件>] [--items <项目>] [-h]

选项:
  -o <文件>      输出: 检查结果JSON文件 (默认: sysinfo_checker.json)
  --items <列表>  配置: 检查项目，逗号分隔 (默认: 全部)
  -h             显示帮助信息

检查项目:
  os, mainboard, cpu, mem, disk, netcard, gpu, software, process, log

示例:
  python3 sysinfo_checker.py
  python3 sysinfo_checker.py -o my_check.json
  python3 sysinfo_checker.py --items os,cpu,mem,disk
""")

# 无参数或帮助模式
if len(sys.argv) == 1 or '-h' in sys.argv:
    show_help()
    sys.exit(0)

import argparse
import subprocess
import datetime
import re
import shutil

parser = argparse.ArgumentParser(add_help=False)
parser.add_argument('-o', dest='output', default='sysinfo_checker.json')
parser.add_argument('--items', dest='items', default='all')
args = parser.parse_args()

# 检查项目映射
ALL_ITEMS = ['os', 'mainboard', 'cpu', 'mem', 'disk', 'netcard', 'gpu', 'software', 'process', 'log']
selected_items = ALL_ITEMS if args.items == 'all' else [i.strip() for i in args.items.split(',')]

info = {}
info['Check_Time'] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def run_cmd(cmd, shell=False):
    try:
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                universal_newlines=True, check=True, shell=shell)
        return result.stdout.strip()
    except:
        return None

# OS信息
if 'os' in selected_items:
    os_info = {}
    os_info['Hostname'] = run_cmd(['hostname']) or 'N/A'
    os_info['Kernel'] = run_cmd(['uname', '-r']) or 'N/A'
    os_info['Arch'] = run_cmd(['arch']) or 'N/A'
    dist = run_cmd(['cat', '/etc/os-release'])
    if dist:
        name = re.search(r'^NAME="?(.*?)"?$', dist, re.MULTILINE)
        ver = re.search(r'^VERSION_ID="?(.*?)"?$', dist, re.MULTILINE)
        os_info['Distro'] = name.group(1) if name else 'N/A'
        os_info['Version'] = ver.group(1) if ver else 'N/A'
    uptime = run_cmd(['uptime', '-p'])
    os_info['Uptime'] = uptime.replace('up ', '') if uptime else 'N/A'
    info['OS'] = os_info

# CPU信息
if 'cpu' in selected_items:
    cpu_info = {}
    lscpu = run_cmd(['lscpu'])
    if lscpu:
        for line in lscpu.splitlines():
            if 'Model name' in line:
                cpu_info['Name'] = line.split(':')[-1].strip()
            elif line.strip().startswith('CPU(s):'):
                cpu_info['Count'] = line.split(':')[-1].strip()
            elif 'Architecture' in line:
                cpu_info['Arch'] = line.split(':')[-1].strip()
    info['CPU'] = cpu_info

# 内存信息
if 'mem' in selected_items:
    mem_info = {}
    free_out = run_cmd(['free', '-h'])
    if free_out:
        for line in free_out.splitlines():
            if 'Mem:' in line:
                vals = line.split()
                if len(vals) >= 7:
                    mem_info['Total'] = vals[1]
                    mem_info['Used'] = vals[2]
                    mem_info['Free'] = vals[3]
                    mem_info['Available'] = vals[6]
    info['Memory'] = mem_info

# 磁盘信息
if 'disk' in selected_items:
    disk_list = []
    df_out = run_cmd("df -h | grep -v tmpfs", shell=True)
    if df_out:
        for line in df_out.splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 6:
                disk_list.append({
                    'Device': parts[0],
                    'Size': parts[1],
                    'Used': parts[2],
                    'Avail': parts[3],
                    'Use%': parts[4],
                    'Mount': parts[5]
                })
    info['Disk'] = disk_list

# 网卡信息
if 'netcard' in selected_items:
    net_list = []
    ip_out = run_cmd(['ip', 'addr'])
    if ip_out:
        for line in ip_out.splitlines():
            if 'inet ' in line and not '127.0.0.1' in line:
                parts = line.split()
                net_list.append({'IP': parts[2].split('/')[0]})
    info['Network'] = net_list

# GPU信息
if 'gpu' in selected_items:
    gpu_info = {}
    nvidia = run_cmd("nvidia-smi --query-gpu=gpu_name --format=csv,noheader", shell=True)
    gpu_info['Nvidia'] = nvidia.splitlines() if nvidia else []
    intel = run_cmd("lspci | grep 'VGA' | grep 'Intel'", shell=True)
    gpu_info['Intel'] = intel.splitlines() if intel else []
    info['GPU'] = gpu_info

# 软件版本
if 'software' in selected_items:
    sw = {}
    for cmd_name in ['python3', 'gcc', 'make', 'docker']:
        ver = run_cmd([cmd_name, '--version'])
        if ver:
            sw[cmd_name] = ver.splitlines()[0]
    info['Software'] = sw

# 进程信息
if 'process' in selected_items:
    proc_list = []
    top_out = run_cmd("ps aux --sort=-%cpu | head -n 11", shell=True)
    if top_out:
        for line in top_out.splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 11:
                proc_list.append({'User': parts[0], 'PID': parts[1], 'CPU': parts[2], 'MEM': parts[3], 'Cmd': parts[10]})
    info['Process'] = proc_list

# 日志检查
if 'log' in selected_items:
    log_info = {}
    for pattern in ['Out of memory', 'segfault']:
        count = run_cmd(f"grep -c '{pattern}' /var/log/syslog 2>/dev/null || grep -c '{pattern}' /var/log/messages 2>/dev/null", shell=True)
        log_info[pattern] = int(count) if count and count.isdigit() else 0
    info['Log'] = log_info

# 输出
with open(args.output, 'w') as f:
    json.dump(info, f, indent=4, ensure_ascii=False)
print(f"[完成] {args.output}")