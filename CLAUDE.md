# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository Overview

这是一个运维和测试工具脚本集合，包含Shell和Python脚本，主要用于网络测试、系统监控和数据处理。

## Script Categories

### 网络测试工具 (network_tools/)
- `ffmpeg_push.sh` - ffmpeg多端口UDP推流，支持循环推流和端口递增
- `pcap_sender.py` - PCAP文件回放工具，支持时序保留模式和无限循环
- `udp_sender.py` - 按指定码率发送TS流文件
- `multi_cap_parser.py` - 多端口并行抓包+TS流时间戳解析对比
- `pcap_extractor.py` - 从PCAP文件提取UDP负载保存为TS

### 系统运维工具 (sysadmin_tools/)
- `sysinfo_checker.py` - 综合系统信息检查，收集OS、CPU、内存、磁盘、网卡、GPU、进程等状态，输出JSON文件
- `auto_clean.sh` - 目录自动清理守护脚本，超过20个文件时删除最旧文件
- `memwatch_parser.sh` - 内存监控数据提取，将xStreamTool_MemWatch日志转为CSV

### 文件处理工具 (file_tools/)
- `config_update.sh` - 配置文件备份更新工具，从./conf复制到目标目录并备份原文件
- `so_link.sh` - 为.so.x.y.z库文件创建完整版本链软链接

### 其他工具 (other_tools/)
- `image_measurer.py` - 图像测量工具，以身份证宽度(85.6mm)为参考测量图片中物体长度

## Dependencies

Python脚本依赖：
- `scapy` - 网络包处理（multi_cap_parser.py, pcap_sender.py, pcap_extractor.py）
- `opencv-python`, `numpy` - 图像处理（image_measurer.py）

Shell脚本依赖：
- `ffmpeg` - 视频推流（ffmpeg_push.sh）
- `tcpdump`, `ffprobe` - 抓包和分析（multi_cap_parser.py调用）

## Common Commands

```bash
# ffmpeg多端口推流
ffmpeg_push.sh -f input.ts -i 127.0.0.1 -p 30000 -n 5

# PCAP回放（保留时序）
python3 pcap_sender.py -f input.pcap -i 192.165.56.184 -p 13000 --preserve-timing

# UDP发送（指定码率）
python3 udp_sender.py -f input.ts -i 127.0.0.1 -p 25234 -b 16600000

# PCAP提取UDP负载
python3 pcap_extractor.py -i input.pcap -o output.ts

# 系统信息检查
python3 sysinfo_checker.py

# 内存数据转CSV
memwatch_parser.sh -i memwatch.log

# 创建.so软链接
so_link.sh -d /usr/lib
```

## Notes

- 所有脚本作者为MGter
- sysinfo_checker.py需要root权限执行部分检查（如dmidecode）
- 网络测试脚本默认使用UDP协议，端口配置需根据实际环境调整
- 所有脚本无参数运行时显示帮助信息