# 脚本编写规范

本仓库所有脚本遵循统一的参数风格。

## 核心规则

**无参数运行时显示帮助信息**

---

## 参数命名规范

### 通用参数

| 参数 | 变量名 | 含义 | 类型 | 示例 |
|------|--------|------|------|------|
| `-f` | `file` | 输入文件路径 | `filepath` | `input.ts`, `test.pcap` |
| `-o` | `output` | 输出文件路径 | `filepath` | `output.ts`, `result.csv` |
| `-i` | `ip` | 目标IP地址 | `ipv4` | `192.168.1.1`, `127.0.0.1` |
| `-p` | `port` | 目标端口 | `port(1-65535)` | `30000`, `5000` |
| `-d` | `dir` | 目录路径 | `directory` | `/tmp`, `./captures` |
| `-n` | `count` | 数量/次数 | `integer` | `5`, `-1`(无限) |
| `-t` | `time` | 时间/间隔(秒) | `float` | `10`, `1.5` |
| `-b` | `bitrate` | 比特率(bps) | `integer` | `16600000` |
| `-l` | `loop` | 循环次数 | `integer` | `3`, `-1`(无限) |
| `-s` | `stop` | 停止操作 | `flag` | 无值 |
| `-h` | `help` | 显示帮助 | `flag` | 无值 |

### 类型说明

| 类型 | 格式 | 验证方式 |
|------|------|----------|
| `filepath` | 文件路径，相对或绝对 | 检查文件是否存在 |
| `directory` | 目录路径 | 检查目录是否存在 |
| `ipv4` | IPv4地址 `x.x.x.x` | 正则 `^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$` |
| `port` | 端口号 1-65535 | `port >= 1 && port <= 65535` |
| `integer` | 整数 | 正则 `^[0-9]+$` |
| `float` | 浮点数 | 正则 `^[0-9]+\.?[0-9]*$` |
| `flag` | 标志位，无值 | 无需验证 |

---

## 输入输出规范

### 文件类型约定

| 扩展名 | 类型 | 说明 |
|--------|------|------|
| `.ts` | MPEG-TS流 | 视频流文件 |
| `.pcap` | PCAP抓包 | 网络抓包文件 |
| `.csv` | CSV表格 | 逗号分隔数据 |
| `.json` | JSON数据 | 结构化数据 |
| `.log` | 日志文件 | 文本日志 |
| `.sh` | Shell脚本 | Bash脚本 |
| `.py` | Python脚本 | Python脚本 |

### 输入输出标记

在帮助信息中使用标记区分输入/输出：

```
选项:
  -f <输入文件>   输入: 要处理的文件
  -o <输出文件>   输出: 结果保存路径
  -i <IP地址>     目标: 发送目标IP
  -p <端口>       目标: 发送目标端口
```

---

## Shell脚本模板

```bash
#!/bin/bash

show_help() {
    echo "用法: $0 [-f <输入文件>] [-o <输出文件>] [-h]"
    echo ""
    echo "选项:"
    echo "  -f <输入文件>  输入: 要处理的文件路径"
    echo "  -o <输出文件>  输出: 结果保存路径 (默认: output.txt)"
    echo "  -h             显示帮助信息"
    echo ""
    echo "示例:"
    echo "  $0 -f input.txt"
    echo "  $0 -f input.txt -o result.txt"
}

INPUT_FILE=""
OUTPUT_FILE="output.txt"

# 无参数时显示帮助
[ $# -eq 0 ] && { show_help; exit 0; }

while getopts "f:o:h" opt; do
    case $opt in
        f) INPUT_FILE="$OPTARG" ;;
        o) OUTPUT_FILE="$OPTARG" ;;
        h) show_help; exit 0 ;;
        ?) show_help; exit 1 ;;
    esac
done

# 参数验证
[ -z "$INPUT_FILE" ] && { echo "错误: 缺少输入文件 (-f)"; show_help; exit 1; }
[ ! -f "$INPUT_FILE" ] && { echo "错误: 文件不存在 $INPUT_FILE"; exit 1; }

# 执行逻辑...
```

---

## Python脚本模板

```python
#!/usr/bin/env python3

def show_help():
    print("""
用法: python3 script.py [-f <输入文件>] [-o <输出文件>] [-h]

选项:
  -f <输入文件>  输入: 要处理的文件路径 (必选)
  -o <输出文件>  输出: 结果保存路径 (默认: output.txt)
  -h             显示帮助信息

示例:
  python3 script.py -f input.txt
  python3 script.py -f input.txt -o result.txt
""")

# 无参数或帮助模式
if len(sys.argv) == 1 or '-h' in sys.argv:
    show_help()
    sys.exit(0)

import argparse
import os

parser = argparse.ArgumentParser(add_help=False)
parser.add_argument('-f', dest='input', required=True, help='输入文件路径')
parser.add_argument('-o', dest='output', default='output.txt', help='输出文件路径')
args = parser.parse_args()

# 参数验证
if not os.path.exists(args.input):
    print(f"错误: 文件不存在 {args.input}")
    sys.exit(1)

# 执行逻辑...
```

---

## 当前脚本参数对照表

### file_tools/

| 脚本 | 参数 | 类型 | 说明 |
|------|------|------|------|
| `so_link.sh` | `-d <目录>` | directory | 输入: 工作目录 |
| | `-h` | flag | 显示帮助 |
| `config_update.sh` | `-i <源目录>` | directory | 输入: 配置文件源目录 |
| | `-d <目标目录>` | directory | 输出: 配置文件目标目录 |
| | `-h` | flag | 显示帮助 |

### network_tools/

| 脚本 | 参数 | 类型 | 说明 |
|------|------|------|------|
| `ffmpeg_push.sh` | `-f <文件>` | filepath(.ts) | 输入: TS流文件 |
| | `-i <IP>` | ipv4 | 目标: 推流IP地址 |
| | `-p <端口>` | port | 目标: 推流起始端口 |
| | `-n <次数>` | integer | 推流数量(端口递增) |
| | `-s` | flag | 停止所有推流 |
| | `-h` | flag | 显示帮助 |
| `multi_cap_parser.py` | `-i <IP>` | ipv4 | 目标: 抓包目标IP |
| | `-p <端口>` | port列表 | 目标: 抓包端口(逗号分隔) |
| | `-d <时长>` | integer | 抓包时长(秒) |
| | `-t <任务名>` | string | 任务名称 |
| | `-o <目录>` | directory | 输出: 结果保存目录 |
| | `-h` | flag | 显示帮助 |
| `pcap_sender.py` | `-f <文件>` | filepath(.pcap) | 输入: PCAP文件 |
| | `-i <IP>` | ipv4 | 目标: 发送IP地址 |
| | `-p <端口>` | port | 目标: 发送端口 |
| | `-n <次数>` | integer | 循环次数(-1无限) |
| | `-t <间隔>` | float | 循环间隔(秒) |
| | `--preserve-timing` | flag | 保留原始时序 |
| | `-h` | flag | 显示帮助 |
| `pcap_extractor.py` | `-i <文件>` | filepath(.pcap) | 输入: PCAP文件 |
| | `-o <文件>` | filepath(.ts) | 输出: 提取的TS文件 |
| | `-h` | flag | 显示帮助 |
| `udp_sender.py` | `-f <文件>` | filepath(.ts) | 输入: TS流文件 |
| | `-i <IP>` | ipv4 | 目标: 发送IP地址 |
| | `-p <端口>` | port | 目标: 发送端口 |
| | `-b <码率>` | integer | 发送比特率(bps) |
| | `-n <次数>` | integer | 循环次数(-1无限) |
| | `-h` | flag | 显示帮助 |

### sysadmin_tools/

| 脚本 | 参数 | 类型 | 说明 |
|------|------|------|------|
| `auto_clean.sh` | `-d <目录>` | directory | 输入: 监控目录 |
| | `-n <数量>` | integer | 最大文件数 |
| | `-t <间隔>` | integer | 检查间隔(秒) |
| | `-h` | flag | 显示帮助 |
| `memwatch_parser.sh` | `-i <文件>` | filepath(.log) | 输入: 内存监控日志 |
| | `-o <文件>` | filepath(.csv) | 输出: 转换后的CSV |
| | `-h` | flag | 显示帮助 |
| `sysinfo_checker.py` | `-o <文件>` | filepath(.json) | 输出: 检查结果JSON |
| | `--items <列表>` | string | 检查项目(逗号分隔) |
| | `-h` | flag | 显示帮助 |

### other_tools/

| 脚本 | 参数 | 类型 | 说明 |
|------|------|------|------|
| `image_measurer.py` | `-i <文件>` | filepath(.jpg/.png) | 输入: 待测量图像 |
| | `-o <文件>` | filepath(.jpg) | 输出: 标记结果图像 |
| | `-h` | flag | 显示帮助 |

---

## 注意事项

1. **帮助信息必须包含**：用法、选项说明、示例
2. **参数类型标注**：使用 `输入:`、`输出:`、`目标:` 标记
3. **默认值标注**：`(默认: xxx)`
4. **必选参数标注**：`(必选)`
5. **特殊值说明**：`-1` 表示无限循环
6. **延迟导入**：Python脚本确保无参数时能显示帮助