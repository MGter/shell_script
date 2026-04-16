# 脚本编写规范

本仓库所有脚本遵循统一的参数风格。

## 核心规则

**无参数运行时显示帮助信息**

## Shell脚本规范

```bash
#!/bin/bash

show_help() {
    echo "用法: $0 [-f <文件>] [-i <IP>] [-h]"
    echo ""
    echo "选项:"
    echo "  -f <文件>   输入文件"
    echo "  -i <IP>     目标IP"
    echo "  -h          显示帮助"
    echo ""
    echo "示例:"
    echo "  $0 -f input.txt -i 127.0.0.1"
}

# 无参数时显示帮助
[ $# -eq 0 ] && { show_help; exit 0; }

while getopts "f:i:h" opt; do
    case $opt in
        f) FILE="$OPTARG" ;;
        i) IP="$OPTARG" ;;
        h) show_help; exit 0 ;;
        ?) show_help; exit 1 ;;
    esac
done
```

## Python脚本规范

```python
#!/usr/bin/env python3

def show_help():
    print("""
用法: python3 script.py [-f <文件>] [-i <IP>] [-h]

选项:
  -f <文件>   输入文件
  -i <IP>     目标IP
  -h          显示帮助

示例:
  python3 script.py -f input.txt -i 127.0.0.1
""")

# 无参数或帮助模式
if len(sys.argv) == 1 or '-h' in sys.argv:
    show_help()
    sys.exit(0)

import argparse
parser = argparse.ArgumentParser(add_help=False)
parser.add_argument('-f', dest='file', required=True)
parser.add_argument('-i', dest='ip', required=True)
args = parser.parse_args()
```

## 参数命名约定

| 参数 | 含义 |
|------|------|
| `-f` | 输入文件 (file) |
| `-i` | IP地址 (ip) |
| `-p` | 端口 (port) |
| `-d` | 目录 (directory) / 目标IP |
| `-o` | 输出文件 (output) |
| `-n` | 数量/次数 (number/count) |
| `-t` | 时间/间隔 (time/interval) |
| `-b` | 码率 (bitrate) |
| `-h` | 显示帮助 (help) |
| `-s` | 停止/状态 (stop/status) |

## 帮助信息格式

```
用法: script [-a <参数>] [-b <参数>] [-h]

选项:
  -a <参数>   参数说明
  -b <参数>   参数说明
  -h          显示帮助

示例:
  script -a value1 -b value2
```

## 注意事项

1. 帮助信息必须包含：用法、选项说明、示例
2. 必选参数用 `required=True` (Python) 或检查变量是否为空 (Shell)
3. 默认值在帮助中标注 `(默认: xxx)`
4. 延迟导入依赖库，确保无参数时能显示帮助（Python）