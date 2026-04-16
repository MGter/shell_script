#!/bin/bash

# 内存监控数据提取工具
# 从 xStreamTool_MemWatch 日志提取数据转为CSV

show_help() {
    echo "用法: $0 [-i <输入文件>] [-o <输出文件>] [-h]"
    echo ""
    echo "选项:"
    echo "  -i <文件>  输入日志文件"
    echo "  -o <文件>  输出CSV文件 (默认: 输入文件名.csv)"
    echo "  -h         显示帮助"
    echo ""
    echo "示例:"
    echo "  $0 -i memwatch.log"
    echo "  $0 -i memwatch.log -o result.csv"
}

INPUT_FILE=""
OUTPUT_FILE=""

# 无参数时显示帮助
[ $# -eq 0 ] && { show_help; exit 0; }

while getopts "i:o:h" opt; do
    case $opt in
        i) INPUT_FILE="$OPTARG" ;;
        o) OUTPUT_FILE="$OPTARG" ;;
        h) show_help; exit 0 ;;
        ?) show_help; exit 1 ;;
    esac
done

# 检查参数
[ -z "$INPUT_FILE" ] && { echo "错误: 缺少输入文件"; show_help; exit 1; }

# 检查文件存在
[ ! -f "$INPUT_FILE" ] && { echo "错误: 文件不存在 $INPUT_FILE"; exit 1; }

# 设置默认输出文件
[ -z "$OUTPUT_FILE" ] && OUTPUT_FILE="${INPUT_FILE}.csv"

TEMP_FILE="${INPUT_FILE}.temp"

echo "[处理] $INPUT_FILE -> $OUTPUT_FILE"

# 提取数据
grep "xStreamTool_MemWatch" "$INPUT_FILE" | grep -v "CRON" > "$TEMP_FILE"
grep -o '{.*}' "$TEMP_FILE" > "${TEMP_FILE}.1"

# 格式转换
sed 's/[[:punct:] ]/,/g' "${TEMP_FILE}.1" | sed 's/, */,/g' > "${TEMP_FILE}.2"
sed -E 's/,+/,/g' "${TEMP_FILE}.2" > "$OUTPUT_FILE"

# 清理
rm -f "$TEMP_FILE" "${TEMP_FILE}.1" "${TEMP_FILE}.2"

echo "[完成] $OUTPUT_FILE"