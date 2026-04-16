#!/bin/bash

# 目录自动清理守护脚本

show_help() {
    echo "用法: $0 [-d <目录>] [-n <数量>] [-t <间隔>] [-h]"
    echo ""
    echo "选项:"
    echo "  -d <目录>   监控目录 (默认: 当前目录)"
    echo "  -n <数量>   最大文件数 (默认: 20)"
    echo "  -t <间隔>   检查间隔秒数 (默认: 5)"
    echo "  -h          显示帮助"
    echo ""
    echo "示例:"
    echo "  $0                      # 监控当前目录，最大20文件"
    echo "  $0 -d /tmp -n 10 -t 10  # 监控/tmp，最大10文件，10秒检查"
}

WORK_DIR="."
MAX_FILES=20
CHECK_INTERVAL=5
LOG_FILE="./clean.log"
IGNORE_PATTERNS=".git .DS_Store .swp *.tmp"

# 无参数时显示帮助
[ $# -eq 0 ] && { show_help; exit 0; }

while getopts "d:n:t:h" opt; do
    case $opt in
        d) WORK_DIR="$OPTARG" ;;
        n) MAX_FILES="$OPTARG" ;;
        t) CHECK_INTERVAL="$OPTARG" ;;
        h) show_help; exit 0 ;;
        ?) show_help; exit 1 ;;
    esac
done

[ -d "$WORK_DIR" ] || { echo "错误: 目录不存在 $WORK_DIR"; exit 1; }
[[ "$MAX_FILES" =~ ^[0-9]+$ ]] || { echo "错误: 数量必须是数字"; exit 1; }
[[ "$CHECK_INTERVAL" =~ ^[0-9]+$ ]] || { echo "错误: 间隔必须是数字"; exit 1; }

LOG_FILE="$WORK_DIR/clean.log"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

get_files() {
    local count=0
    for file in "$WORK_DIR"/*; do
        [[ -d "$file" ]] && continue
        for pattern in $IGNORE_PATTERNS; do
            [[ "$(basename "$file")" == $pattern ]] && continue 2
        done
        ((count++))
    done
    echo $count
}

log "启动清理服务: 目录=$WORK_DIR, 最大=$MAX_FILES文件, 间隔=$CHECK_INTERVAL秒"

while true; do
    count=$(get_files)
    if (( count > MAX_FILES )); then
        oldest_file=$(ls -t "$WORK_DIR" | tail -n 1)
        if [[ -n "$oldest_file" && -f "$WORK_DIR/$oldest_file" ]]; then
            log "[清理] 共$count文件，删除: $oldest_file"
            rm -f "$WORK_DIR/$oldest_file"
        fi
    else
        log "[正常] 文件数: $count"
    fi
    sleep "$CHECK_INTERVAL"
done