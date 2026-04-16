#!/bin/bash

# =============================================================================
#  自动清理脚本：当文件数 > 20 时，删除最旧的文件
#  每 5 秒执行一次
#  当前目录下所有文件（非子目录）
#  安全设计：支持隐藏文件排除、日志输出、防误删
# =============================================================================

# 配置参数
MAX_FILES=20           # 超过此数量就删除最旧的
CHECK_INTERVAL=5      # 检查间隔（秒）
LOG_FILE="./clean.log" # 日志文件路径
IGNORE_PATTERNS=".git .DS_Store .swp *.tmp"  # 忽略的文件/模式

# 记录日志函数
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

# 获取当前目录下所有文件（不含子目录），并过滤掉忽略项
get_files() {
    local files=()
    # 找出所有普通文件（不递归），并排除指定模式
    for file in *; do
        # 跳过目录
        [[ -d "$file" ]] && continue
        # 跳过忽略的文件
        for pattern in $IGNORE_PATTERNS; do
            [[ "$file" == $pattern ]] && continue 2
        done
        # 保留文件名
        files+=("$file")
    done
    # 返回数组长度和文件列表
    echo "${#files[@]}"
    printf '%s\n' "${files[@]}"
}

# 主逻辑
main() {
    log "✅ 启动自动清理服务，最大文件数: $MAX_FILES"

    while true; do
        # 统计文件数量
        count=$(get_files | head -n1)
        files=$(get_files | tail -n+2)

        # 判断是否需要清理
        if (( count > MAX_FILES )); then
            # 按修改时间升序排列，取第一个（最旧）
	    oldest_file=$(ls -tr | head -n 1)

            if [[ -n "$oldest_file" ]]; then
                log "[WARN] 超过 $MAX_FILES 个文件（共 $count 个），删除最旧文件：$oldest_file"
                rm -f "$oldest_file"
                log "️ [INFO] 已删除：$oldest_file"
            else
                log "❌ 未找到可删除的文件（可能全部被忽略或为空）"
            fi
        else
            log "[INFO] 文件数量 $count ≤ $MAX_FILES，无需清理。"
        fi

        # 等待下一轮
        sleep "$CHECK_INTERVAL"
    done
}

# 启动主程序
main

