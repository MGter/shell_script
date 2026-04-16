#!/bin/bash

# 配置文件备份更新工具
# 将源文件复制到目标目录，目标文件存在则先备份

show_help() {
    echo "用法: $0 [-i <源目录>] [-d <目标目录>]"
    echo ""
    echo "选项:"
    echo "  -i <源目录>    源文件目录 (默认: ./conf)"
    echo "  -d <目标目录>  目标目录 (默认: ~)"
    echo ""
    echo "示例:"
    echo "  $0                          # 使用默认路径"
    echo "  $0 -i ./config -d /etc/app  # 指定源和目标目录"
    echo ""
    echo "逻辑:"
    echo "  - 目标文件存在且备份不存在 → 先备份再覆盖"
    echo "  - 目标文件存在且备份已存在 → 直接覆盖"
    echo "  - 目标文件不存在 → 直接复制"
}

# 默认值
CONF_DIR="./conf"
DST_PATH=~
SHOW_HELP=false

# 无参数时显示帮助
[ $# -eq 0 ] && SHOW_HELP=true

# 解析参数
while getopts "i:d:h" opt; do
    case $opt in
        i) CONF_DIR="$OPTARG"; SHOW_HELP=false ;;
        d) DST_PATH="$OPTARG"; SHOW_HELP=false ;;
        h) SHOW_HELP=true ;;
        ?) SHOW_HELP=true ;;
    esac
done

# 显示帮助
if $SHOW_HELP; then
    show_help
    exit 0
fi

# 检查目录
[ -d "$CONF_DIR" ] || { echo "错误: 源目录 $CONF_DIR 不存在"; exit 1; }
[ -d "$DST_PATH" ] || { echo "错误: 目标目录 $DST_PATH 不存在"; exit 1; }

echo "开始处理配置文件..."
echo "源目录: $CONF_DIR"
echo "目标目录: $DST_PATH"
echo "----------------------------------------"

for src_file in "$CONF_DIR"/*; do
    [ -f "$src_file" ] || continue

    filename=$(basename "$src_file")
    purename="${filename%.*}"
    extension="${filename##*.}"
    [ "$filename" = "$purename" ] && extension=""

    target_file="$DST_PATH/$filename"
    [ -n "$extension" ] && backup_file="$DST_PATH/${purename}_back.${extension}" || backup_file="$DST_PATH/${purename}_back"

    echo "处理: $filename"

    if [ -e "$target_file" ]; then
        [ -e "$backup_file" ] && echo "  备份已存在，跳过备份" || { cp "$target_file" "$backup_file"; echo "  已创建备份"; }
        cp "$src_file" "$target_file"
        echo "  已覆盖"
    else
        cp "$src_file" "$target_file"
        echo "  已复制"
    fi
done

echo "========================================"
echo "完成!"