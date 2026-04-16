#!/bin/bash

# 为 .so.x.y.z 库文件创建完整版本链软链接

show_help() {
    echo "用法: $0 [-d <目录>] [-h]"
    echo ""
    echo "选项:"
    echo "  -d <目录>   输入: 工作目录路径 (默认: 当前目录)"
    echo "  -h          显示帮助信息"
    echo ""
    echo "功能:"
    echo "  扫描目录下 *.so.x.y.z 格式的真实文件(非软链接)"
    echo "  逐级创建软链接链:"
    echo "    libtest.so.1.2.3 → libtest.so.1 → libtest.so.1.2 → libtest.so"
    echo ""
    echo "示例:"
    echo "  $0                  # 处理当前目录"
    echo "  $0 -d /usr/lib      # 处理指定目录"
}

WORK_DIR="."
SHOW_HELP=false

# 无参数时显示帮助
[ $# -eq 0 ] && SHOW_HELP=true

while getopts "d:h" opt; do
    case $opt in
        d) WORK_DIR="$OPTARG"; SHOW_HELP=false ;;
        h) SHOW_HELP=true ;;
        ?) SHOW_HELP=true ;;
    esac
done

# 显示帮助
if $SHOW_HELP; then
    show_help
    exit 0
fi

[ -d "$WORK_DIR" ] || { echo "错误: 目录 $WORK_DIR 不存在"; exit 1; }
cd "$WORK_DIR" || exit 1

count=0
for file in *.so.*; do
    # 只处理普通文件，跳过目录和软链接
    [ -L "$file" ] && continue
    [ -d "$file" ] && continue
    [ ! -f "$file" ] && continue
    [[ ! "$file" =~ \.so\.[0-9]+\.[0-9]+ ]] && continue

    echo "处理: $file"
    base="${file%%.so.*}"
    version="${file#*.so.}"

    prev_link=""
    IFS='.' read -ra ver_parts <<< "$version"

    for i in "${!ver_parts[@]}"; do
        current_ver=$(IFS='.'; echo "${ver_parts[*]:0:$i+1}")
        link_name="${base}.so.${current_ver}"
        [ -z "$prev_link" ] && target="$file" || target="$prev_link"
        [ -L "$link_name" ] && rm -f "$link_name"
        ln -s "$target" "$link_name"
        echo "  创建: $link_name -> $target"
        prev_link="$link_name"
    done

    final_so="${base}.so"
    [ -L "$final_so" ] && rm -f "$final_so"
    ln -s "$prev_link" "$final_so"
    echo "  创建: $final_so -> $prev_link"
    ((count++))
done

[ "$count" -eq 0 ] && echo "未找到 .so.x.y.z 格式的库文件"
echo "✅ 处理 $count 个文件"