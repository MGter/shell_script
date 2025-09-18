#!/bin/bash

# version 1.1
# 修改日期：2025年9月18日09:24:34
# 功能：从文件中提取 xStreamTool_MemWatch.py 生成的内存统计数据部分，合成一个csv文件辅助查看趋势
# 使用方法： sh memwatch_striper.sh [file]
# 创建人：MGter

SRC_FILE=$1
TEMP_FILE="${SRC_FILE}.temp"
DST_FILE="${SRC_FILE}.csv"

# 检查源文件是否存在
if [ ! -f "$SRC_FILE" ]; then
    echo "错误：源文件 '$SRC_FILE' 不存在。"
    echo "使用方法： sh memwatch_striper.sh [file]"
    exit 1
fi

echo "开始处理文件 '$SRC_FILE'..."

# 1. 提取包含 "xStreamTool_MemWatch" 的内容
echo "提取包含 "xStreamTool_MemWatch" 的内容" 
grep "xStreamTool_MemWatch" "$SRC_FILE" | grep -v "CRON" > "$TEMP_FILE"
grep -o '{.*}' $TEMP_FILE >  "{$TEMP_FILE}.1"

# 2. 将所有标点符号和空格都替换为逗号，并清除多余的逗号
echo "文件格式转换中，目标文件：$DST_FILE"
sed 's/[[:punct:] ]/,/g' "{$TEMP_FILE}.1" | sed 's/, */,/g' > "{$TEMP_FILE}.2"
sed -E 's/,+/,/g' "{$TEMP_FILE}.2" > $DST_FILE

# 4. 清理中间的临时文件
echo "正在清理中间文件"
rm -f "$TEMP_FILE" "{$TEMP_FILE}.1" "{$TEMP_FILE}.2"

echo "处理完成，结果已保存到 '$DST_FILE'。"