#!/bin/bash

# 检查参数数量是否正确
if [ $# -ne 4 ]; then
    echo "用法错误！正确用法：$0 <file> <ip> <port> <times>"
    echo "示例：$0 input.ts 127.0.0.1 30000 5"
    echo "说明：以上示例会执行5次命令，端口依次为30000、30001、30002、30003、30004"
    exit 1
fi

# 给参数赋值，提高可读性
INPUT_FILE=$1
TARGET_IP=$2
START_PORT=$3
EXEC_TIMES=$4

# 检查输入文件是否存在
if [ ! -f "$INPUT_FILE" ]; then
    echo "错误：文件 $INPUT_FILE 不存在！"
    exit 1
fi

# 检查 ffmpeg 是否安装
if ! command -v ffmpeg &> /dev/null; then
    echo "错误：未找到 ffmpeg，请先安装 ffmpeg！"
    exit 1
fi

# 检查参数是否为数字（端口和执行次数）
if ! [[ "$START_PORT" =~ ^[0-9]+$ && "$EXEC_TIMES" =~ ^[0-9]+$ ]]; then
    echo "错误：port 和 times 必须是正整数！"
    exit 1
fi

# 检查执行次数是否大于0
if [ "$EXEC_TIMES" -le 0 ]; then
    echo "错误：执行次数 times 必须大于0！"
    exit 1
fi

# 循环执行指定次数的ffmpeg命令
current_port=$START_PORT
echo "开始执行 $EXEC_TIMES 次 ffmpeg 后台推流命令..."
for ((i=1; i<=EXEC_TIMES; i++)); do
    # 拼接完整命令
    cmd="nohup ffmpeg -stream_loop -1 -re -i $INPUT_FILE -c copy -f mpegts -pkt_size 1316 udp://$TARGET_IP:$current_port &"
    
    # 打印并执行命令
    echo "执行第 $i 次命令：$cmd"
    eval $cmd
    
    # 记录进程ID，方便后续管理
    pid=$!
    echo "第 $i 次命令的进程ID：$pid，监听端口：$current_port"
    
    # 端口自增1
    current_port=$((current_port + 1))
    
    # 短暂延迟，避免命令执行过快导致异常（可选，可根据需要调整）
    sleep 0.5
done

echo "所有命令已提交执行！"
echo "可使用 ps -ef | grep ffmpeg 查看运行的进程"
echo "可使用 kill -9 <进程ID> 停止指定的推流进程"