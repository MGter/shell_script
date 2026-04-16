#!/bin/bash

# ffmpeg多端口UDP推流工具

PID_FILE="./ff_push.pid"

show_help() {
    echo "用法: $0 [-f <文件>] [-i <IP>] [-p <端口>] [-n <次数>] [-s] [-h]"
    echo ""
    echo "选项:"
    echo "  -f <文件>   输入TS文件"
    echo "  -i <IP>     目标IP地址"
    echo "  -p <端口>   起始端口"
    echo "  -n <次数>   推流数量 (端口递增)"
    echo "  -s          停止所有推流进程"
    echo "  -h          显示帮助"
    echo ""
    echo "示例:"
    echo "  $0 -f input.ts -i 127.0.0.1 -p 30000 -n 5"
    echo "  $0 -s                    # 停止所有推流"
}

stop_push() {
    if [ -f "$PID_FILE" ]; then
        echo "正在停止推流进程..."
        while read pid; do
            if kill -0 "$pid" 2>/dev/null; then
                kill "$pid"
                echo "已停止进程: $pid"
            fi
        done < "$PID_FILE"
        rm -f "$PID_FILE"
        echo "所有推流已停止"
    else
        echo "未找到PID文件，无推流进程记录"
        echo "可手动执行: ps -ef | grep ffmpeg"
    fi
}

# 无参数时显示帮助
[ $# -eq 0 ] && { show_help; exit 0; }

INPUT_FILE=""
TARGET_IP=""
START_PORT=""
EXEC_TIMES=""
ACTION="start"

while getopts "f:i:p:n:sh" opt; do
    case $opt in
        f) INPUT_FILE="$OPTARG" ;;
        i) TARGET_IP="$OPTARG" ;;
        p) START_PORT="$OPTARG" ;;
        n) EXEC_TIMES="$OPTARG" ;;
        s) ACTION="stop" ;;
        h) show_help; exit 0 ;;
        ?) show_help; exit 1 ;;
    esac
done

# 停止模式
if [ "$ACTION" = "stop" ]; then
    stop_push
    exit 0
fi

# 启动模式：检查参数
if [ -z "$INPUT_FILE" ] || [ -z "$TARGET_IP" ] || [ -z "$START_PORT" ] || [ -z "$EXEC_TIMES" ]; then
    echo "错误: 缺少必要参数"
    show_help
    exit 1
fi

# 检查输入文件
if [ ! -f "$INPUT_FILE" ]; then
    echo "错误: 文件 $INPUT_FILE 不存在"
    exit 1
fi

# 检查 ffmpeg
if ! command -v ffmpeg &> /dev/null; then
    echo "错误: 未找到 ffmpeg"
    exit 1
fi

# 检查端口和次数是否为数字
if ! [[ "$START_PORT" =~ ^[0-9]+$ ]]; then
    echo "错误: 端口必须是正整数"
    exit 1
fi
if ! [[ "$EXEC_TIMES" =~ ^[0-9]+$ ]] || [ "$EXEC_TIMES" -le 0 ]; then
    echo "错误: 次数必须是大于0的正整数"
    exit 1
fi

# 清理旧的PID文件
rm -f "$PID_FILE"

echo "开始推流..."
echo "文件: $INPUT_FILE"
echo "目标: $TARGET_IP"
echo "端口: $START_PORT - $((START_PORT + EXEC_TIMES - 1))"
echo "数量: $EXEC_TIMES"
echo "----------------------------------------"

current_port=$START_PORT
for ((i=1; i<=EXEC_TIMES; i++)); do
    nohup ffmpeg -stream_loop -1 -re -i "$INPUT_FILE" -c copy -f mpegts -pkt_size 1316 "udp://$TARGET_IP:$current_port" &>/dev/null &
    pid=$!
    echo "$pid" >> "$PID_FILE"
    echo "[$i] PID: $pid, 端口: $current_port"
    current_port=$((current_port + 1))
    sleep 0.5
done

echo "----------------------------------------"
echo "推流完成，PID已保存到: $PID_FILE"
echo "停止推流: $0 -s"