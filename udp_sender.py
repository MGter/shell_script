import sys
import socket
import time

def printHelp():
    print("""
用法: python udp_sender.py <输入文件> <IP地址> <端口> <码率>
示例: python udp_sender.py 50_audio_program_300s.ts 127.0.0.1 25234 16600000

参数:
  输入文件: TS文件的路径
  IP地址: 目标IP地址
  端口: 目标端口号
  码率: 以比特每秒为单位的码率
""")
    sys.exit(1)

def send_udp_with_bitrate(input_file, ip, port, bitrate, packet_size=1316):
    try:
        # 验证输入参数
        if not input_file.endswith('.ts'):
            raise ValueError("输入文件必须是.ts文件")
        if not isinstance(port, int) or port < 1 or port > 65535:
            raise ValueError("端口号必须在1到65535之间")
        if not isinstance(bitrate, int) or bitrate <= 0:
            raise ValueError("码率必须为正整数")
            
        # 创建UDP套接字
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        
        # 读取输入文件
        with open(input_file, 'rb') as f:
            data = f.read()
        
        # 计算数据包发送时间间隔
        bytes_per_second = bitrate / 8
        time_per_packet = packet_size / bytes_per_second
        
        # 发送数据包
        start_time = time.time()
        for i in range(0, len(data), packet_size):
            packet = data[i:i + packet_size]
            sock.sendto(packet, (ip, port))
            time.sleep(time_per_packet)
            
        # 关闭套接字
        sock.close()
        print(f"完成向{ip}:{port}发送{input_file}，码率为{bitrate} bps")
        
    except FileNotFoundError:
        print(f"错误: 未找到输入文件 '{input_file}'")
        sys.exit(1)
    except ValueError as e:
        print(f"错误: {str(e)}")
        printHelp()
    except socket.gaierror:
        print(f"错误: 无效的IP地址 '{ip}'")
        sys.exit(1)
    except Exception as e:
        print(f"错误: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    # 检查命令行参数数量
    if len(sys.argv) != 5:
        printHelp()
    
    try:
        # 获取命令行参数
        input_file = sys.argv[1]
        ip = sys.argv[2]
        port = int(sys.argv[3])
        bitrate = int(sys.argv[4])
        
        # 执行UDP发送函数
        send_udp_with_bitrate(input_file, ip, port, bitrate)
        
    except ValueError:
        printHelp()