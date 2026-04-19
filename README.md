# Shell Script 工具集

运维和测试工具脚本集合，包含Shell和Python脚本，主要用于网络测试、系统监控和数据处理。

作者: MGter

---

## 目录结构

```
shell_script/
├── file_tools/              # 文件处理工具
│   ├── so_link.sh           # .so库文件软链接生成
│   └── config_update.sh     # 配置文件备份更新
│
├── network_tools/           # 网络测试工具
│   ├── ffmpeg_push.sh       # ffmpeg多端口UDP推流
│   ├── udp_sender.py        # UDP发送工具(TS流/PCAP回放)
│   ├── multi_cap_parser.py  # 多端口并行抓包+TS流解析
│   └── pcap_extractor.py    # PCAP提取UDP负载
│
├── sysadmin_tools/          # 系统运维工具
│   ├── auto_clean.sh        # 目录自动清理守护脚本
│   ├── memwatch_parser.sh   # 内存监控数据转CSV
│   └── sysinfo_checker.py   # 系统信息检查(输出JSON)
│
└── other_tools/             # 其他工具
    └── image_measurer.py    # 图像测量工具(身份证参考)
```

---

## 快速使用

### 文件处理工具

**so_link.sh** - 创建.so库文件软链接链
```bash
# 处理当前目录下的 .so.x.y.z 文件
so_link.sh

# 处理指定目录
so_link.sh -d /usr/lib
```

**config_update.sh** - 配置文件备份更新
```bash
# 使用默认路径 (./conf → ~)
config_update.sh

# 指定源目录和目标目录
config_update.sh -i ./config -d /etc/app
```

---

### 网络测试工具

**ffmpeg_push.sh** - ffmpeg多端口UDP推流
```bash
# 推流5次，端口从30000递增
ffmpeg_push.sh -f input.ts -i 127.0.0.1 -p 30000 -n 5

# 停止所有推流进程
ffmpeg_push.sh -s
```

**udp_sender.py** - UDP发送工具
```bash
# TS流按码率发送
python3 udp_sender.py -f input.ts -i 127.0.0.1 -p 5000 -b 16600000

# TS流循环发送
python3 udp_sender.py -f input.ts -i 127.0.0.1 -p 5000 -b 16600000 -n 5

# PCAP回放
python3 udp_sender.py -f input.pcap -i 192.168.1.1 -p 13000

# PCAP回放(保留时序)
python3 udp_sender.py -f input.pcap -i 127.0.0.1 -p 5000 --preserve-timing
```

**multi_cap_parser.py** - 多端口抓包+解析
```bash
# 抓包多个端口并解析TS流时间戳
python3 multi_cap_parser.py -i 192.168.1.1 -p 30000,30001,30002 -d 10
```

**pcap_extractor.py** - 提取PCAP中的UDP负载
```bash
# 从PCAP提取UDP数据保存为TS
python3 pcap_extractor.py -i input.pcap -o output.ts
```

---

### 系统运维工具

**auto_clean.sh** - 目录自动清理
```bash
# 监控当前目录，超过20文件自动删除最旧
auto_clean.sh

# 自定义参数
auto_clean.sh -d /tmp -n 10 -t 30
```

**memwatch_parser.sh** - 内存监控数据解析
```bash
# 转换日志为CSV
memwatch_parser.sh -i memwatch.log

# 指定输出文件
memwatch_parser.sh -i memwatch.log -o result.csv
```

**sysinfo_checker.py** - 系统信息检查
```bash
# 检查全部信息，输出到JSON
python3 sysinfo_checker.py

# 只检查部分项目
python3 sysinfo_checker.py --items os,cpu,mem,disk
```

---

### 其他工具

**image_measurer.py** - 图像测量
```bash
# 以身份证宽度(85.6mm)为参考测量物体
python3 image_measurer.py -i photo.jpg
```

---

## 依赖说明

| 脚本 | 依赖 |
|------|------|
| ffmpeg_push.sh | ffmpeg |
| udp_sender.py | scapy (仅PCAP模式) |
| multi_cap_parser.py | tcpdump, ffprobe, scapy |
| pcap_extractor.py | scapy |
| image_measurer.py | opencv-python, numpy |
| sysinfo_checker.py | dmidecode (需root) |

安装依赖:
```bash
# Python依赖
pip install scapy opencv-python numpy

# 系统工具
apt install ffmpeg tcpdump  # Ubuntu/Debian
yum install ffmpeg tcpdump  # CentOS/RHEL
```

---

## 规范说明

所有脚本遵循统一规范:

1. **无参数运行显示帮助** - 直接运行脚本即可查看用法
2. **参数命名统一** - `-f`文件, `-i`IP, `-p`端口, `-d`目录, `-o`输出, `-n`次数, `-h`帮助
3. **输入输出标记** - 帮助信息标注 `输入:`、`输出:`、`目标:`

详见 [SCRIPT_STYLE.md](SCRIPT_STYLE.md)