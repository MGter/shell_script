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
│   ├── pcap_extractor.py    # PCAP提取UDP负载（Scapy版本）
│   ├── pcap_extractor_v2.py # PCAP提取UDP负载（标准库版本）
│   ├── frame_fingerprint.py # 逐帧内容指纹对比(TS)
│   └── set_policy_routing.py # IPv4源策略路由设置
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

**set_policy_routing.py** - IPv4源策略路由设置
```bash
# 为指定网卡配置源策略路由，默认使用路由表203
sudo python3 set_policy_routing.py enp8s0

# 指定策略路由表ID
sudo python3 set_policy_routing.py enp8s0 203
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

**pcap_extractor.py** - 提取PCAP中的UDP负载（Scapy版本）
```bash
# 从PCAP提取UDP数据保存为TS
python3 pcap_extractor.py -i input.pcap -o output.ts

# 按源或目的 IP、端口过滤（逗号分隔，参数可重复）
python3 pcap_extractor.py -i input.pcap -o output.ts --ip 192.168.1.10 --port 5000
```

**pcap_extractor_v2.py** - 无第三方依赖的PCAP UDP负载提取
```bash
# 基础提取
python3 pcap_extractor_v2.py -i input.pcap -o output.ts

# 单向流提取：只要"发给某台设备"的包（避免混入反向包导致TS错位）
python3 pcap_extractor_v2.py -i input.pcap -o to31.ts --dst-ip 10.10.40.31 --dport 23233

# 多端口 / 多设备（逗号分隔，参数也可重复）
python3 pcap_extractor_v2.py -i input.pcap -o multi.ts -p 23233,23234,23235
python3 pcap_extractor_v2.py -i input.pcap -o two.ts --ip 10.10.40.31,10.10.40.32
```

两个脚本参数完全一致，输出均为命中包的 UDP 负载按抓包顺序拼接（自动裁掉以太网最小帧填充）：

- 过滤选项之间是"与"关系，同一选项内多个值是"或"关系；`--ip` / `-p` 为源或目的双向匹配，
  只要单向流请用 `--src-ip` / `--dst-ip` / `--sport` / `--dport`
- 输出先写 `<输出>.part` 再原子替换，出错时保留原有输出文件
- 默认做 MPEG-TS 188 字节对齐自检，混入其他流时打印 `[警告]` 并提示排查方向
- 无参数或 `-h` 显示帮助，帮助内含完整操作手册

**frame_fingerprint.py** - 逐帧内容指纹对比
```bash
# 计算两个TS文件每帧指纹(dHash+亮度)并绘制对比SVG
python3 network_tools/frame_fingerprint.py -f a.ts -f b.ts -o compare.svg
# 交互式可缩放图(滚轮缩放/拖拽平移/比例尺)
python3 network_tools/frame_fingerprint.py -f a.ts -f b.ts -o compare.html
# 单文件出图 / 快速预览前200帧
python3 network_tools/frame_fingerprint.py -f a.ts -o single.svg
python3 network_tools/frame_fingerprint.py -f a.ts -f b.ts -n 200
# 通过命令行给 A/B 时间轴增加偏移（单位毫秒）
python3 network_tools/frame_fingerprint.py -f a.ts -f b.ts \
  --shift-a-ms 12.5 --shift-b-ms 0 -o compare.html
```

脚本会在每个输入文件旁生成 `<输入文件>.fingerprint.csv`，其中 `pts_time`
为秒；`-n` 必须是正整数，省略时处理全部帧。

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

最低 Python 版本要求：Python 3.6。

| 脚本 | 依赖 |
|------|------|
| ffmpeg_push.sh | ffmpeg |
| udp_sender.py | scapy (仅PCAP模式) |
| multi_cap_parser.py | tcpdump, ffprobe, scapy |
| pcap_extractor.py | scapy |
| pcap_extractor_v2.py | Python 标准库（无需额外安装） |
| frame_fingerprint.py | ffmpeg, ffprobe |
| set_policy_routing.py | iproute2 (`ip`), procps (`sysctl`)，需root |
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
