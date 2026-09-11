#!/usr/bin/env python3
"""
PCAP UDP 负载提取工具（标准库版本）。

只使用 Python 标准库，不依赖 Scapy。支持 classic pcap 和常见的 pcapng
文件，以及 Ethernet、Linux cooked、RAW 和 loopback 链路类型。

支持按源/目的 IP 与端口过滤（逗号分隔列表），并在输出时做 MPEG-TS
188 字节对齐自检，发现混流立即告警。
"""

import argparse
import ipaddress
import os
import struct
import sys

SCRIPT_NAME = os.path.basename(__file__)
PCAP_MAGICS = {
    b"\xd4\xc3\xb2\xa1",  # microsecond, little endian
    b"\xa1\xb2\xc3\xd4",  # microsecond, big endian
    b"\x4d\x3c\xb2\xa1",  # nanosecond, little endian
    b"\xa1\xb2\x3c\x4d",  # nanosecond, big endian
}
PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"
MAX_BLOCK_BYTES = 256 * 1024 * 1024
TS_PACKET_SIZE = 188
TS_SYNC_BYTE = 0x47


class PcapError(ValueError):
    """PCAP 文件格式或内容错误。"""


def _read_exact(file_obj, size):
    data = file_obj.read(size)
    if len(data) != size:
        raise PcapError("PCAP 文件在包数据结束前意外结束")
    return data


def _iter_classic_pcap(file_obj):
    """逐包读取 classic pcap，返回 (链路类型, 原始帧)。"""
    header = _read_exact(file_obj, 24)
    magic = header[:4]
    formats = {
        b"\xd4\xc3\xb2\xa1": "<",  # microsecond, little endian
        b"\xa1\xb2\xc3\xd4": ">",  # microsecond, big endian
        b"\x4d\x3c\xb2\xa1": "<",  # nanosecond, little endian
        b"\xa1\xb2\x3c\x4d": ">",  # nanosecond, big endian
    }
    endian = formats.get(magic)
    if endian is None:
        raise PcapError("不是支持的 classic pcap 文件")

    _version_major, _version_minor, _tz, _sigfigs, _snaplen, linktype = struct.unpack(
        endian + "HHiiii", header[4:]
    )

    while True:
        packet_header = file_obj.read(16)
        if not packet_header:
            return
        if len(packet_header) != 16:
            raise PcapError("PCAP 包头不完整")
        _ts_sec, _ts_fraction, captured_len, _original_len = struct.unpack(
            endian + "IIII", packet_header
        )
        # 防止损坏的长度字段造成超大内存分配或长时间等待。
        if captured_len > MAX_BLOCK_BYTES:
            raise PcapError(f"单个包长度异常: {captured_len} 字节")
        yield linktype, _read_exact(file_obj, captured_len)


def _iter_pcapng(file_obj):
    """逐包读取 pcapng 的 Enhanced/旧式 Packet Block。"""
    endian = None
    linktypes = {}

    while True:
        block_header = file_obj.read(8)
        if not block_header:
            return
        if len(block_header) != 8:
            raise PcapError("pcapng 块头不完整")

        block_type_raw = block_header[:4]
        total_length_raw = block_header[4:8]
        # Section Header Block 的字节序标记位于块头之后，需先读出块体。
        # 其他块沿用当前 section 的字节序。
        if block_type_raw == PCAPNG_MAGIC:
            # SHB 的长度字段总是可按任一端序解释，先尝试读取两种结果。
            little_length = struct.unpack("<I", total_length_raw)[0]
            big_length = struct.unpack(">I", total_length_raw)[0]
            total_length = little_length if 16 <= little_length <= MAX_BLOCK_BYTES else big_length
            if total_length < 16 or total_length > MAX_BLOCK_BYTES:
                raise PcapError(f"pcapng 块长度异常: {total_length}")
            remaining = _read_exact(file_obj, total_length - 8)
            body = remaining[:-4]
            byte_order_magic = body[:4]
            if byte_order_magic == b"\x4d\x3c\x2b\x1a":
                endian = "<"
            elif byte_order_magic == b"\x1a\x2b\x3c\x4d":
                endian = ">"
            else:
                raise PcapError("pcapng 字节序标记无效")
        else:
            if endian is None:
                raise PcapError("pcapng 文件缺少 Section Header Block")
            block_type = struct.unpack(endian + "I", block_type_raw)[0]
            total_length = struct.unpack(endian + "I", total_length_raw)[0]
            if total_length < 16 or total_length > MAX_BLOCK_BYTES:
                raise PcapError(f"pcapng 块长度异常: {total_length} 字节")
            remaining = _read_exact(file_obj, total_length - 8)
            body = remaining[:-4]

        trailing_length = struct.unpack(endian + "I", remaining[-4:])[0]
        if trailing_length != total_length:
            raise PcapError("pcapng 块首尾长度不一致")

        block_type = struct.unpack(endian + "I", block_type_raw)[0]
        if block_type == 0x0A0D0D0A:
            linktypes = {}
            continue

        if block_type == 0x00000001:  # Interface Description Block
            if len(body) < 8:
                raise PcapError("pcapng 接口描述块不完整")
            interface_id = len(linktypes)
            linktypes[interface_id] = struct.unpack(endian + "H", body[:2])[0]

        elif block_type == 0x00000006:  # Enhanced Packet Block
            if len(body) < 20:
                raise PcapError("pcapng Enhanced Packet Block 不完整")
            interface_id, _ts_high, _ts_low, captured_len, _original_len = struct.unpack(
                endian + "IIIII", body[:20]
            )
            if captured_len > len(body) - 20:
                raise PcapError("pcapng 包长度超出块边界")
            if interface_id not in linktypes:
                continue
            yield linktypes[interface_id], body[20:20 + captured_len]

        elif block_type == 0x00000002:  # legacy Packet Block
            if len(body) < 20:
                raise PcapError("pcapng Packet Block 不完整")
            interface_id = struct.unpack(endian + "H", body[:2])[0]
            captured_len = struct.unpack(endian + "I", body[12:16])[0]
            if captured_len > len(body) - 20 or interface_id not in linktypes:
                continue
            yield linktypes[interface_id], body[20:20 + captured_len]

        elif block_type == 0x00000003:  # Simple Packet Block
            # 该块没有接口编号；只有一个接口时可以安全使用它。
            if len(body) < 4 or len(linktypes) != 1:
                continue
            original_len = struct.unpack(endian + "I", body[:4])[0]
            captured_len = min(original_len, len(body) - 4)
            yield next(iter(linktypes.values())), body[4:4 + captured_len]


def _iter_packets(input_file):
    """自动识别 pcap/pcapng，并逐包返回 (链路类型, 原始帧)。"""
    with open(input_file, "rb") as file_obj:
        magic = file_obj.read(4)
        file_obj.seek(0)
        if magic in PCAP_MAGICS:
            yield from _iter_classic_pcap(file_obj)
        elif magic == PCAPNG_MAGIC:
            yield from _iter_pcapng(file_obj)
        else:
            raise PcapError("无法识别文件格式，仅支持 pcap 和 pcapng")


def _network_payload(frame, linktype):
    """去掉链路层头，返回 (EtherType, 网络层数据)。"""
    if linktype == 1:  # DLT_EN10MB, Ethernet
        if len(frame) < 14:
            return None
        protocol = struct.unpack("!H", frame[12:14])[0]
        offset = 14
        # 处理 QinQ/802.1Q VLAN 标签。
        while protocol in (0x8100, 0x88A8, 0x9100):
            if len(frame) < offset + 4:
                return None
            protocol = struct.unpack("!H", frame[offset + 2:offset + 4])[0]
            offset += 4
        return protocol, frame[offset:]

    if linktype in (0, 108):  # DLT_NULL / DLT_LOOP
        if len(frame) < 4:
            return None
        version = frame[4] >> 4 if len(frame) > 4 else 0
        protocol = 0x0800 if version == 4 else 0x86DD if version == 6 else None
        return (protocol, frame[4:]) if protocol is not None else None

    if linktype == 101:  # DLT_RAW
        if not frame:
            return None
        version = frame[0] >> 4
        protocol = 0x0800 if version == 4 else 0x86DD if version == 6 else None
        return (protocol, frame) if protocol is not None else None

    if linktype == 113:  # DLT_LINUX_SLL
        return (struct.unpack("!H", frame[14:16])[0], frame[16:]) if len(frame) >= 16 else None

    if linktype == 276:  # DLT_LINUX_SLL2
        return (struct.unpack("!H", frame[:2])[0], frame[20:]) if len(frame) >= 20 else None

    return None


def _parse_udp(frame, linktype):
    """解析 UDP，返回 (源 IP, 目的 IP, 源端口, 目的端口, 负载)。"""
    network = _network_payload(frame, linktype)
    if network is None:
        return None
    protocol, data = network

    if protocol == 0x0800:  # IPv4
        if len(data) < 20 or data[0] >> 4 != 4:
            return None
        header_len = (data[0] & 0x0F) * 4
        if header_len < 20 or len(data) < header_len:
            return None
        total_len = struct.unpack("!H", data[2:4])[0]
        if total_len < header_len:
            return None
        packet_end = min(len(data), total_len)
        # 非首个 IPv4 分片没有 UDP 头。
        fragment_offset = struct.unpack("!H", data[6:8])[0] & 0x1FFF
        if data[9] != 17 or fragment_offset or packet_end < header_len + 8:
            return None
        source = ipaddress.IPv4Address(data[12:16])
        destination = ipaddress.IPv4Address(data[16:20])
        udp = data[header_len:packet_end]

    elif protocol == 0x86DD:  # IPv6
        if len(data) < 40 or data[0] >> 4 != 6:
            return None
        source = ipaddress.IPv6Address(data[8:24])
        destination = ipaddress.IPv6Address(data[24:40])
        next_header = data[6]
        offset = 40
        payload_length = struct.unpack("!H", data[4:6])[0]
        packet_end = min(len(data), 40 + payload_length) if payload_length else len(data)
        # 跳过常见 IPv6 扩展头，直到 UDP。
        while next_header != 17:
            if next_header in (0, 43, 60):  # Hop-by-Hop, Routing, Destination
                if offset + 2 > packet_end:
                    return None
                extension_len = (data[offset + 1] + 1) * 8
            elif next_header == 44:  # Fragment
                if offset + 8 > packet_end:
                    return None
                fragment_field = struct.unpack("!H", data[offset + 2:offset + 4])[0]
                if fragment_field & 0xFFF8:
                    return None
                extension_len = 8
            elif next_header == 51:  # Authentication Header
                if offset + 2 > packet_end:
                    return None
                extension_len = (data[offset + 1] + 2) * 4
            else:  # ESP、TCP 等无法继续解析为 UDP
                return None
            if offset + extension_len > packet_end:
                return None
            next_header = data[offset]
            offset += extension_len
        if offset + 8 > packet_end:
            return None
        udp = data[offset:packet_end]

    else:
        return None

    source_port, destination_port, udp_len = struct.unpack("!HHH", udp[:6])
    if udp_len < 8:
        return None
    payload_end = min(len(udp), udp_len)
    return source, destination, source_port, destination_port, udp[8:payload_end]


def _detect_format(input_file):
    """按文件头识别格式，返回 'pcap' / 'pcapng'；无法识别返回 None。"""
    if os.path.isdir(input_file):
        raise PcapError(f"输入是目录而不是文件: {input_file}")
    with open(input_file, "rb") as file_obj:
        magic = file_obj.read(4)
    if not magic:
        raise PcapError("文件为空")
    if magic in PCAP_MAGICS:
        return "pcap"
    if magic == PCAPNG_MAGIC:
        return "pcapng"
    return None


def _parse_list(values, parser, label):
    """摊平可重复、可逗号分隔的参数，逐项校验并保序去重。"""
    parsed_values = []
    for raw in values or []:
        for piece in str(raw).split(","):
            piece = piece.strip()
            if not piece:
                raise ValueError(f"{label}中存在空项: {raw}")
            try:
                value = parser(piece)
            except ValueError:
                raise ValueError(f"无效的{label}: {piece}") from None
            if value not in parsed_values:
                parsed_values.append(value)
    return parsed_values


def _parse_port_list(values, label):
    def to_port(piece):
        if not piece.isdigit():
            raise ValueError(f"无效的{label}: {piece}")
        return int(piece)

    ports = _parse_list(values, to_port, label)
    for port in ports:
        if not 1 <= port <= 65535:
            raise ValueError(f"{label}必须在 1 到 65535 之间: {port}")
    return ports


def parse_filters(values):
    """把命令行原始值转成过滤条件字典，非法输入抛 ValueError。"""
    return {
        "ip": _parse_list(values.get("ip"), ipaddress.ip_address, "IP 地址"),
        "src_ip": _parse_list(values.get("src_ip"), ipaddress.ip_address, "源 IP 地址"),
        "dst_ip": _parse_list(values.get("dst_ip"), ipaddress.ip_address, "目的 IP 地址"),
        "port": _parse_port_list(values.get("port"), "端口"),
        "sport": _parse_port_list(values.get("sport"), "源端口"),
        "dport": _parse_port_list(values.get("dport"), "目的端口"),
    }


FILTER_LABELS = (
    ("ip", "IP(源或目的)"),
    ("src_ip", "源 IP"),
    ("dst_ip", "目的 IP"),
    ("port", "端口(源或目的)"),
    ("sport", "源端口"),
    ("dport", "目的端口"),
)


def _build_matcher(filters):
    """选项之间取"与"，同一选项内多个值取"或"。"""
    conditions = {key: set(filters.get(key) or ()) for key, _label in FILTER_LABELS}
    ip_any = conditions["ip"]
    ip_src = conditions["src_ip"]
    ip_dst = conditions["dst_ip"]
    port_any = conditions["port"]
    port_src = conditions["sport"]
    port_dst = conditions["dport"]

    def match(source, destination, source_port, destination_port):
        if ip_any and source not in ip_any and destination not in ip_any:
            return False
        if ip_src and source not in ip_src:
            return False
        if ip_dst and destination not in ip_dst:
            return False
        if port_any and source_port not in port_any and destination_port not in port_any:
            return False
        if port_src and source_port not in port_src:
            return False
        if port_dst and destination_port not in port_dst:
            return False
        return True

    return match


class TsChecker:
    """写入过程中统计 188 字节对齐处的 MPEG-TS 同步字。"""

    def __init__(self):
        self.written = 0
        self.bad = 0

    def feed(self, chunk):
        if not chunk:
            return
        offset = (-self.written) % TS_PACKET_SIZE
        for index in range(offset, len(chunk), TS_PACKET_SIZE):
            if chunk[index] != TS_SYNC_BYTE:
                self.bad += 1
        self.written += len(chunk)

    @property
    def blocks(self):
        return self.written // TS_PACKET_SIZE

    def report(self):
        """返回自检结论（多行文本列表）。"""
        if self.written == 0:
            return ["[校验] 未提取到任何负载，请检查过滤条件"]
        if self.written % TS_PACKET_SIZE:
            return [
                f"[警告] 输出 {self.written} 字节，不是 188 的整数倍（余 {self.written % TS_PACKET_SIZE}）",
                "[提示] 常见原因: 过滤条件混入了反方向或其他流的包",
                "       可用 --src-ip / --dst-ip / --sport / --dport 限定单向流后重试",
            ]
        if self.bad == 0:
            return [
                f"[校验] TS 对齐正常: {self.blocks} 个 188 字节包，同步字 0x47 全部命中"
            ]
        return [
            f"[警告] TS 对齐异常: {self.blocks} 个包中 {self.bad} 个同步字不是 0x47"
            f"（{self.bad / self.blocks:.1%}）",
            "[提示] 常见原因: 过滤条件混入了反方向或其他流的包",
            "       可用 --src-ip / --dst-ip / --sport / --dport 限定单向流后重试",
        ]


def _temp_path(output_file):
    """输出不是普通文件（/dev/null、FIFO 等）时直接写目标，其余走临时文件。"""
    if os.path.exists(output_file) and not os.path.isfile(output_file):
        return output_file
    return f"{output_file}.part"


def _discard_temp(temp_file, output_file):
    if temp_file == output_file:
        return
    try:
        if os.path.exists(temp_file):
            os.remove(temp_file)
    except OSError:
        pass


def extract_udp_payload(input_file, output_file, filters, ts_check=True):
    """提取 UDP 负载，可按源/目的 IP 和端口过滤，并按需做 TS 自检。"""
    try:
        matcher = _build_matcher(filters)
    except ValueError as exc:
        print(f"[错误] {exc}")
        return False

    # 先确认输入可用，再动输出文件，避免破坏已有结果。
    if not os.path.exists(input_file):
        print(f"[错误] 文件不存在: {input_file}")
        return False
    if os.path.realpath(input_file) == os.path.realpath(output_file):
        print("[错误] 输入文件和输出文件不能相同")
        return False
    try:
        file_format = _detect_format(input_file)
    except (OSError, PcapError) as exc:
        print(f"[错误] {exc}")
        return False
    if file_format is None:
        print("[错误] 无法识别文件格式，仅支持 pcap 和 pcapng")
        return False

    count_total = 0
    count_udp = 0
    count_matched = 0
    checker = TsChecker() if ts_check else None

    print(f"[读取] {input_file}（{file_format}）")
    for key, label in FILTER_LABELS:
        values = filters.get(key) or []
        if values:
            print(f"[过滤] {label}: " + ", ".join(str(value) for value in values))

    temp_file = _temp_path(output_file)
    try:
        with open(temp_file, "wb") as output:
            for linktype, frame in _iter_packets(input_file):
                count_total += 1
                if count_total % 10000 == 0:
                    print(
                        f"  已处理 {count_total} 包, UDP {count_udp}, 匹配 {count_matched}",
                        end="\r",
                    )
                parsed = _parse_udp(frame, linktype)
                if parsed is None:
                    continue
                count_udp += 1
                source, destination, source_port, destination_port, payload = parsed
                if not matcher(source, destination, source_port, destination_port):
                    continue
                output.write(payload)
                if checker is not None:
                    checker.feed(payload)
                count_matched += 1

        if count_total == 0:
            raise PcapError("未从文件中解析到任何数据包（文件可能为空或被截断）")
        if temp_file != output_file:
            os.replace(temp_file, output_file)
    except (OSError, PcapError, struct.error) as exc:
        _discard_temp(temp_file, output_file)
        print(f"[错误] {exc}")
        return False

    print()
    if checker is not None:
        for line in checker.report():
            print(line)
    print(f"[完成] 总包: {count_total}, UDP: {count_udp}, 输出: {count_matched}")
    print(f"[输出] {output_file}")
    return True


HELP_TEMPLATE = """用法: python3 {script} [-i <输入>] [-o <输出>] [过滤选项] [--no-ts-check] [-h]

选项:
  -i, --input <文件>      输入: PCAP/PCAPNG 文件路径 (必选)
  -o, --output <文件>     输出: 提取的 TS 文件路径 (默认: output.ts)
  --ip <IP列表>           过滤: 源或目的 IP，逗号分隔，可重复
  --src-ip <IP列表>       过滤: 仅源 IP，逗号分隔，可重复
  --dst-ip <IP列表>       过滤: 仅目的 IP，逗号分隔，可重复
  -p, --port <端口列表>   过滤: 源或目的端口 1-65535，逗号分隔，可重复
  --sport <端口列表>      过滤: 仅源端口，逗号分隔，可重复
  --dport <端口列表>      过滤: 仅目的端口，逗号分隔，可重复
  --no-ts-check           配置: 关闭输出的 TS 188 字节对齐自检
  -h, --help              显示帮助信息

过滤规则:
  1. 选项之间是"与"关系；同一选项内多个值是"或"关系
  2. 逗号分隔与重复传递等价: --ip A,B 等同 --ip A --ip B
  3. --ip / -p 是"源或目的"双向匹配；只要单向流请用
     --src-ip / --dst-ip / --sport / --dport

操作手册:
  [1] 提取整份抓包的全部 UDP 负载
      python3 {script} -i capture.pcap -o all.ts
  [2] 提取"发给某台设备"的单向流（推荐先这样跑）
      python3 {script} -i capture.pcap -o to31.ts --dst-ip 10.10.40.31
      双向会话里再加端口限定，结果最精确:
      python3 {script} -i capture.pcap -o to31.ts --dst-ip 10.10.40.31 --dport 23233
  [3] 按单端口/多端口提取
      python3 {script} -i capture.pcap -o p23233.ts -p 23233
      python3 {script} -i capture.pcap -o multi.ts -p 23233,23234,23235
  [4] 按多台设备提取
      python3 {script} -i capture.pcap -o two.ts --ip 10.10.40.31,10.10.40.32
  [5] 只要抓包机自己发出的流量（出方向）
      python3 {script} -i capture.pcap -o out.ts --src-ip 10.10.40.190
  [6] 输出不是 MPEG-TS 时关闭自检
      python3 {script} -i capture.pcap -o raw.bin --no-ts-check

输出说明:
  · 命中包的 UDP 负载按抓包顺序拼接，不含 IP/UDP/RTP 头
  · 自动裁掉以太网最小帧填充，不写入多余补零字节
  · 先校验输入格式，再写入 <输出>.part 并原子替换，
    出错时保留原有输出文件，不留半截文件
  · 默认做 188 字节对齐自检，异常时打印 [警告] 并给出排查建议

依赖:
  Python 标准库（无需额外安装）；数据量大时本脚本快于 pcap_extractor.py

退出码:
  0 成功（含 [警告]）    1 参数错误 / 文件不存在 / 格式无法识别

示例:
  python3 {script} -i test.pcap -o output.ts
  python3 {script} -i capture.pcap -o to31.ts --dst-ip 10.10.40.31 --dport 23233
"""


def show_help():
    print(HELP_TEMPLATE.format(script=SCRIPT_NAME))


def main():
    if len(sys.argv) == 1 or "-h" in sys.argv or "--help" in sys.argv:
        show_help()
        return 0

    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("-i", "--input", dest="input", required=True)
    parser.add_argument("-o", "--output", dest="output", default="output.ts")
    parser.add_argument("--ip", dest="ip", action="append", metavar="<IP列表>")
    parser.add_argument("--src-ip", dest="src_ip", action="append", metavar="<IP列表>")
    parser.add_argument("--dst-ip", dest="dst_ip", action="append", metavar="<IP列表>")
    parser.add_argument("-p", "--port", dest="port", action="append", metavar="<端口列表>")
    parser.add_argument("--sport", dest="sport", action="append", metavar="<端口列表>")
    parser.add_argument("--dport", dest="dport", action="append", metavar="<端口列表>")
    parser.add_argument("--no-ts-check", dest="ts_check", action="store_false", default=True)
    parser.add_argument("-h", "--help", dest="help", action="store_true")
    try:
        args = parser.parse_args()
    except SystemExit:
        show_help()
        return 1
    if args.help:
        show_help()
        return 0

    raw_filters = {
        key: getattr(args, key) for key, _label in FILTER_LABELS
    }
    try:
        filters = parse_filters(raw_filters)
    except ValueError as exc:
        print(f"[错误] {exc}")
        return 1

    ok = extract_udp_payload(args.input, args.output, filters, args.ts_check)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
