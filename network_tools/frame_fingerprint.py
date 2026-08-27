#!/usr/bin/env python3
"""
逐帧内容指纹对比工具 - 计算两个TS文件每帧指纹(dHash感知哈希+亮度)，绘制对比SVG
依赖: ffmpeg / ffprobe
"""

import sys
import json
import subprocess


def show_help():
    print("""
用法: python3 frame_fingerprint.py [-f <文件>] [-f <文件>] [-o <文件>] [-n <帧数>] [-h]

选项:
  -f <文件>  输入: TS文件路径，可指定一个或两个 (必选; 一个出单路图, 两个出对比图)
  -o <文件>  输出: 指纹SVG文件路径 (默认: fingerprint_compare.svg)
  -n <帧数>  配置: 最多处理前N帧，用于快速预览 (默认: 全部)
  -h         显示帮助信息

说明:
  对每帧缩放为 9x8 灰度计算 64 位 dHash 感知哈希 + 亮度均值
  同一画面指纹一致(对编码参数差异鲁棒); 内容对齐则两条曲线重叠,
  有偏移/丢帧/重建时曲线错开或出现缺口。

示例:
  python3 frame_fingerprint.py -f 20002.ts -f 20003.ts -o compare.svg
  python3 frame_fingerprint.py -f a.ts -f b.ts -n 200
""")


# 配置参数
config = {
    "width": 9,               # 灰度块宽度
    "height": 8,              # 灰度块高度
    "pts_jump_threshold": 10000,  # PTS跳变检测阈值(90kHz)
}


def ffprobe_pts(file_path):
    """获取视频每帧原始PTS(解码序, 90kHz)"""
    p = subprocess.run(
        ["ffprobe", "-v", "error", "-select_streams", "v:0", "-show_frames",
         "-show_entries", "frame=pts", "-of", "json", file_path],
        capture_output=True, text=True)
    try:
        data = json.loads(p.stdout)
    except Exception as e:
        print(f"[错误] 解析PTS失败: {e}")
        return []
    return [f["pts"] for f in data.get("frames", []) if "pts" in f]


def ffmpeg_gray(file_path):
    """用ffmpeg把每帧缩放到灰度块并输出(-fps_mode vfr保证与ffprobe帧数一致)"""
    p = subprocess.run(
        ["ffmpeg", "-hide_banner", "-v", "error", "-i", file_path,
         "-map", "0:v:0",
         "-vf", f"scale={config['width']}:{config['height']},format=gray",
         "-fps_mode", "vfr",
         "-f", "rawvideo", "-pix_fmt", "gray", "-"],
        capture_output=True)
    return p.stdout


def blocks_hashes(raw):
    """灰度块 -> 每帧(dHash, 亮度均值)"""
    frame_size = config["width"] * config["height"]
    n = len(raw) // frame_size
    out = []
    for i in range(n):
        blk = raw[i * frame_size:(i + 1) * frame_size]
        h = 0
        for r in range(config["height"]):
            row = blk[r * config["width"]:(r + 1) * config["width"]]
            for c in range(config["width"] - 1):
                h = (h << 1) | (1 if row[c] > row[c + 1] else 0)
        out.append((h, sum(blk) / frame_size))
    return out


def fingerprints(file_path, max_frames):
    """计算一个文件每帧指纹: [(pts, 序号, dhash, luma)]"""
    pts = ffprobe_pts(file_path)
    raw = ffmpeg_gray(file_path)
    hashes = blocks_hashes(raw)
    n = min(len(pts), len(hashes))
    if len(pts) != len(hashes):
        print(f"[警告] {file_path}: PTS帧数={len(pts)} 灰度帧数={len(hashes)}，按{n}对齐")
    if max_frames and n > max_frames:
        n = max_frames
    return [(pts[i], i, hashes[i][0], hashes[i][1]) for i in range(n)]


def write_csv(file_path, rows):
    """写CSV: pts,index,dhash,luma"""
    out_file = file_path + ".fingerprint.csv"
    with open(out_file, "w") as f:
        f.write("pts,index,dhash,luma\n")
        for pts, idx, dh, luma in rows:
            f.write(f"{pts},{idx},{dh},{luma:.3f}\n")
    print(f"[输出] CSV: {out_file}")


def svg_compare(a, b, out_file):
    """画指纹对比SVG(一个或两个文件; b为空则只画文件A)"""
    p0 = a[0][0] if not b else min(a[0][0], b[0][0])

    def to_series(rows):
        return [((p - p0) / 90000.0, h / 2**64, luma / 255.0) for (p, i, h, luma) in rows]

    sa = to_series(a)
    sb = to_series(b) if b else []
    xs = [x for (x, _, _) in sa] + [x for (x, _, _) in sb]
    if not xs:
        print("[错误] 无有效数据")
        return

    xmin, xmax = min(xs), max(xs)
    W, H = 1500, 560
    L, R, T, B = 90, 1480, 48, 500
    sp = 0.55
    x2px = lambda x: L + (x - xmin) / ((xmax - xmin) or 1) * (R - L)
    y2dh = lambda y: T + (1 - y) * (B - T) * sp
    y2lu = lambda y: T + (B - T) * sp + (1 - y) * (B - T) * (1 - sp)

    def poly(points, color, width=1.3, dash=None):
        d = f' stroke-dasharray="{dash}"' if dash else ""
        pts = " ".join(f"{x2px(x):.1f},{y2dh(y):.1f}" for (x, y) in points)
        return f'<polyline fill="none" stroke="{color}" stroke-width="{width}"{d} points="{pts}"/>'

    def poly2(points, color):
        pts = " ".join(f"{x2px(x):.1f},{y2lu(z):.1f}" for (x, z) in points)
        return f'<polyline fill="none" stroke="{color}" stroke-width="1" points="{pts}"/>'

    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}">',
        f'<rect width="{W}" height="{H}" fill="#fff"/>',
        f'<text x="{W/2}" y="26" text-anchor="middle" font-size="20" font-weight="bold" font-family="Arial">Frame fingerprint {("compare" if sb else "single")}</text>',
        f'<text x="{W/2}" y="{H-8}" text-anchor="middle" font-size="13" font-family="Arial">PTS relative (s)</text>',
        f'<text x="6" y="{T+(B-T)*0.25}" font-size="12" fill="#c0392b" font-family="Arial">dHash</text>',
        f'<text x="6" y="{T+(B-T)*sp+(B-T)*0.25}" font-size="12" fill="#2f6f63" font-family="Arial">Luma</text>',
    ]
    nseg = 8
    for i in range(nseg + 1):
        xv = xmin + (xmax - xmin) * i / nseg
        px = x2px(xv)
        parts.append(f'<line x1="{px:.1f}" y1="{T}" x2="{px:.1f}" y2="{B}" stroke="#ece8e2"/>')
        parts.append(f'<text x="{px+3:.1f}" y="{B+14}" font-size="10" fill="#888" font-family="Arial">{xv:.2f}</text>')
    for yv in (0.0, 0.5, 1.0):
        parts.append(f'<line x1="{L}" y1="{y2dh(yv):.1f}" x2="{R}" y2="{y2dh(yv):.1f}" stroke="#ece8e2"/>')
    parts.append(poly([(x, y) for (x, y, _) in sa], "#c0392b", 1.3))
    if sb:
        parts.append(poly([(x, y) for (x, y, _) in sb], "#2980b9", 1.3, dash="5,3"))
    parts.append(poly2([(x, z) for (x, _, z) in sa], "#e8a49b"))
    if sb:
        parts.append(poly2([(x, z) for (x, _, z) in sb], "#9bc7e8"))
    ly = B + 22
    parts.append(f'<rect x="{L}" y="{ly}" width="10" height="10" fill="#c0392b"/>')
    parts.append(f'<text x="{L+16}" y="{ly+10}" font-size="12" font-family="Arial">File A dHash</text>')
    if sb:
        parts.append(f'<rect x="{L+150}" y="{ly}" width="10" height="10" fill="#2980b9"/>')
        parts.append(f'<text x="{L+166}" y="{ly+10}" font-size="12" font-family="Arial">File B dHash (虚线)</text>')
    parts.append(f'<text x="{L+360}" y="{ly+10}" font-size="12" fill="#888" font-family="Arial">细线=亮度: A #e8a49b' + (' B #9bc7e8' if sb else '') + '</text>')
    parts.append("</svg>")
    with open(out_file, "w") as f:
        f.write("\n".join(parts))
    print(f"[输出] SVG: {out_file}")


if __name__ == "__main__":
    # 无参数或帮助模式
    if len(sys.argv) == 1 or '-h' in sys.argv:
        show_help()
        sys.exit(0)

    import argparse
    import os

    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument('-f', dest='input', action='append', help='输入: TS文件(可指定两个)')
    parser.add_argument('-o', dest='output', default='fingerprint_compare.svg', help='输出: SVG文件')
    parser.add_argument('-n', dest='max_frames', type=int, default=None, help='配置: 最大帧数')
    args = parser.parse_args()

    # 参数验证
    if not args.input:
        print("[错误] 缺少输入文件 (-f)")
        show_help()
        sys.exit(1)
    for f in args.input:
        if not os.path.exists(f):
            print(f"[错误] 文件不存在: {f}")
            sys.exit(1)
    if len(args.input) > 2:
        print("[错误] 最多两个输入文件")
        sys.exit(1)

    rows_all = {}
    for f in args.input:
        print(f"[处理] {f}")
        rows = fingerprints(f, args.max_frames)
        print(f"  帧数={len(rows)}")
        if rows:
            for i in range(1, len(rows)):
                d = rows[i][0] - rows[i - 1][0]
                if d > config["pts_jump_threshold"]:
                    print(f"  PTS跳变 idx {rows[i-1][1]}->{rows[i][1]}: Δ{d} (={d/90:.0f} ms)")
        rows_all[f] = rows
        write_csv(f, rows)

    if len(args.input) >= 1:
        svg_compare(rows_all[args.input[0]],
                    rows_all[args.input[1]] if len(args.input) == 2 else [],
                    args.output)