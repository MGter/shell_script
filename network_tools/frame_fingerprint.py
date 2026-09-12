#!/usr/bin/env python3
"""
逐帧内容指纹对比工具 - 计算一个或两个TS文件的逐帧指纹(dHash感知哈希+亮度)，绘制对比SVG
兼容 Python 3.6 及以上版本。
依赖: ffmpeg / ffprobe
"""

import sys
import json
import math
import subprocess


class ToolError(RuntimeError):
    """外部工具或输入数据处理失败。"""


def show_help():
    print("""
用法: python3 frame_fingerprint.py [-f <文件>] [-f <文件>] [-o <文件>] [-n <帧数>] [-h]

选项:
  -f <文件>  输入: TS文件路径，可指定一个或两个 (必选; 一个出单路图, 两个出对比图)
  -o <文件>  输出: 指纹图文件; .html为可缩放交互图(滚轮缩放/拖拽/比例尺), .svg为静态图 (默认: fingerprint_compare.svg)
  -n <帧数>  配置: 最多处理前N帧，用于快速预览 (正整数; 默认: 全部)
  --shift-a-ms <毫秒>  配置: File A横向偏移; 正值向右/时间变晚，负值向左/时间变早 (默认: 0)
  --shift-b-ms <毫秒>  配置: File B横向偏移; 正值向右/时间变晚，负值向左/时间变早 (默认: 0)
  -h         显示帮助信息

说明:
  对每帧缩放为 9x8 灰度计算 64 位 dHash 感知哈希 + 亮度均值
  横轴使用 ffprobe 返回的 PTS 时间(秒)，不假定输入流一定使用 90kHz time base
  同一画面指纹一致(对编码参数差异鲁棒); 内容对齐则两条曲线重叠,
  有偏移/丢帧/重建时曲线错开或出现缺口。每个输入还会生成同目录下的
  <输入文件>.fingerprint.csv，保存逐帧指纹数据。

示例:
  python3 frame_fingerprint.py -f 20002.ts -f 20003.ts -o compare.svg
  python3 frame_fingerprint.py -f a.ts -f b.ts -n 200
""")


# 配置参数
config = {
    "width": 9,               # 灰度块宽度
    "height": 8,              # 灰度块高度
    "pts_jump_threshold": 0.1,    # PTS跳变检测阈值(秒)
}


def _command_detail(stderr):
    """提取外部命令的可读错误信息。"""
    if isinstance(stderr, bytes):
        stderr = stderr.decode("utf-8", errors="replace")
    return (stderr or "").strip() or "无错误信息"


def ffprobe_pts(file_path):
    """获取视频每帧 PTS 时间(秒)，并保留没有时间戳的帧位置。"""
    try:
        p = subprocess.run(
            ["ffprobe", "-v", "error", "-select_streams", "v:0", "-show_frames",
             "-show_entries", "frame=pts_time,best_effort_timestamp_time", "-of", "json", file_path],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            universal_newlines=True, check=False)
    except OSError as exc:
        raise ToolError(f"调用 ffprobe 失败: {exc}") from exc
    if p.returncode != 0:
        raise ToolError(f"ffprobe 读取 {file_path} 失败: {_command_detail(p.stderr)}")
    try:
        data = json.loads(p.stdout)
    except (TypeError, json.JSONDecodeError) as exc:
        raise ToolError(f"解析 {file_path} 的 PTS 失败: {exc}") from exc

    timestamps = []
    if not isinstance(data, dict):
        raise ToolError(f"解析 {file_path} 的 PTS 失败: JSON 根节点不是对象")
    frames = data.get("frames", [])
    if not isinstance(frames, list):
        raise ToolError(f"解析 {file_path} 的 PTS 失败: frames 不是数组")
    for frame in frames:
        if not isinstance(frame, dict):
            timestamps.append(None)
            continue
        value = frame.get("pts_time")
        if value is None:
            value = frame.get("best_effort_timestamp_time")
        if value is None or value == "N/A":
            timestamps.append(None)
            continue
        try:
            timestamp = float(value)
            timestamps.append(timestamp if math.isfinite(timestamp) else None)
        except (TypeError, ValueError):
            timestamps.append(None)
    return timestamps


def ffmpeg_gray(file_path):
    """用ffmpeg把每帧缩放到灰度块并输出(-fps_mode vfr保证与ffprobe帧数一致)"""
    try:
        p = subprocess.run(
            ["ffmpeg", "-hide_banner", "-nostdin", "-v", "error", "-i", file_path,
             "-map", "0:v:0",
             "-vf", f"scale={config['width']}:{config['height']},format=gray",
             "-fps_mode", "vfr",
             "-f", "rawvideo", "-pix_fmt", "gray", "-"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    except OSError as exc:
        raise ToolError(f"调用 ffmpeg 失败: {exc}") from exc
    if p.returncode != 0:
        raise ToolError(f"ffmpeg 解码 {file_path} 失败: {_command_detail(p.stderr)}")
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
    """计算一个文件每帧指纹: [(pts_time秒, 序号, dhash, luma)]"""
    if max_frames is not None and max_frames <= 0:
        raise ValueError("最大帧数必须是正整数")
    pts = ffprobe_pts(file_path)
    raw = ffmpeg_gray(file_path)
    hashes = blocks_hashes(raw)
    n = min(len(pts), len(hashes))
    if len(pts) != len(hashes):
        print(f"[警告] {file_path}: PTS帧数={len(pts)} 灰度帧数={len(hashes)}，按{n}对齐")
    if max_frames is not None and n > max_frames:
        n = max_frames
    rows = []
    missing_pts = 0
    for i in range(n):
        if pts[i] is None:
            missing_pts += 1
            continue
        rows.append((pts[i], i, hashes[i][0], hashes[i][1]))
    if missing_pts:
        print(f"[警告] {file_path}: {missing_pts} 帧没有有效PTS，已跳过")
    return rows


def write_csv(file_path, rows):
    """写CSV: pts_time,index,dhash,luma"""
    out_file = file_path + ".fingerprint.csv"
    with open(out_file, "w", encoding="utf-8", newline="") as f:
        f.write("pts_time,index,dhash,luma\n")
        for pts, idx, dh, luma in rows:
            f.write(f"{pts:.6f},{idx},{dh},{luma:.3f}\n")
    print(f"[输出] CSV: {out_file}")


def _hash_ratio(value):
    """把 dHash 映射到 [0, 1]，使全 1 哈希也能落在坐标轴上。"""
    bits = config["height"] * (config["width"] - 1)
    max_value = (1 << bits) - 1
    return value / max_value if max_value else 0.0


def svg_compare(a, b, out_file, shift_a_ms=0.0, shift_b_ms=0.0):
    """画指纹对比SVG(一个或两个文件; b为空则只画文件A)"""
    if not a:
        print("[错误] File A 没有有效视频帧")
        return False
    p0 = min(row[0] for row in a + (b or []))
    shift_a = shift_a_ms / 1000.0
    shift_b = shift_b_ms / 1000.0

    def to_series(rows, shift=0.0):
        return [(p - p0 + shift, _hash_ratio(h), luma / 255.0) for (p, i, h, luma) in rows]

    sa = to_series(a, shift_a)
    sb = to_series(b, shift_b) if b else []
    xs = [x for (x, _, _) in sa] + [x for (x, _, _) in sb]
    if not xs:
        print("[错误] 无有效数据")
        return False

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
    parts.append(f'<text x="{L+16}" y="{ly+10}" font-size="12" font-family="Arial">File A dHash (偏移 {shift_a_ms:+g} ms)</text>')
    if sb:
        parts.append(f'<rect x="{L+150}" y="{ly}" width="10" height="10" fill="#2980b9"/>')
        parts.append(f'<text x="{L+166}" y="{ly+10}" font-size="12" font-family="Arial">File B dHash (虚线, 偏移 {shift_b_ms:+g} ms)</text>')
    parts.append(f'<text x="{L+360}" y="{ly+10}" font-size="12" fill="#888" font-family="Arial">细线=亮度: A #e8a49b' + (' B #9bc7e8' if sb else '') + '</text>')
    parts.append("</svg>")
    with open(out_file, "w", encoding="utf-8") as f:
        f.write("\n".join(parts))
    print(f"[输出] SVG: {out_file}")
    return True


def html_viewer(a, b, out_file, shift_a_ms=0.0, shift_b_ms=0.0):
    """生成可缩放/平移/带比例尺的交互式 HTML 指纹图"""
    if not a:
        print("[错误] File A 没有有效视频帧")
        return False
    p0 = min(row[0] for row in a + (b or []))

    def to_series(rows):
        return [[p - p0, _hash_ratio(h), luma / 255.0] for (p, i, h, luma) in rows]

    sa = to_series(a)
    sb = to_series(b) if b else []
    if not sa:
        print("[错误] 无有效数据")
        return False

    js = (
        "const DATA_A = " + json.dumps(sa) + ";\n"
        "const DATA_B = " + json.dumps(sb) + ";\n"
        "const INITIAL_SHIFT_A_MS = " + json.dumps(float(shift_a_ms)) + ";\n"
        "const INITIAL_SHIFT_B_MS = " + json.dumps(float(shift_b_ms)) + ";\n"
    )

    html = """<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<title>Frame Fingerprint Viewer</title>
<style>
  body { font-family: "Microsoft YaHei", Arial, sans-serif; margin: 20px; background: #faf9f7; }
  h1 { font-size: 20px; color: #333; }
  .hint { font-size: 13px; color: #777; margin-bottom: 6px; }
  #chart { position: relative; width: 100%; max-width: 1500px; background: #fff;
           border: 1px solid #e0dbd3; border-radius: 8px; overflow: hidden; }
  svg { display: block; width: 100%; height: 560px; touch-action: none; background: #fff; }
  #tooltip { position: absolute; pointer-events: none; background: rgba(0,0,0,.78);
             color: #fff; padding: 6px 9px; border-radius: 6px; font-size: 12px; display: none;
             white-space: pre; }
  #scalebar { position: absolute; left: 90px; bottom: 16px; background: #fff;
              border: 1px solid #999; border-left: none; height: 12px; display: flex; }
  #scalebar span { position: absolute; left: 100%; padding-left: 4px; font-size: 11px;
                   color: #555; white-space: nowrap; }
  #controls { margin: 6px 0; font-size: 12px; color: #555; }
  button { margin-right: 8px; }
  .lg { font-size: 12px; margin-top: 4px; }
  .shift-controls { font-size: 12px; color: #555; margin: 6px 0; }
  .shift-controls label { margin-right: 4px; }
  .shift-controls input { width: 76px; margin-left: 2px; }
  .shift-controls button { margin-right: 4px; }
</style>
</head>
<body>
<h1>Frame Fingerprint Viewer</h1>
<div class="hint">滚轮=缩放(x轴), 拖拽=平移, 悬停=查看数值; 底部比例尺随缩放更新</div>
<div id="controls"><button onclick="resetView()">重置视图</button><span id="viewinfo"></span></div>
<div class="shift-controls">
  横向偏移（正值向右/时间变晚，负值向左/时间变早）：
  <label>A <input id="shiftA" type="number" step="0.1" value="0" oninput="setShift('a', this.value)"> ms</label>
  <button onclick="nudge('a', -1)">A −1 ms</button><button onclick="nudge('a', 1)">A +1 ms</button>
  <label>B <input id="shiftB" type="number" step="0.1" value="0" oninput="setShift('b', this.value)"> ms</label>
  <button onclick="nudge('b', -1)">B −1 ms</button><button onclick="nudge('b', 1)">B +1 ms</button>
  <button onclick="resetShifts()">偏移归零</button>
</div>
<div id="chart">
  <svg id="svg" viewBox="0 0 1500 560" width="100%" height="560"></svg>
  <div id="scalebar"><span id="scalebarLabel"></span></div>
  <div id="tooltip"></div>
  <div class="lg">红=FileA(dHash) 蓝=FileB(dHash,虚线); 细线=亮度</div>
</div>
<script>
""" + js + """
const W=1500, H=560, L=90, R=1480, T=48, B=500, sp=0.55;
let view = {x0:null, x1:null};
let shiftMs = {a:INITIAL_SHIFT_A_MS, b:INITIAL_SHIFT_B_MS};
function shiftSec(which){ return shiftMs[which] / 1000.0; }
function shiftedX(p, which){ return p[0] + shiftSec(which); }
function dataExtent(){
  let x0=Infinity, x1=-Infinity;
  const visit=(series,which)=>{
    for (const p of series){
      const x=shiftedX(p,which);
      if (x < x0) x0=x;
      if (x > x1) x1=x;
    }
  };
  visit(DATA_A,"a"); visit(DATA_B,"b");
  return {x0,x1};
}
(function init(){
  document.getElementById("shiftA").value = shiftMs.a;
  document.getElementById("shiftB").value = shiftMs.b;
  const extent = dataExtent();
  if (!Number.isFinite(extent.x0) || !Number.isFinite(extent.x1)) { view.x0 = 0; view.x1 = 1; }
  else { view.x0 = extent.x0; view.x1 = extent.x1; }
  if (!(view.x1 > view.x0)) view.x1 = view.x0 + 1;
  render();
})();
function x2px(x){ return L + (x-view.x0)/(view.x1-view.x0 || 1)*(R-L); }
function y2dh(y){ return T + (1-y)*(B-T)*sp; }
function y2lu(y){ return T + (B-T)*sp + (1-y)*(B-T)*(1-sp); }
function polyFrom(series, yfn, which){
  const pts=[];
  for (const p of series){
    const x=shiftedX(p,which);
    if (x < view.x0 || x > view.x1) continue;
    pts.push([x2px(x).toFixed(1), yfn(p).toFixed(1)]);
  }
  return pts.map(q=>q.join(",")).join(" ");
}
function render(){
  const svg=document.getElementById("svg"); svg.innerHTML="";
  const NS="http://www.w3.org/2000/svg";
  const el=(tag,attrs)=>{const e=document.createElementNS(NS,tag); for(const k in attrs)e.setAttribute(k,attrs[k]); return e;};
  svg.appendChild(el("rect",{x:0,y:0,width:W,height:H,fill:"#fff"}));
  // grid + x labels
  const nseg=8;
  for(let i=0;i<=nseg;i++){
    const xv=view.x0+(view.x1-view.x0)*i/nseg, px=x2px(xv);
    svg.appendChild(el("line",{x1:px,y1:T,x2:px,y2:B,stroke:"#ece8e2"}));
    const t=el("text",{x:px+3,y:B+14,"font-size":"10",fill:"#888"}); t.textContent=xv.toFixed(2); svg.appendChild(t);
  }
  for(const yv of [0,0.5,1]){
    const py=y2dh(yv);
    svg.appendChild(el("line",{x1:L,y1:py,x2:R,y2:py,stroke:"#ece8e2"}));
  }
  // labels
  for(const [txt,fn,color] of [["dHash",y2dh,"#c0392b"],["Luma",y2lu,"#2f6f63"]]){
    const t=el("text",{x:6,y:fn(0.25)+4,"font-size":"12",fill:color}); t.textContent=txt; svg.appendChild(t);
  }
  // curves
  if(DATA_A.length){
    svg.appendChild(el("polyline",{fill:"none",stroke:"#c0392b","stroke-width":1.3,
      points:polyFrom(DATA_A,p=>y2dh(p[1]),"a")}));
    svg.appendChild(el("polyline",{fill:"none",stroke:"#e8a49b","stroke-width":1,
      points:polyFrom(DATA_A,p=>y2lu(p[2]),"a")}));
  }
  if(DATA_B.length){
    svg.appendChild(el("polyline",{fill:"none",stroke:"#2980b9","stroke-width":1.3, "stroke-dasharray":"5,3",
      points:polyFrom(DATA_B,p=>y2dh(p[1]),"b")}));
    svg.appendChild(el("polyline",{fill:"none",stroke:"#9bc7e8","stroke-width":1,
      points:polyFrom(DATA_B,p=>y2lu(p[2]),"b")}));
  }
  // scale bar (约 10 等分，支持缩放到毫秒/微秒范围)
  const range=view.x1-view.x0;
  function niceStep(value){
    if (!(value>0) || !Number.isFinite(value)) return 1;
    const raw=value/10, exponent=Math.pow(10,Math.floor(Math.log10(raw)));
    const normalized=raw/exponent;
    const base=normalized<=1 ? 1 : normalized<=2 ? 2 : normalized<=5 ? 5 : 10;
    return base*exponent;
  }
  function formatNumber(value){ return Number(value.toPrecision(3)).toString(); }
  function formatStep(value){
    if (value>=1) return formatNumber(value)+" s";
    if (value>=0.001) return formatNumber(value*1000)+" ms";
    return formatNumber(value*1000000)+" μs";
  }
  const stepNice=niceStep(range);
  const ticks=Math.max(1,Math.round(range/stepNice));
  const bar=document.getElementById("scalebar");
  const pxW=Math.round((R-L)/ticks);
  bar.innerHTML="";
  bar.style.width=pxW+"px";
  bar.style.height="12px";
  bar.style.border="1px solid #666"; bar.style.borderLeft="1px solid #666";
  const lab=document.createElement("span"); lab.textContent=formatStep(stepNice);
  bar.appendChild(lab);
  document.getElementById("viewinfo").textContent=
    "  [视图] "+view.x0.toFixed(2)+" ~ "+view.x1.toFixed(2)+" s (共 "+(view.x1-view.x0).toFixed(2)+" s), 每格 "+formatStep(stepNice)+
    "；偏移 A="+shiftMs.a.toFixed(1)+" ms, B="+shiftMs.b.toFixed(1)+" ms";
  // tooltip mouse move
  svg.onmousemove=e=>{ const rect=svg.getBoundingClientRect();
    const px=(e.clientX-rect.left)/rect.width*W;
    const xv=view.x0+(px-L)/(R-L)*(view.x1-view.x0);
    let txt="x="+xv.toFixed(3)+" s\\n";
    const find=(data,which)=>{let best=null; for(const p of data){ if(best===null||Math.abs(shiftedX(p,which)-xv)<Math.abs(shiftedX(best,which)-xv)) best=p;} return best;};
    const a=find(DATA_A,"a"), b=find(DATA_B,"b");
    if(a) txt+="A t="+shiftedX(a,"a").toFixed(3)+" s dhash="+a[1].toFixed(3)+" luma="+a[2].toFixed(3)+"\\n";
    if(b) txt+="B t="+shiftedX(b,"b").toFixed(3)+" s dhash="+b[1].toFixed(3)+" luma="+b[2].toFixed(3);
    const tip=document.getElementById("tooltip");
    tip.style.display="block";
    tip.style.left=(e.clientX-rect.left+14)+"px"; tip.style.top=(e.clientY-rect.top-10)+"px";
    tip.textContent=txt;
  };
  svg.onmouseleave=()=>{document.getElementById("tooltip").style.display="none";};
}
function setShift(which, value){
  const v=Number(value);
  if(!Number.isFinite(v)) return;
  shiftMs[which]=v;
  document.getElementById("shift"+which.toUpperCase()).value=v;
  render();
}
function nudge(which, delta){ setShift(which, shiftMs[which]+delta); }
function resetShifts(){
  setShift("a",0);
  setShift("b",0);
  resetView();
}
// zoom on wheel (以鼠标为中心缩放 x)
document.getElementById("svg").addEventListener("wheel",e=>{
  e.preventDefault();
  const rect=document.getElementById("svg").getBoundingClientRect();
  const px=(e.clientX-rect.left)/rect.width*W;
  const t=view.x0+(px-L)/(R-L)*(view.x1-view.x0);
  const factor=e.deltaY>0?0.85:1.175;
  const r=view.x1-view.x0;
  let x0=t-(t-view.x0)*factor, x1=t+(view.x1-t)*factor;
  if(x1-x0 < 0.001){ x1=x0+0.001; }
  view={x0,x1}; render();
},{passive:false});
// drag to pan
let dragging=false, dragStartX=0, dragStartView=null;
document.getElementById("svg").addEventListener("mousedown",e=>{dragging=true;
  const rect=document.getElementById("svg").getBoundingClientRect();
  dragStartX=(e.clientX-rect.left)/rect.width*W; dragStartView={...view};});
document.addEventListener("mousemove",e=>{
  if(!dragging) return;
  const rect=document.getElementById("svg").getBoundingClientRect();
  const px=(e.clientX-rect.left)/rect.width*W;
  const range=dragStartView.x1-dragStartView.x0;
  const dx=-(px-dragStartX)/ (R-L) * range;
  view={x0:dragStartView.x0+dx, x1:dragStartView.x1+dx}; render();
});
document.addEventListener("mouseup",()=>{dragging=false;});
function resetView(){
  const extent=dataExtent();
  if(!Number.isFinite(extent.x0) || !Number.isFinite(extent.x1)){ view.x0=0; view.x1=1; }
  else { view.x0=extent.x0; view.x1=extent.x1; }
  if (!(view.x1 > view.x0)) view.x1=view.x0+1;
  render();
}
</script>
</body>
</html>"""

    with open(out_file, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"[输出] HTML: {out_file}")
    return True


def _positive_int(value):
    """argparse 类型：只接受正整数。"""
    try:
        number = int(value)
    except ValueError as exc:
        raise ValueError("必须是正整数") from exc
    if number <= 0:
        raise ValueError("必须是正整数")
    return number


def _finite_float(value):
    """argparse 类型：只接受有限浮点数。"""
    try:
        number = float(value)
    except ValueError as exc:
        raise ValueError("必须是有限浮点数") from exc
    if not math.isfinite(number):
        raise ValueError("必须是有限浮点数")
    return number


def main(argv=None):
    """命令行入口，返回进程退出码。"""
    argv = sys.argv[1:] if argv is None else argv

    # 无参数或帮助模式
    if not argv or "-h" in argv:
        show_help()
        return 0

    import argparse
    import os

    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument('-f', dest='input', action='append', help='输入: TS文件(可指定两个)')
    parser.add_argument('-o', dest='output', default='fingerprint_compare.svg', help='输出: 指纹图文件(.html交互/.svg静态)')
    parser.add_argument('-n', dest='max_frames', type=_positive_int, default=None, help='配置: 最大帧数(正整数)')
    parser.add_argument('--shift-a-ms', type=_finite_float, default=0.0, help='配置: File A横向偏移，单位毫秒')
    parser.add_argument('--shift-b-ms', type=_finite_float, default=0.0, help='配置: File B横向偏移，单位毫秒')
    try:
        args = parser.parse_args(argv)
    except (SystemExit, ValueError):
        show_help()
        return 1

    if not args.input:
        print("[错误] 缺少输入文件 (-f)")
        show_help()
        return 1
    if len(args.input) > 2:
        print("[错误] 最多两个输入文件")
        return 1

    output_lower = args.output.lower()
    if not output_lower.endswith((".svg", ".html")):
        print("[错误] 输出文件必须使用 .svg 或 .html 扩展名")
        return 1
    output_dir = os.path.dirname(os.path.abspath(args.output))
    if not os.path.isdir(output_dir):
        print(f"[错误] 输出目录不存在: {output_dir}")
        return 1

    input_paths = []
    for file_path in args.input:
        if not os.path.isfile(file_path):
            print(f"[错误] 输入文件不存在或不是普通文件: {file_path}")
            return 1
        input_paths.append(os.path.realpath(file_path))
    if os.path.realpath(os.path.abspath(args.output)) in input_paths:
        print("[错误] 输出文件不能覆盖输入文件")
        return 1

    rows_all = {}
    try:
        for file_path in args.input:
            print(f"[处理] {file_path}")
            rows = fingerprints(file_path, args.max_frames)
            print(f"  帧数={len(rows)}")
            for i in range(1, len(rows)):
                delta = rows[i][0] - rows[i - 1][0]
                if abs(delta) > config["pts_jump_threshold"]:
                    print(
                        f"  PTS跳变 idx {rows[i-1][1]}->{rows[i][1]}: "
                        f"Δ{delta:.6f} s (={delta * 1000:.0f} ms)"
                    )
            rows_all[file_path] = rows
            write_csv(file_path, rows)

        a = rows_all[args.input[0]]
        b = rows_all[args.input[1]] if len(args.input) == 2 else []
        if not a or (len(args.input) == 2 and not b):
            print("[错误] 未提取到有效视频帧，未生成图表")
            return 1
        if output_lower.endswith(".html"):
            generated = html_viewer(a, b, args.output, args.shift_a_ms, args.shift_b_ms)
        else:
            generated = svg_compare(a, b, args.output, args.shift_a_ms, args.shift_b_ms)
        return 0 if generated else 1
    except (ToolError, OSError, ValueError) as exc:
        print(f"[错误] {exc}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
