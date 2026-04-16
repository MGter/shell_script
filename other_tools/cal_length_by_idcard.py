#!/usr/bin/env python3
"""
图像测量工具 - 以身份证宽度(85.6mm)为参考测量图片中物体长度
依赖: pip install opencv-python numpy
"""

import sys
import os

def show_help():
    print("""
用法: python3 cal_length_by_idcard.py [-i <图像>] [-o <输出>] [-h]

选项:
  -i <文件>   输入图像文件
  -o <文件>   输出结果图像 (默认: measurement_result.jpg)
  -h          显示帮助

操作说明:
  1. 先点击身份证两端(宽度85.6mm作为参考)
  2. 再点击要测量的物体两端
  3. 按 'r' 重置参考点
  4. 按 'c' 清除测量
  5. 按 's' 保存结果
  6. 按 ESC/q 退出

示例:
  python3 cal_length_by_idcard.py -i photo.jpg
""")

# 无参数或帮助模式
if len(sys.argv) == 1 or '-h' in sys.argv:
    show_help()
    sys.exit(0)

import argparse
parser = argparse.ArgumentParser(add_help=False)
parser.add_argument('-i', dest='input', required=True)
parser.add_argument('-o', dest='output', default='measurement_result.jpg')
args = parser.parse_args()

if not os.path.exists(args.input):
    print(f"[错误] 文件不存在: {args.input}")
    sys.exit(1)

try:
    import cv2
    import math
except ImportError:
    print("[错误] 缺少opencv，请执行: pip install opencv-python")
    sys.exit(1)

image = cv2.imread(args.input)
if image is None:
    print(f"[错误] 无法加载图像: {args.input}")
    sys.exit(1)

display = image.copy()
ref_points = []
measure_points = []
mm_per_pixel = None
results = []
status = "REF"

def mouse_cb(event, x, y, flags, param):
    global status, mm_per_pixel
    if event != cv2.EVENT_LBUTTONDOWN:
        return
    cv2.circle(display, (x, y), 8, (0, 0, 255) if status == "REF" else (0, 255, 0), -1)
    if status == "REF":
        ref_points.append((x, y))
        if len(ref_points) == 2:
            px_len = math.sqrt((ref_points[1][0]-ref_points[0][0])**2 + (ref_points[1][1]-ref_points[0][1])**2)
            mm_per_pixel = 85.6 / px_len
            cv2.line(display, ref_points[0], ref_points[1], (0, 0, 255), 2)
            cv2.putText(display, f"Scale: {mm_per_pixel:.4f} mm/px", (10, 30), cv2.FONT_HERSHEY_SIMPLEX, 0.6, (0, 255, 0), 2)
            status = "MEASURE"
            print("[提示] 参考已设置，现在测量物体")
    elif status == "MEASURE" and mm_per_pixel:
        measure_points.append((x, y))
        if len(measure_points) == 2:
            px_len = math.sqrt((measure_points[1][0]-measure_points[0][0])**2 + (measure_points[1][1]-measure_points[0][1])**2)
            mm_len = px_len * mm_per_pixel
            cv2.line(display, measure_points[0], measure_points[1], (0, 255, 0), 2)
            mid = ((measure_points[0][0]+measure_points[1][0])//2, (measure_points[0][1]+measure_points[1][1])//2)
            cv2.putText(display, f"{mm_len:.2f} mm", mid, cv2.FONT_HERSHEY_SIMPLEX, 0.6, (0, 255, 255), 2)
            results.append(mm_len)
            print(f"[测量] {mm_len:.2f} mm")
            measure_points = []

cv2.namedWindow("Measure")
cv2.setMouseCallback("Measure", mouse_cb)

print("[提示] 按 r重置, c清除, s保存, q退出")
while True:
    cv2.imshow("Measure", display)
    key = cv2.waitKey(1) & 0xFF
    if key == 27 or key == ord('q'):
        break
    elif key == ord('r'):
        ref_points = []
        measure_points = []
        mm_per_pixel = None
        status = "REF"
        display = image.copy()
        print("[重置] 请重新设置参考")
    elif key == ord('c'):
        measure_points = []
        results = []
        display = image.copy()
        if mm_per_pixel:
            cv2.line(display, ref_points[0], ref_points[1], (0, 0, 255), 2)
            cv2.putText(display, f"Scale: {mm_per_pixel:.4f} mm/px", (10, 30), cv2.FONT_HERSHEY_SIMPLEX, 0.6, (0, 255, 0), 2)
        print("[清除] 测量已清除")
    elif key == ord('s'):
        cv2.imwrite(args.output, display)
        print(f"[保存] {args.output}")

cv2.destroyAllWindows()
if results:
    print("\n[结果]")
    for i, r in enumerate(results, 1):
        print(f"  测量{i}: {r:.2f} mm")