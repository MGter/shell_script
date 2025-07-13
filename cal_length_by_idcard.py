# pip install opencv-python numpy

import cv2
import numpy as np
import math

class ImageDistanceMeasurer:
    def __init__(self, image_path):
        self.image = cv2.imread(image_path)
        if self.image is None:
            raise FileNotFoundError(f"无法加载图像: {image_path}")
        
        self.display_image = self.image.copy()
        self.ref_points = []  # 存储参考点（身份证宽度端点）
        self.measure_points = []  # 存储测量点
        self.mm_per_pixel = None  # 每像素对应的毫米数
        self.status = "SELECT_REF"  # 当前状态: SELECT_REF, SELECT_MEASURE
        self.distance_results = []  # 存储测量结果
        
        cv2.namedWindow("Image Distance Measurer")
        cv2.setMouseCallback("Image Distance Measurer", self.mouse_callback)
        
    def mouse_callback(self, event, x, y, flags, param):
        if event == cv2.EVENT_LBUTTONDOWN:
            if self.status == "SELECT_REF":
                # 选择身份证宽度端点
                self.ref_points.append((x, y))
                cv2.circle(self.display_image, (x, y), 8, (0, 0, 255), -1)
                
                # 如果已经选择了两个参考点
                if len(self.ref_points) == 2:
                    # 计算参考长度（像素）
                    ref_length_px = math.sqrt(
                        (self.ref_points[1][0] - self.ref_points[0][0])**2 +
                        (self.ref_points[1][1] - self.ref_points[0][1])**2
                    )
                    
                    # 计算每像素对应的毫米数（身份证标准长度85.6）
                    self.mm_per_pixel = 85.6 / ref_length_px
                    
                    # 绘制参考线
                    cv2.line(self.display_image, 
                             self.ref_points[0], self.ref_points[1], 
                             (0, 0, 255), 2)
                    
                    # 显示比例尺信息
                    cv2.putText(self.display_image, 
                                f"Scale: 1 px = {self.mm_per_pixel:.4f} mm", 
                                (10, 30), cv2.FONT_HERSHEY_SIMPLEX, 
                                0.7, (0, 255, 0), 2)
                    
                    # 切换到测量模式
                    self.status = "SELECT_MEASURE"
                    print("参考比例尺已设置。现在可以测量其他距离。")
            
            elif self.status == "SELECT_MEASURE" and self.mm_per_pixel is not None:
                # 选择测量点
                self.measure_points.append((x, y))
                cv2.circle(self.display_image, (x, y), 8, (0, 255, 0), -1)
                
                # 如果已经选择了两个测量点
                if len(self.measure_points) == 2:
                    # 计算像素距离
                    dx = self.measure_points[1][0] - self.measure_points[0][0]
                    dy = self.measure_points[1][1] - self.measure_points[0][1]
                    distance_px = math.sqrt(dx**2 + dy**2)
                    
                    # 计算实际距离（毫米）
                    distance_mm = distance_px * self.mm_per_pixel
                    
                    # 绘制测量线
                    cv2.line(self.display_image, 
                             self.measure_points[0], self.measure_points[1], 
                             (0, 255, 0), 2)
                    
                    # 显示测量结果
                    mid_x = (self.measure_points[0][0] + self.measure_points[1][0]) // 2
                    mid_y = (self.measure_points[0][1] + self.measure_points[1][1]) // 2
                    
                    cv2.putText(self.display_image, 
                                f"{distance_mm:.2f} mm", 
                                (mid_x, mid_y), cv2.FONT_HERSHEY_SIMPLEX, 
                                0.7, (0, 255, 255), 2)
                    
                    # 存储结果
                    self.distance_results.append({
                        "points": self.measure_points.copy(),
                        "distance_mm": distance_mm
                    })
                    
                    # 重置测量点
                    self.measure_points = []
                    print(f"测量结果: {distance_mm:.2f} mm")
    
    def run(self):
        print("使用说明:")
        print("1. 首先在身份证的宽度方向上点击两个端点（例如左边缘和右边缘）")
        print("2. 然后点击需要测量的两个点")
        print("3. 按 'r' 重置参考点")
        print("4. 按 'c' 清除所有测量")
        print("5. 按 's' 保存结果图像")
        print("6. 按 ESC 或 'q' 退出")
        
        while True:
            cv2.imshow("Image Distance Measurer", self.display_image)
            key = cv2.waitKey(1) & 0xFF
            
            # 退出程序
            if key == 27 or key == ord('q'):
                break
            
            # 重置参考点
            elif key == ord('r'):
                self.ref_points = []
                self.measure_points = []
                self.mm_per_pixel = None
                self.status = "SELECT_REF"
                self.display_image = self.image.copy()
                print("参考点已重置。请重新设置比例尺。")
            
            # 清除测量结果
            elif key == ord('c'):
                self.measure_points = []
                self.distance_results = []
                self.display_image = self.image.copy()
                
                # 重新绘制参考线（如果已设置）
                if self.mm_per_pixel is not None:
                    cv2.line(self.display_image, 
                             self.ref_points[0], self.ref_points[1], 
                             (0, 0, 255), 2)
                    cv2.putText(self.display_image, 
                                f"Scale: 1 px = {self.mm_per_pixel:.4f} mm", 
                                (10, 30), cv2.FONT_HERSHEY_SIMPLEX, 
                                0.7, (0, 255, 0), 2)
                print("所有测量结果已清除。")
            
            # 保存结果图像
            elif key == ord('s'):
                output_path = "measurement_result.jpg"
                cv2.imwrite(output_path, self.display_image)
                print(f"结果已保存为: {output_path}")
        
        cv2.destroyAllWindows()
        
        # 打印所有测量结果
        if self.distance_results:
            print("\n最终测量结果:")
            for i, result in enumerate(self.distance_results, 1):
                print(f"测量 {i}: {result['distance_mm']:.2f} mm")

# 使用示例
if __name__ == "__main__":
    # 替换为你的图像路径
    image_path = "input.jpg"
    
    try:
        measurer = ImageDistanceMeasurer(image_path)
        measurer.run()
    except FileNotFoundError as e:
        print(e)
    except Exception as e:
        print(f"发生错误: {e}")
