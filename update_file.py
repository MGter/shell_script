import os
import shutil
from pathlib import Path

DST_PATH="~"

def process_conf_files():
    """处理配置文件：如果目标文件存在且没有备份，则创建备份"""
    
    # 定义路径
    conf_dir = Path("./conf")
    dst_path = Path(DST_PATH)
    
    print("开始处理配置文件...")
    print(f"源目录: {conf_dir}")
    print(f"目标目录: {dst_path}")
    print("-" * 50)
    
    # 检查目录是否存在
    if not conf_dir.exists():
        print(f"错误: 源目录 {conf_dir} 不存在")
        return
    
    if not dst_path.exists():
        print(f"错误: 目标目录 {dst_path} 不存在")
        return
    
    # 遍历conf目录下的所有文件
    for conf_file in conf_dir.glob("*"):
        if not conf_file.is_file():
            continue
            
        purename = conf_file.stem  # 不带扩展名的文件名
        extension = conf_file.suffix  # 扩展名
        
        print(f"\n处理文件: {conf_file.name}")
        print(f"纯文件名: {purename}")
        
        # 在目标目录中查找对应文件
        target_file = dst_path / conf_file.name
        
        if target_file.exists():
            # 检查备份文件是否已经存在
            backup_file = dst_path / f"{purename}_back{extension}"
            
            if backup_file.exists():
                print(f"✓ 备份文件已存在: {backup_file.name}，跳过备份")
            else:
                # 创建备份
                shutil.copy2(target_file, backup_file)
                print(f"✓ 已创建备份: {backup_file.name}")
            
            # 复制conf文件覆盖目标文件
            shutil.copy2(conf_file, target_file)
            print(f"✓ 已复制覆盖: {conf_file.name} → {target_file.name}")
        else:
            print(f"⚠ 目标目录中没有找到 {conf_file.name}，直接复制")
            shutil.copy2(conf_file, target_file)
            print(f"✓ 已复制: {conf_file.name} → {target_file.name}")
    
    print("\n" + "=" * 50)
    print("所有文件处理完成!")

if __name__ == "__main__":
    process_conf_files()