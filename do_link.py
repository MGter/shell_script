#!/usr/bin/env python3
import os
import re

def main():
    # 匹配 .so.x.y.z 格式的真实文件（x/y/z 都是数字）
    pattern = re.compile(r'.*\.so\.[0-9.]+$')

    for filename in os.listdir('.'):
        # 跳过不是 .so.数字 格式的文件
        if not pattern.match(filename):
            continue

        # 跳过软链接，只处理真实文件
        if os.path.islink(filename):
            continue

        print(f"处理真实库文件: {filename}")

        # 拆分基础名 + 版本号
        # 例如 libtest.so.1.2.3 → base=libtest, version=1.2.3
        base_part, _, version_part = filename.partition('.so.')
        base = base_part
        version = version_part

        # 按 . 分割版本号
        ver_parts = version.split('.')
        prev_link = None

        # 逐级创建版本链
        for i in range(len(ver_parts)):
            current_ver = '.'.join(ver_parts[:i+1])
            link_name = f"{base}.so.{current_ver}"

            if prev_link is None:
                # 第一层指向真实文件
                target = filename
            else:
                # 后续指向上一级链接
                target = prev_link

            # 创建软链接（强制覆盖）
            if os.path.exists(link_name) or os.path.islink(link_name):
                os.unlink(link_name)
            os.symlink(target, link_name)
            print(f"  创建: {link_name} -> {target}")

            prev_link = link_name

        # 最后创建顶层 .so
        final_so = f"{base}.so"
        if os.path.exists(final_so) or os.path.islink(final_so):
            os.unlink(final_so)
        os.symlink(prev_link, final_so)
        print(f"  创建: {final_so} -> {prev_link}")

    print("\n✅ 完整版本链软链接创建完成！")

if __name__ == '__main__':
    main()