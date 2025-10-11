import subprocess
import json
import re
import os
import sys
import datetime
import shutil

__DEBUG__ = True

# ------------ 版本信息 ------------ 
# 版本：        v1.3
# 修订时间：    2025年10月11日11:10:22
# 修订人：      MGter
# 邮箱：        zxwangbuaa@gmail.com
# 功能：        检查当前系统情况，统计表格输出到 sysinfo_checker.json 中
# 使用方法：    python3 执行本脚本
# 上次更新：    新增DNS解析函数
# ------------------------------ 


# ------------ 检查表 ------------ 
# 脚本按照此表顺序执行系统信息检查
# 可以注释或删除掉不需要的检查
# 可以手动修改调换检查顺序
check_list = [
    # 重点信息
    "check_os_ver_info",
    "check_mainboard_info",
    "check_cpu_info",
    "check_mem_basic_info",
    "check_diskinfo_free",
    "check_suma_software_versions",
    "check_processes_status",
    "check_all_hw_cnt",
    "check_sys_log",
    "check_time_info",
    "check_resolve_info",
    # 系统信息
    "check_login_info",
    "check_grub_info",
    "check_sysctl_info",
    "check_netcard_info",
    "check_cron_task_info",
    "check_listen_port",
    "check_firewall_rules",
    # 硬件信息
    "check_RAM_info",
    "check_intel_gpu_info",
    "check_nvidia_gpu_info",
    "check_emerge_gpu_info",
    "check_blackmagic_card_info",
    "check_mem_detail_info",
    "check_block_info",
    # 软件信息
    "check_versions",
    "check_top10_cpu_usage_process",
    "check_top10_mem_usage_process",
    "check_2050_info",
]


temp_list = [
    
]
# ------------------------------ 


# ------------ 参数表 ------------ 
# check_processes_status 参数
suma_process_list=[                     # check_processes_status 将检查本列表列出的进程状态，并打印出当前存在的进程数量
    "xStreamDeviceTool",
    "xStreamDog",
    "DogForTool",
    "xStreamNginx",
    "MediaTransform",
    "miramserver",
    "java"
]
# check_sys_log 参数
syslog_check_record_cnt = -1            # syslog_check_record_cnt 表示打印日志行数，-1 表示全部打印        
syslog_check_pattern = {                # 示例：oom 过滤的 pattern 为: "Out of memory"
    "oom": "Out of memory",
    "segfault": "segfault"
}
# ------------------------------


# ------------ check类 ------------ 
class SystemInfoChecker:
    def __init__(self, output_file="sysinfo_checker.json"):
        self.base_output_file = output_file
        self.output_file = output_file
        self.info = {}

    def generate_filename(self):
        """
        生成带有当前时间戳的文件名。
        例如: sysinfo_20250919_131313.json
        """
        now = datetime.datetime.now()
        timestamp = now.strftime("%Y%m%d_%H%M%S")
        filename_parts = self.base_output_file.split('.')
        new_filename = f"{filename_parts[0]}_{timestamp}.{filename_parts[1]}"
        self.output_file = new_filename
        print(f"Output file will be: {self.output_file}")

    def run_command(self, cmd, shell=False):
        '''
        执行命令，返回string，如果有错误，返回None
        '''

        try:
            result = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True,
                check=True,
                shell=shell
            )
            # 获取 stdout 和 stderr 的内容，并去除首尾空白
            stdout_content = result.stdout.strip()
            stderr_content = result.stderr.strip()

            # 将两者合并，用换行符分隔
            combined_output = f"{stdout_content}\n{stderr_content}"
            return combined_output.strip()
        except (subprocess.CalledProcessError, FileNotFoundError) as e:
            # print(f"Error running command '{' '.join(cmd)}': {e}")
            return None

    def get_service_status(self, service_name: str) -> dict:
        """
        获取服务状态信息
        
        Args:
            service_name: 服务名称
            
        Returns:
            dict: 包含服务状态信息的字典
        """
        dict_status = {
            "Name": service_name,
            "Exist": False,
            "Status": "N/A",
            "ActiveState": "N/A",
            "LoadedState": "N/A",
            "MainPid": "N/A",
            "IsEnabled": "N/A",
            "Error": None
        }

        try:
            # 检查服务是否存在
            result = self.run_command(['systemctl', 'status', service_name])
            if not result or "could not be found" in result or "Loaded: error" in result:
                dict_status["Exist"] = False
                dict_status["Error"] = "Service not found"
                return dict_status
            
            dict_status["Exist"] = True
            
            # 解析服务状态信息
            for line in result.split('\n'):
                line = line.strip()
                if not line:
                    continue
                    
                if "Active:" in line:
                    active_state = line.split("Active:")[1].strip()
                    dict_status["ActiveState"] = active_state
                    
                    # 根据Active状态设置综合状态
                    if "active (running)" in active_state:
                        dict_status["Status"] = "running"
                    elif "active (exited)" in active_state:
                        dict_status["Status"] = "exited"
                    elif "active (waiting)" in active_state:
                        dict_status["Status"] = "waiting"
                    elif "inactive (dead)" in active_state:
                        dict_status["Status"] = "stopped"
                    elif "failed" in active_state:
                        dict_status["Status"] = "failed"
                    else:
                        dict_status["Status"] = "unknown"
                        
                elif "Loaded:" in line:
                    loaded_state = line.split("Loaded:")[1].strip()
                    dict_status["LoadedState"] = loaded_state
                    
                    # 从Loaded状态提取启用状态
                    if "enabled" in loaded_state:
                        dict_status["IsEnabled"] = "enabled"
                    elif "disabled" in loaded_state:
                        dict_status["IsEnabled"] = "disabled"
                    elif "static" in loaded_state:
                        dict_status["IsEnabled"] = "static"
                        
                elif "Main PID:" in line:
                    main_pid = line.split("Main PID:")[1].strip().split()[0]
                    dict_status["MainPid"] = main_pid
                    
                elif "Process:" in line and dict_status["MainPid"] == "N/A":
                    # 备选方案获取PID
                    import re
                    pid_match = re.search(r'PID:(\d+)', line)
                    if pid_match:
                        dict_status["MainPid"] = pid_match.group(1)
            
            # 使用 systemctl is-enabled 确认启用状态
            enabled_result = self.run_command(['systemctl', 'is-enabled', service_name])
            if enabled_result and enabled_result.strip() in ['enabled', 'disabled', 'static', 'masked', 'indirect']:
                dict_status["IsEnabled"] = enabled_result.strip()
            
            # 如果还没有确定状态，使用 systemctl is-active 检查
            if dict_status["Status"] == "N/A":
                active_result = self.run_command(['systemctl', 'is-active', service_name])
                if active_result:
                    dict_status["Status"] = active_result.strip()
            
            return dict_status
            
        except Exception as e:
            dict_status["Error"] = f"Unexpected error: {str(e)}"
            return dict_status

    def check_timestamp(self):
        """
        生成一个当前时间戳，作为info的第一个参数
        """
        now = datetime.datetime.now()
        readable_timestamp = now.strftime("%Y-%m-%d %H:%M:%S")
        self.info['Check_Time'] = readable_timestamp

    def check_processes_status(self, check_list: list) -> bool:
        """
        检查指定的进程是否正在运行。
        """
        all_running = True
        process_list = {}

        for proc in check_list:
            truncated_proc = proc[:15]
            result = subprocess.run(
                ["pgrep", "-c", "-f", truncated_proc],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            # 成功
            if result.returncode == 0:
                count = int(result.stdout.strip())
                process_list[proc] = count
            # 失败
            else:
                process_list[proc] = 0
                all_running = False

        self.info["Process_Cnt"] = process_list
        return all_running

    def get_rpm_package_version(self, package_name):
        """
        使用 rpm -q 查询软件包版本信息
        """
        try:
            # 使用 rpm -q --queryformat 格式化输出
            # %{NAME} 获取软件包名称
            # %{VERSION} 获取版本号
            # %{RELEASE} 获取发布号
            # %{ARCH} 获取架构
            output = self.run_command(['rpm', '-q', '--queryformat', '%{NAME}:%{VERSION}-%{RELEASE}:%{ARCH}', package_name])
            
            if not output:
                return None

            parts = output.split(':')
            if len(parts) == 3:
                package_info = {
                    'Package': parts[0],
                    'Version': parts[1],
                    'Architecture': parts[2]
                }
                return package_info['Version']
            else:
                return None

        except Exception as e:
            return None

    def get_apt_package_version(self, package_name):
        """
        使用apt show 获得软件版本信息
        """
        try:
            result = self.run_command(['apt', 'show', package_name])
            if not result:
                return None            
            
            # 解析输出
            package_info = {}
            
            for line in result:
                line = line.strip()
                
                # 查找Package信息
                if line.startswith('Package:'):
                    package_info['Package'] = line.split(':', 1)[1].strip()
                
                # 查找Version信息
                elif line.startswith('Version:'):
                    package_info['Version'] = line.split(':', 1)[1].strip()
                
                # 查找Status信息
                elif line.startswith('Status:'):
                    package_info['Status'] = line.split(':', 1)[1].strip()
                
                # 如果已经收集到所有需要的信息，提前退出循环
                if len(package_info) == 3:
                    break
            
            # 检查是否成功获取到所有必要信息
            if len(package_info) == 3:
                return package_info
            else:
                return None
                
        except Exception as e:
            # print(f"Error getting package info for {package_name}: {e}")
            return None

    def check_os_ver_info(self):
        """
        检查并获取 Linux 系统的操作系统版本、内核、启动时间等信息。
        """
        os_info = {
            'Host_Name': "N/A",
            'Distribution_Name': "N/A",
            'Distribution_Version': "N/A",
            'Description': "N/A",
            'Architecture': "N/A",
            'Kernel_Version': "N/A",
            'Up_Time': "N/A",
            'Last_Boot_Time': "N/A"
        }

        # 获取内核版本 (Kernel_Version)
        ans = self.run_command(['uname', '-r'])
        if ans:
            os_info['Kernel_Version'] = ans

        # 获取发行版信息 (Distribution_Name, Distribution_Version)
        # 使用 lsb_release 命令
        dist_info_output = self.run_command(['lsb_release', '-a'])
        if dist_info_output:
            for line in dist_info_output.split('\n'):
                if "Distributor ID:" in line:
                    os_info['Distribution_Name'] = line.split(":")[-1].strip()
                elif "Release:" in line:
                    os_info['Distribution_Version'] = line.split(":")[-1].strip()
                elif "Description" in line:
                    os_info['Description'] = line.split(":")[-1].strip()
        # 如果 lsb_release 不可用，尝试读取 /etc/os-release
        else:
            try:
                os_release_content = self.run_command(['cat', '/etc/os-release'])
                if os_release_content:
                    name_match = re.search(r'^NAME="?(.*?)"?$', os_release_content, re.MULTILINE)
                    ver_match = re.search(r'^VERSION_ID="?(.*?)"?$', os_release_content, re.MULTILINE)
                    pretty_match = re.search(r'^PRETTY_NAME="?(.*?)"?$', os_release_content, re.MULTILINE)
                    if name_match:
                        os_info['Distribution_Name'] = name_match.group(1).strip()
                    if ver_match:
                        os_info['Distribution_Version'] = ver_match.group(1).strip()
                    if ver_match:
                        os_info['Description'] = pretty_match.group(1).strip()
            except Exception as e:
                print(f"Error reading /etc/os-release: {e}")

        # 获取架构
        try:
            arch = self.run_command(['arch'])
            if arch:
                os_info['Architecture'] = arch
        except Exception as e:
            print(f"Error getting Architecture: {e}")

        # 获取主机名 (Host_Name)
        try:
            hostname_output = self.run_command(['hostname'])
            if hostname_output:
                os_info['Host_Name'] = hostname_output
        except Exception as e:
            print(f"Error getting hostname: {e}")

        # 获取上次启动时间 (Last_Boot_Time)
        try:
            boot_output = self.run_command(['who', '-b'])
            if boot_output:
                # who -b 输出格式为 "         system boot  2023-10-27 10:30"
                parts = boot_output.split()
                if len(parts) >= 4:
                    os_info['Last_Boot_Time'] = f"{parts[2]} {parts[3]}"
                else:
                    print("Unexpected output from 'who -b'")
        except Exception as e:
            print(f"Error getting last boot time: {e}")

        # 获取系统运行时间 (Up_Time)
        try:
            uptime_output = self.run_command(['uptime', '-p'])
            if uptime_output:
                # uptime -p 输出格式为 "up 1 day, 2 hours, 3 minutes"
                os_info['Up_Time'] = uptime_output.strip().replace("up ", "")
        except Exception as e:
            print(f"Error getting uptime info: {e}")

        self.info["OS_Info"] = os_info


    def check_mainboard_info(self):
        # 初始值
        mainboard_info = {
            'Manufacturer': "N/A",
            'Product_Name': "N/A",
            'Serial_Number': "N/A",
            'UUID': "N/A",
            'BIOS_Vendor': "N/A",
            'BIOS_Version': "N/A",
        }

        # 尝试使用 dmidecode 命令获取系统信息 (Type 1)
        try:
            command_output = self.run_command(['dmidecode', '-t', 'system'])
            if command_output:
                for line in command_output.split('\n'):
                    if "Manufacturer:" in line:
                        mainboard_info['Manufacturer'] = line.split(":")[-1].strip()
                    elif "Product Name:" in line:
                        mainboard_info['Product_Name'] = line.split(":")[-1].strip()
                    elif "Serial Number:" in line:
                        mainboard_info['Serial_Number'] = line.split(":")[-1].strip()
                    elif "UUID:" in line:
                        mainboard_info['UUID'] = line.split(":")[-1].strip()
        except Exception as e:
            print(f"Error executing dmidecode -t system: {e}")

        # 尝试使用 dmidecode 获取 BIOS 信息 (Type 0)
        try:
            command_output = self.run_command(['dmidecode', '-t', 'bios'])
            if command_output:
                for line in command_output.split('\n'):
                    if "Vendor:" in line:
                        mainboard_info['BIOS_Vendor'] = line.split(":")[-1].strip()
                    elif "Version:" in line:
                        mainboard_info['BIOS_Version'] = line.split(":")[-1].strip()
        except Exception as e:
            print(f"Error executing dmidecode -t bios: {e}")

        # 将结果添加到 info 字典
        self.info["MainBoard_Info"] = mainboard_info

    def check_RAM_info(self):
        '''
        检查内存信息
        '''

        RAM_info = {
            'Memory_Total_Size': "N/A",
            'Memory_Modules': [] 
        }

        # 尝试使用 dmidecode 获取内存信息
        try:
            command_output = self.run_command(['dmidecode', '-t', 'memory'])
            if command_output:
                memory_size_mb = 0
                current_module = {}
                for line in command_output.split('\n'):
                    line = line.strip()
                    if line.startswith("Memory Device"):
                        if current_module:
                            RAM_info['Memory_Modules'].append(current_module)
                        current_module = {
                            'Size': "N/A",
                            'Speed': "N/A",
                            'Technology': "N/A",
                            'Manufacturer': "N/A",
                            'Part_Number': "N/A",
                            'Serial_Number': "N/A"
                        }
                    elif line.startswith("Size:"):
                        size_str = line.split(":")[-1].strip()
                        if "No Module Installed" not in size_str:
                            current_module['Size'] = size_str
                            parts = size_str.split()
                            if len(parts) >= 2:
                                size = int(parts[0])
                                unit = parts[1].strip()
                                if unit == "MB":
                                    memory_size_mb += size
                                elif unit == "GB":
                                    memory_size_mb += size * 1024
                    elif line.startswith("Configured Memory Speed:"):
                        current_module['Speed'] = line.split(":")[-1].strip()
                    elif line.startswith("Memory Technology:"):
                        current_module['Technology'] = line.split(":")[-1].strip()
                    elif line.startswith("Manufacturer:"):
                        current_module['Manufacturer'] = line.split(":")[-1].strip()
                    elif line.startswith("Part Number:"):
                        current_module['Part_Number'] = line.split(":")[-1].strip()
                    elif line.startswith("Serial Number:"):
                        current_module['Serial_Number'] = line.split(":")[-1].strip()

                # Append the last module after the loop finishes
                if current_module:
                    RAM_info['Memory_Modules'].append(current_module)

                if memory_size_mb > 0:
                    RAM_info['Memory_Total_Size'] = f"{memory_size_mb // 1024} GB" if memory_size_mb % 1024 == 0 else f"{memory_size_mb} MB"
        except Exception as e:
            print(f"Error executing dmidecode -t memory: {e}")
            
        # 将结果添加到 info 字典
        self.info["RAM_Info"] = RAM_info

    def check_login_info(self):
        """
        检查并获取系统的登录信息，包括最后一次成功登录和登录失败的次数。
        """

        login_info = {
            'Last_User': "N/A",
            'Last_Terminal': "N/A",
            'Last_Login_Ip': "N/A",
            'Last_Login_Time': "N/A",
            'Failed_Attempts': 0
        }

        # 获取最后一次成功登录的信息
        try:
            last_login_output = self.run_command(['last', '-n', '1'])
            if last_login_output:
                first_line = last_login_output.split('\n')[0].strip()
                # 使用 split() 按空格分割，并过滤空字符串
                parts = [p for p in first_line.split(' ') if p]
                
                # 根据字段数量来处理不同的输出格式
                # 常见格式: user tty ip time - time
                # 你的格式: user tty ip time still logged in
                if len(parts) >= 7:
                    login_info['Last_User'] = parts[0]
                    login_info['Last_Terminal'] = parts[1]
                    login_info['Last_Login_Ip'] = parts[2]
                    
                    # 组合日期和时间部分
                    # 从第四个字段（星期几）开始，到第七个字段（时间）结束
                    login_info['Last_Login_Time'] = ' '.join(parts[3:7])
                else:
                    print("Unexpected 'last' command output format or no user logged in.")
                    
        except Exception as e:
            print(f"Error getting last login info: {e}")

        # 获取登录失败的次数
        # 尝试使用 'lastb' 命令（如果可用）
        try:
            failed_attempts_output = self.run_command(['lastb', '-n', '100'])
            if failed_attempts_output:
                login_info['Failed_Attempts_Lastb'] = len(failed_attempts_output.split('\n'))
        except Exception as e:
            print(f"Command 'lastb' not found or error: {e}")
            log_file = None
            if os.path.exists('/var/log/auth.log'):
                log_file = '/var/log/auth.log'
            elif os.path.exists('/var/log/secure'):
                log_file = '/var/log/secure'
            if log_file:
                try:
                    # 统计日志文件中包含“failed password”的行数
                    failed_count_output = self.run_command(['grep', '-c', 'failed password', log_file])
                    if failed_count_output and failed_count_output.isdigit():
                        login_info['Failed_Attempts_Log'] = int(failed_count_output)
                except Exception as e:
                    # print(f"Error getting failed login info from {log_file}: {e}")
                    pass

        # 将最终的字典赋值给实例变量
        self.info['Login_Info'] = login_info

    def check_grub_info(self):
        '''
        解析grub脚本的cmdlime参数
        '''

        grub_cmd_list = []

        try:
            grub_file_content = self.run_command(['cat', '/etc/default/grub'])
            if grub_file_content:
                lines = grub_file_content.split('\n')
                for line in lines:
                    if line.startswith("GRUB_CMDLINE_LINUX="):
                        # 提取双引号内的内容，并去除首尾空格
                        grub_line = line.split("=", 1)[-1].strip()
                        # 移除双引号
                        grub_line = grub_line.strip('"')
                        # 按空格分割参数，并过滤空字符串
                        params = [p.strip() for p in grub_line.split() if p.strip()]
                        grub_cmd_list = params
                        # 找到后即可退出循环
                        break
        except Exception as e:
            # print(f"Failed to parse GRUB info: {e}")
            pass

        self.info["GRUB_Cmd_Info"] = grub_cmd_list

    def check_sysctl_info(self):
        """
        解析/etc/sysctl.conf的参数
        """
        sysctl_info = {}
        try:
            sysctl_content = self.run_command(['cat', '/etc/sysctl.conf'])
            if sysctl_content:
                for line in sysctl_content.splitlines():
                    line = line.strip()

                    if not line or line.startswith('#'):
                        continue

                    if '=' in line:
                        key, value = line.split('=', 1)
                        key = key.strip()
                        value = value.strip()
                        sysctl_info[key] = value

        except Exception as e:
            print(f"Failed to parse sysctl info: {e}")
            sysctl_info = {} 

        self.info["Sysctl_Info"] = sysctl_info

    def check_cpu_info(self) -> bool:
        '''
        查询cpu相关信息
        '''

        cpu_info = {}
        cpu_info['CPU_Name'] = "N/A"
        cpu_info['CPU_Arch'] = "N/A"
        cpu_info['CPU_Cnt'] = "N/A"
        cpu_info['Byte_Order'] = "N/A"
        cpu_info['Scaling_Governor'] = "N/A"
        
        cpu_output = self.run_command(['lscpu'])
        if not cpu_output:
            self.info["CPU_Info"] =  cpu_info
            return False

        # 查询CPU基本信息
        for line in cpu_output.split('\n'):
            if "Model name" in line:
                cpu_info['CPU_Name'] = line.split(":")[-1].strip()
            if "型号名称：" in line:
                cpu_info['CPU_Name'] = line.split("：")[-1].strip()
            elif "Architecture" in line:
                cpu_info['CPU_Arch'] = line.split(":")[-1].strip()
            elif "架构：" in line:
                cpu_info['CPU_Arch'] = line.split("：")[-1].strip()
            elif line.strip().startswith("CPU(s):"):
                cpu_info['CPU_Cnt'] = line.split(":")[-1].strip()
            elif line.strip().startswith("CPU:"):
                cpu_info['CPU_Cnt'] = line.split(":")[-1].strip()
            elif line.strip().startswith("Byte Order:"):
                cpu_info['Byte_Order'] = line.split(":")[-1].strip()
            elif line.strip().startswith("字节序："):
                cpu_info['Byte_Order'] = line.split("：")[-1].strip()
        # 查询节能模式
        try:
            governor_output = self.run_command(['cat', '/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor'])
            if governor_output and "No such file or directory" not in governor_output:
                cpu_info['Scaling_Governor'] = governor_output.strip()
        except Exception as e:
            print(f"Error reading scaling_governor: {e}")

        self.info["CPU_Info"] =  cpu_info
        return True

    def check_mem_basic_info(self):
        '''
        查询内存基本信息，使用free -h
        '''

        self.info['Meminfo_Free'] = {}
        meminfo_free = {}
        # 解析 free -h 命令
        free_output = self.run_command(['free', '-h'])
        if free_output:
            lines = free_output.splitlines()
            for line in lines:
                if "Mem:" in line:
                    values = line.split() 
                    if len(values) >= 7:  # 7列: 'Mem:' + 6个值
                        meminfo_free['total'] = values[1]
                        meminfo_free['used'] = values[2]
                        meminfo_free['free'] = values[3]
                        meminfo_free['shared'] = values[4]
                        meminfo_free['buff_cache'] = values[5]
                        meminfo_free['available'] = values[6]
                    else:
                        # 警告：输出格式不符合预期
                        print(f"Warning: Unexpected free -h output format. Line: {line}")
        self.info['Meminfo_Free'] =  meminfo_free
        
    def check_mem_detail_info(self):
        """
        查询内存详细信息，即解析 /proc/meminfo 文件
        """
        meminfo = {}

        # 查看meminfo文件
        meminfo_output = self.run_command(['cat', '/proc/meminfo'])
        if meminfo_output:
            for line in meminfo_output.splitlines():
                # A valid line should contain a colon
                if ':' in line:
                    key, value = line.split(':', 1)
                    key = key.strip()
                    value = value.strip()
                    meminfo[key] = value
        
        self.info["Meminfo_Detail"] = meminfo
        
    def check_nvidia_gpu_info(self):
        """
        查询 NVIDIA GPU 的相关信息（数量、型号、驱动和位置）
        """

        nvidia_info = {
            "Cnt": 0,
            "Driver_Version": "N/A",
            "CUDA_Version": "N/A",
            "Info": []
        }

        try:
            command = "lspci | grep 'VGA compatible controller' | grep -i Nvidia"
            result = self.run_command(command, shell=True)
            if result and "not found" not in result:
                nvidia_info["Cnt"] = len(result.splitlines())
            else:
                nvidia_info["Cnt"] = 0
        except (subprocess.CalledProcessError, FileNotFoundError) as e:
            # print(f"Error running command: {e}")
            pass

        gpu_query_cmd = "nvidia-smi --query-gpu=gpu_name,driver_version,pci.bus_id --format=csv,noheader"
        gpu_output = self.run_command(gpu_query_cmd, shell=True)

        if gpu_output:
            try:
                gpu_lines = gpu_output.splitlines()
                nvidia_info["Cnt"] = len(gpu_lines)
                for line in gpu_lines:
                    parts = [p.strip() for p in line.split(',')]
                    if len(parts) >= 3:
                        name, driver, bus_id = parts
                        nvidia_info["Driver_Version"] = driver
                        nvidia_info["Info"].append({
                            "Name": name,
                            "Loc": bus_id
                        })
            except Exception as e:
                print(f"Failed to parse nvidia-smi GPU output: {e}")
        
        cuda_version_cmd = "nvidia-smi -q | grep 'CUDA Version'"
        cuda_output = self.run_command(cuda_version_cmd, shell=True)
        
        if cuda_output:
            try:
                cuda_match = re.search(r"CUDA Version\s+:\s+(\S+)", cuda_output)
                if cuda_match:
                    nvidia_info["CUDA_Version"] = cuda_match.group(1)
            except Exception as e:
                print(f"Failed to parse CUDA version: {e}")

        # Store the final information
        self.info["Nvidia_GPU_Info"] = nvidia_info

    def check_intel_gpu_info(self):
        """
        查询intel显卡信息（数量、型号和位置，暂不查询驱动版本）
        """
        intel_gpu_info = {
            "Cnt": 0,
            "Info": []
        }

        try:
            command = "lspci | grep 'VGA compatible controller' | grep 'Intel Corporation'"
            result = subprocess.run(
                command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True,
                check=True
            )
            intel_vga_output = result.stdout.strip()

            if intel_vga_output:
                for line in intel_vga_output.splitlines():
                    info = {}
                    info["Name"] = "N/A"
                    info["Loc"] = "N/A"

                    clean_line = line.strip()
                    parts = clean_line.split()
                    if len(parts) > 0:
                        info["Name"] = " ".join(parts[4:])
                        info["Loc"] = parts[0]
                        intel_gpu_info["Info"].append(info)
                        intel_gpu_info["Cnt"] += 1

        except (subprocess.CalledProcessError, FileNotFoundError) as e:
            # print(f"Error running command: {e}")
            pass

        self.info['Intel_GPU_Info'] = intel_gpu_info
    
    def check_emerge_gpu_info(self):
        """
        查询涌现显卡信息，使用lspci 过滤 accelerators 关键字
        """
        emerge_gpu_info = {
            "Cnt": 0,
            "Driver_Loaded" : False,
            "Info": []  
        }

        # 查询卡名称和位置
        try:
            command = "lspci | grep 'accelerators'"
            result = subprocess.run(
                command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True,
                check=True
            )
            emerge_output = result.stdout.strip()

            if emerge_output:
                for line in emerge_output.splitlines():
                    clean_line = line.strip()
                    parts = clean_line.split()
                    
                    if len(parts) > 0:
                        info = {}
                        info["Name"] = " ".join(parts[3:]) 
                        info["Loc"] = parts[0]
                        
                        emerge_gpu_info["Cnt"] += 1
                        emerge_gpu_info["Info"].append(info)
        except (subprocess.CalledProcessError, FileNotFoundError) as e:
            # print(f"Error running command: {e}")
            pass


        # 查询卡的驱动信息
        try:
            command = "lsmod | grep 'transcoder_pcie'"
            result = subprocess.run(
                command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True,
                check=True
            )
            if result:
                emerge_gpu_info["Driver_Loaded"] = True
        except (subprocess.CalledProcessError, FileNotFoundError) as e:
            # print(f"Error running command: {e}")
            pass

        self.info['Emerge_GPU_Info'] = emerge_gpu_info

    def check_diskinfo_free(self) -> bool:
        """
        查询磁盘空间信息，使用'df -h' 
        """

        disk_info_list = []

        # run command
        cmd = "df -h | grep -v tmpfs"
        disk_output = self.run_command(cmd, shell=True)
        if not disk_output:
            self.info['Diskinfo_Free'] = disk_info_list
            return False
        
        # parse output
        lines = disk_output.splitlines()
        # Skip the header line
        for line in lines[1:]:
            parts = line.split()
            if len(parts) >= 6:
                disk_info = {
                    'Filesystem': parts[0],
                    'Size': parts[1],
                    'Used': parts[2],
                    'Avail': parts[3],
                    'Use%': parts[4],
                    'Mounted on': parts[5]
                }
                disk_info_list.append(disk_info)

        self.info['Diskinfo_Free'] = disk_info_list
        return True

    def check_block_info(self):
        """
        查询内存块分布信息，使用'lsblk --json'，部分lsblk版本可能不支持此操作
        """
        # Using 'lsblk --json' for reliable, machine-readable output.
        disk_output = self.run_command(['lsblk', '--json', '-b'])
        if not disk_output or 'unrecognized' in disk_output:
            self.info['Block_Info'] = []
            return

        try:
            # Load the JSON data
            data = json.loads(disk_output)
            
            # Recursively parse devices and their children
            def parse_devices(devices):
                parsed_list = []
                for dev in devices:
                    info = {
                        'name': dev.get('name'),
                        'type': dev.get('type'),
                        'size': f"{dev.get('size') / (1024**3):.1f}G" if dev.get('size') else '0G',
                        'mountpoint': dev.get('mountpoint', 'N/A')
                    }
                    
                    # Check for children devices (partitions, LVMs, etc.)
                    if 'children' in dev and dev['children']:
                        info['children'] = parse_devices(dev['children'])
                    
                    parsed_list.append(info)
                return parsed_list

            # Start parsing from the top-level block devices
            self.info['Block_Info'] = parse_devices(data.get('blockdevices', []))
        except (json.JSONDecodeError, KeyError) as e:
            print(f"Error parsing lsblk JSON output: {e}")
            self.info['Block_Info'] = []

    def check_netcard_info(self) -> bool:
        """
        查询网卡信息
        using the 'ip -s addr' command.
        """
        netcard_info_list = []
        current_netcard = None

        # ip addr 查询
        netcard_output = self.run_command(['ip', '-s', 'addr'])
        if not netcard_output:
            self.info['Netcard_Info'] = netcard_info_list
            return False
        lines = netcard_output.splitlines()

        i = 0
        while i < len(lines):
            line = lines[i].strip()
            
            # Check for a new network interface block
            if line and line[0].isdigit() and ':' in line and '<' in line:
                if current_netcard:
                    netcard_info_list.append(current_netcard)
                
                # Reset for the new interface
                current_netcard = {
                    'name': "N/A",
                    'state': "N/A",
                    'ipv4': "N/A",
                    'ipv6': "N/A",
                    'mac_address': "N/A",
                    'mtu': "N/A",
                    'speed': "N/A",
                    'duplex': "N/A",
                    #'rx_bytes': "N/A",
                    #'rx_packets': "N/A",
                    #'tx_bytes': "N/A",
                    #'tx_packets': "N/A"
                }
                
                parts = line.split()
                current_netcard['name'] = parts[1].strip(':')
                # current_netcard['flags'] = parts[2].strip('<>').split(',')
                
                # Use a loop to find MTU, state, and qlen
                for j in range(3, len(parts)):
                    if parts[j] == 'mtu' and j + 1 < len(parts):
                        current_netcard['mtu'] = parts[j+1]
                    elif parts[j] == 'state' and j + 1 < len(parts):
                        current_netcard['state'] = parts[j+1]

            # Check for MAC Address
            elif line.startswith('link/ether'):
                try:
                    current_netcard['mac_address'] = line.split()[1]
                except IndexError:
                    pass

            elif 'inet ' in line:
                try:
                    current_netcard['ipv4'] = line.split()[1].split('/')[0]
                except IndexError:
                    pass
                    
            elif 'inet6 ' in line:
                try:
                    current_netcard['ipv6'] = line.split()[1].split('/')[0]
                except IndexError:
                    pass
            
            # Check for RX/TX statistics
            # The statistics are usually on lines after the main interface line 
            if current_netcard and i + 1 < len(lines):
                next_line = lines[i+1].strip()
                if next_line.startswith('RX:'):
                    if i + 2 < len(lines):
                        stats_line_rx = lines[i+2].strip().split()
                        if len(stats_line_rx) >= 2:
                            pass
                            #current_netcard['rx_bytes'] = stats_line_rx[0]
                            #current_netcard['rx_packets'] = stats_line_rx[1]
                        i += 2  # Skip the next two lines as they contain RX stats
                    else:
                        i += 1
                elif next_line.startswith('TX:'):
                    if i + 2 < len(lines):
                        stats_line_tx = lines[i+2].strip().split()
                        if len(stats_line_tx) >= 2:
                            pass
                            #current_netcard['tx_bytes'] = stats_line_tx[0]
                            #current_netcard['tx_packets'] = stats_line_tx[1]
                        i += 2  # Skip the next two lines as they contain TX stats
                    else:
                        i += 1
                else:
                    i += 1
            else:
                i += 1
        # 添加最后一张卡
        if current_netcard:
            netcard_info_list.append(current_netcard)
        
        # 检查speed和duplex模式
        for card_info in netcard_info_list:
            if card_info['name']:
                ethtool_output = self.run_command(['ethtool', card_info['name']])
                if ethtool_output:
                    # Use regular expressions to find speed, duplex, and link status
                    speed_match = re.search(r'Speed: (\d+Mb/s)', ethtool_output)
                    duplex_match = re.search(r'Duplex: (Full|Half)', ethtool_output)
                    link_match = re.search(r'Link detected: (yes|no)', ethtool_output)

                    if speed_match:
                        card_info['speed'] = speed_match.group(1)
                    if duplex_match:
                        card_info['duplex'] = duplex_match.group(1)
                    if link_match:
                        card_info['link_detected'] = link_match.group(1)

        self.info['Netcard_Info'] = netcard_info_list
        return True


    def check_versions(self):
        """
        查询一些开发和依赖库、基础软件的版本信息
        """

        software_versions = {
            'g++_ver': "N/A",
            'python_ver': "N/A",
            'python3_ver': "N/A",
            'make_ver': "N/A",
            'cmake_ver': "N/A",
            "glibc_ver": "N/A",
            "openssl_ver": "N/A",
            "libcurl_ver": "N/A",
            "java_ver": "N/A",
            "docker_ver": "N/A"
        }

        # Check G++ version
        gplusplus_output = self.run_command(['g++', '--version'])
        if gplusplus_output:
            lines = gplusplus_output.splitlines()
            if lines and "g++" in lines[0]:
                # Use regex to reliably extract the version number
                match = re.search(r'g\+\+ \((.*?)\) ([\d\.]+)', lines[0])
                if match:
                    software_versions['g++_ver'] = match.group(2)
                else:
                    software_versions['g++_ver'] = " ".join(lines[0].split()[2:])

        # Check python version
        python_output = self.run_command(['python', '--version'])
        if python_output:
            software_versions['python_ver'] = python_output.split(" ")[-1]

        # Check python3 version
        python3_output = self.run_command(['python3', '--version'])
        if python3_output:
            software_versions['python3_ver'] = python3_output.split()[-1]

        # Check make version
        make_output = self.run_command(['make', '--version'])
        if make_output:
            lines = make_output.splitlines()
            if lines:
                software_versions['make_ver'] = lines[0].split()[-1]

        # Check cmake version
        cmake_output = self.run_command(['cmake', '--version'])
        if cmake_output:
            lines = cmake_output.splitlines()
            if lines:
                software_versions['cmake_ver'] = lines[0].split()[-1]

        # Check glibc version
        ldd_output = self.run_command(['ldd', '--version'])
        if ldd_output:
            lines = ldd_output.splitlines()
            if lines and "ldd" in lines[0]:
                software_versions["glibc_ver"] = lines[0].split()[-1]

        # Check OpenSSL version
        openssl_output = self.run_command(['openssl', 'version'])
        if openssl_output:
            software_versions["openssl_ver"] = openssl_output.split()[1]

        # Check libcurl version
        curl_output = self.run_command(['curl', '--version'])
        if curl_output:
            lines = curl_output.splitlines()
            if lines and "curl" in lines[0]:
                software_versions["libcurl_ver"] = lines[0].split()[1]

        # Check Java version
        java_output = self.run_command(['java', '-version'])
        # The output of java -version goes to stderr, so we need a robust check.
        if java_output:
            for line in java_output.splitlines():
                if "version" in line:
                    # Use a regex to handle different Java version string formats
                    match = re.search(r'"(.*?)"', line)
                    if match:
                        software_versions["java_ver"] = match.group(1)
                    break

        # Check Docker version
        docker_output = self.run_command(['docker', '--version'])
        if docker_output:
            if "Docker version" in docker_output:
                software_versions["docker_ver"] = docker_output.split(' ')[2].replace(',', '')

        # Store the combined information in the instance's info dictionary
        self.info["Software_Versions"] = software_versions

    def check_suma_software_versions(self, suma_path="/usr/sbin/sumavision/version"):
        '''
        检查sumavision目录下的版本信息
        '''

        suma_software_list = []

        # 检查suma_path是否存在
        if os.path.isdir(suma_path):
            try:
                # 列出当前目录下的文件名称，放入list
                files = os.listdir(suma_path)
                # 过滤掉目录，只保留文件
                suma_software_list = [f for f in files if os.path.isfile(os.path.join(suma_path, f))]
                
            except OSError as e:
                # 捕获权限错误或其他文件系统错误
                print(f"Error accessing directory {suma_path}: {e}")
                suma_software_list = []
                
        else:
            # 如果路径不存在，则返回一个包含"N/A"的列表，或者一个空列表
            print(f"Directory {suma_path} does not exist.")
            suma_software_list = []

        self.info["Suma_Software_Version"] = suma_software_list

    def check_blackmagic_card_info(self):
        """
        检查blackmagic卡的相关信息
        """

        # 初始化参数
        deb_list = ['dkms', "desktopvideo", "desktopvideo-gui", "mediaexpress"]
        black_magic_info = {}
        black_magic_info["Cnt"] = 0
        for deb in deb_list:
            black_magic_info[deb] = "N/A"
        black_magic_info['Info'] = []

        # check card
        try:
            command = "lspci | grep -i 'blackmagic'"
            result = subprocess.run(
                command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True,
                check=True
            )
            
            black_magic_info_out = result.stdout.strip()
            if black_magic_info_out:
                for line in black_magic_info_out.splitlines():
                    clean_line = line.strip()
                    parts = clean_line.split()
                    
                    if len(parts) > 0:
                        info = {}
                        info["Name"] = " ".join(parts[3:]) 
                        info["Loc"] = parts[0]
                        
                        black_magic_info["Cnt"] += 1
                        black_magic_info["Info"].append(info)
        except (subprocess.CalledProcessError, FileNotFoundError) as e:
            # print(f"Error running command: {e}")
            pass

        # check apt or yum
        apt_exist = shutil.which('apt') is not None
        yum_exist = shutil.which('yum') is not None

        # check driver version
        for deb in deb_list:
            if apt_exist:
                deb_info = self.get_apt_package_version(deb)
            elif yum_exist:
                deb_info = self.get_rpm_package_version(deb)
            else:
                deb_info = None
            if deb_info:
                black_magic_info[deb]  = deb_info

        self.info['Black_Magic_Info'] = black_magic_info

    def check_cron_task_info(self):
        """
        解析CRON定时任务
        """

        cron_task_list = {
            "Cnt": 0,
            "Info": []  
        }

        # check card
        try:
            command = "crontab -l"
            result = subprocess.run(
                command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True,
                check=True
            )
            cron_ans = result.stdout.strip()
            for line in cron_ans.splitlines():
                cron_task_list["Cnt"] = cron_task_list["Cnt"] + 1
                cron_task_list["Info"].append(line)
        except (subprocess.CalledProcessError, FileNotFoundError) as e:
            # print(f"Error running command: {e}")
            pass

        self.info["Cron_Task_Info"] = cron_task_list

    def check_listen_port(self):
        """
        检查当前监听端口信息
        """

        listen_ports = {}
        listen_ports["Cnt"] = int(0)
        listen_ports["Port"] = []

        try:
            command = "netstat -tunlp"
            result = subprocess.run(
                command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True,
                check=True
            )
            
            # Split the output into lines and skip the first two header lines
            ports_ans = result.stdout.strip().splitlines()[2:]

            for line in ports_ans:
                parts = line.split()
                if len(parts) >= 7:  # Ensure there are enough columns to parse
                    proto = parts[0]
                    recv_q = int(parts[1])
                    send_q = int(parts[2])
                    local_address = parts[3]
                    foreign_address = parts[4]
                    state = parts[5]
                    pid_program = parts[6]
                    
                    # Special handling for UDP/UDP6 to set state to empty string
                    if proto.startswith("udp"):
                        state = ""
                    
                    port_info = {
                        "proto": proto,
                        "recv_q": recv_q,
                        "send_q": send_q,
                        "local_address": local_address,
                        "foreign_address": foreign_address,
                        "state": state,
                        "pid_program": pid_program
                    }
                    listen_ports["Cnt"] += 1
                    listen_ports["Port"].append(port_info)
        
        except (subprocess.CalledProcessError, FileNotFoundError) as e:
            # print(f"Error running command: {e}")
            pass

        self.info["Listen_Ports"] = listen_ports
    
    # todo，暂时不从此处解析
    def check_iptables_rules(self):
        """
        从小工具防火墙中解析规则.
        """
        iptables_rules = {
            "Chain_Name": "",
            "Policy": "",
            "Count": 0,
            "Rules": []
        }
        
        try:
            command = "iptables -nvL"
            result = subprocess.run(
                command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True,
                check=True
            )
            
            lines = result.stdout.strip().splitlines()
            
            if lines:
                header_line = lines[0]
                header_parts = header_line.split()
                if len(header_parts) >= 4:
                    iptables_rules["Chain_Name"] = header_parts[1]
                    iptables_rules["Policy"] = header_parts[3].strip('(')

            if len(lines) > 2:
                rules_lines = lines[2:] 
                for line in rules_lines:
                    parts = re.findall(r'\S+', line)
                    if len(parts) > 8:
                        rule = {
                            "pkts": parts[0],
                            "bytes": parts[1],
                            "target": parts[2],
                            "prot": parts[3],
                            "opt": parts[4],
                            "in": parts[5],
                            "out": parts[6],
                            "source": parts[7],
                            "destination": parts[8]
                        }
                        
                        iptables_rules["Count"] += 1
                        iptables_rules["Rules"].append(rule)

        except (subprocess.CalledProcessError, FileNotFoundError) as e:
            # print(f"Error running command: {e}")
            pass

        self.info["Iptables_Rules"] = iptables_rules

    def check_firewall_rules(self, path="/sbin/sumavision/firewall"):
        """
        从小工具firewall脚本处读取防火墙配置信息
        """
        firewall_rules_list = {
            "Count": 0,
            "Rules": []
        }

        try:
            # Check if the directory exists and is a directory
            if not os.path.isdir(path):
                print(f"Error: Directory not found or is not a directory: {path}")
                self.info["Firewall_Rules"] = firewall_rules_list
                return

            # Regular expression to match iptables ACCEPT rules
            # It looks for '-A INPUT -p <protocol> --dport <port> -j ACCEPT'
            # The regex is flexible enough to capture protocol and dport
            rule_pattern = re.compile(
                r'iptables\s+-A\s+INPUT\s+-p\s+(?P<protocol>\S+)\s+--dport\s+(?P<port>\S+)\s+-j\s+ACCEPT'
            )

            for filename in os.listdir(path):
                if filename.endswith(".sh"):
                    file_path = os.path.join(path, filename)
                    try:
                        with open(file_path, 'r', encoding='utf-8') as f:
                            for line in f:
                                match = rule_pattern.search(line)
                                if match:
                                    rule_info = {
                                        "protocol": match.group('protocol'),
                                        "port": match.group('port')
                                    }
                                    firewall_rules_list["Count"] += 1
                                    firewall_rules_list["Rules"].append(rule_info)
                    except Exception as e:
                        print(f"Error reading file {file_path}: {e}")
        
        except Exception as e:
            print(f"An unexpected error occurred: {e}")

        self.info["Firewall_Rules"] = firewall_rules_list

    def check_top10_cpu_usage_process(self) -> bool:
        """
        检查并返回当前系统CPU使用率排名前十的进程信息。
        """

        top10_processes = []
        try:
            cmd = "top -b -n 1 -o %CPU | head -n 17"
            output = self.run_command(cmd, shell=True)
            if not output:
                self.info["Top10_CPU_Usage"] = top10_processes
                return False

            lines = output.strip().split('\n')

            process_lines = lines[7:]
            for line in process_lines:
                parts = line.split()
                if len(parts) >= 12: 
                    try:
                        process_info = {
                            "COMMAND": ' '.join(parts[11:]),
                            "PID": parts[0],
                            "CPU_USAGE": parts[8],
                            "MEM_USAGE": parts[9]
                        }
                        top10_processes.append(process_info)
                    except IndexError as e:
                        # This handles cases where a line might have fewer parts than expected
                        print(f"Error parsing line: {line}. Skipping. Error: {e}")
                        continue
            
            self.info["Top10_CPU_Usage"] = top10_processes
            return True

        except Exception as e:
            self.info["Top10_CPU_Usage"] = top10_processes
            print(f"Error getting top 10 CPU usage processes: {e}")
            False
    
    def check_top10_mem_usage_process(self) -> bool:
        """
        检查并返回当前系统内存使用率排名前十的进程信息。
        """

        top10_processes = []
        
        try:
            # 使用 -b 批处理模式, -n 1 只运行一次, -o %MEM 按内存使用率排序
            # head -n 17 获取前7行头部信息和随后的10行进程信息
            cmd = "top -b -n 1 -o %MEM | head -n 17"
            
            # 假设 self.run_command 能够执行 shell 命令并返回输出
            output = self.run_command(cmd, shell=True)
            if not output:
                self.info["Top10_MEM_Usage"] = top10_processes
                return False

            lines = output.strip().split('\n')
            
            # 进程信息通常从第8行开始（索引为7）
            process_lines = lines[7:]
            
            for line in process_lines:
                # 使用 split() 自动处理多余的空格
                parts = line.split()
                
                if len(parts) >= 12: 
                    try:
                        process_info = {
                            "COMMAND": ' '.join(parts[11:]),
                            "PID": parts[0],
                            "CPU_USAGE": parts[8],
                            "MEM_USAGE": parts[9]
                        }
                        top10_processes.append(process_info)
                    except IndexError as e:
                        # 这可以处理某一行字段少于预期的情况
                        print(f"Error parsing line: {line}. Skipping. Error: {e}")
                        continue
            
            self.info["Top10_MEM_Usage"] = top10_processes
            return True
        
        except Exception as e:
            print(f"Error getting top 10 memory usage processes: {e}")
            self.info["Top10_MEM_Usage"] = []
            return False

    def check_all_hw_cnt(self) -> bool:
        """
        使用lspci命令简单检查各种硬件设备数量
        """

        hardware_queries = {
            "Nvidia_GPU": "lspci | grep -i vga | grep -i nvidia | wc -l",
            "Intel_GPU": "lspci | grep -i vga | grep 'Intel Corporation' | grep -vi huawei | wc -l",
            "Emerge_GPU": "lspci | grep -i accelerators| wc -l",
            "DeckLink_SDI": "lspci | grep -i DeckLink | wc -l",
            "DekTec_ASI": "lspci | grep -i DekTec | wc -l",
        }

        hw_counts = {}
        for name, cmd in hardware_queries.items():
            try:
                result = self.run_command(cmd, shell=True)
                if result and "not found" not in result:
                    count = int(result)
                    hw_counts[name] = count
                else:
                    result = 0
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
                hw_counts[name] = 0

        self.info['Hardware_Cnt'] = hw_counts
        return hw_counts

    # 过滤系统日志
    def check_sys_log(self, default_keys = syslog_check_pattern, syslog_check_record_cnt = syslog_check_record_cnt) -> bool:
        """
        检查系统日志文件，并统计包含特定关键词的日志数量。
        函数会依次检查 /var/log/syslog 和 /var/log/messages，有谁用谁
        """
        sysinfo = {}
        syslog_path = "/var/log/syslog"
        messages_path = "/var/log/messages"
        message_file = ""

        # 确定系统文件
        if os.path.exists(syslog_path):
            message_file = syslog_path
        elif os.path.exists(messages_path):
            message_file = messages_path
        else:
            self.info["Sysinfo"] = sysinfo
            print("System log file not found at /var/log/syslog or /var/log/messages.")
            return False

        # 过滤并统计日志
        for key, pattern in default_keys.items():
            try:
                # 统计数量
                count_cmd = f"grep -iE '{pattern}' {message_file} | wc -l"
                count_output = self.run_command(count_cmd, shell=True)
                if count_output:
                    count = int(count_output.strip())
                    sysinfo[key] = count
                else:
                    sysinfo[key] = 0
                
                last_log_cmd = ""
                if syslog_check_record_cnt < 0:
                    last_log_cmd = f"grep -iE '{pattern}' {message_file}"
                else:
                    last_log_cmd = f"grep -iE '{pattern}' {message_file} | tail -n {syslog_check_record_cnt}"
                last_log_output = self.run_command(last_log_cmd, shell=True)

                if last_log_output and count > 0:
                    # 使用splitlines()将多行输出存储为列表
                    sysinfo[f"last_{key}"] = last_log_output.strip().splitlines()
                else:
                    sysinfo[f"last_{key}"] = "N/A"

            except (subprocess.CalledProcessError, ValueError) as e:
                print(f"Error filtering logs for {key}: {e}")
                sysinfo[key] = "N/A"
                sysinfo[f"last_{key}"] = "N/A"

        if not any(sysinfo[key] for key in default_keys):
            # print("No log entries with specified default_keys found.")
            pass

        self.info["Sysinfo"] = sysinfo
        return True

    # 过滤dmesg信息，todo
    def check_dmesg_info(self) -> bool:
        pass

    def check_time_info(self) -> bool:
        '''
        从systemd-timedatectl中获取处理
        '''

        Time_Info = {}
        Time_Info["Local_Time"] = "N/A"
        Time_Info["Universal_Time"] = "N/A"
        Time_Info["RTC_Time"] = "N/A"
        Time_Info["Time_Zone"] = "N/A"
        Time_Info["System_Clock_Synchronized"] = "N/A"
        Time_Info["Timesyncd_Status"] = "N/A"
        Time_Info["Active_NTP_Service"] = "N/A"
        Time_Info["RTC_In_Local_TZ"] = "N/A"

        timedatectl_output = self.run_command(['timedatectl', 'status'])
        if not timedatectl_output:
            self.info["Time_Info"] = Time_Info
            print("Failed to run command timedatectl")
            return False
        
        # Parse the output line by line
        try:
            for line in timedatectl_output.splitlines():
                line = line.strip()
                if line.startswith("Local time:"):
                    Time_Info["Local_Time"] = line.split(":", 1)[1].strip()
                elif line.startswith("Universal time:"):
                    Time_Info["Universal_Time"] = line.split(":", 1)[1].strip()
                elif line.startswith("RTC time:"):
                    Time_Info["RTC_Time"] = line.split(":", 1)[1].strip()
                elif line.startswith("Time zone:"):
                    Time_Info["Time_Zone"] = line.split(":", 1)[1].strip()
                elif line.startswith("System clock synchronized:"):
                    Time_Info["System_Clock_Synchronized"] = line.split(":", 1)[1].strip()
                elif line.startswith("NTP service:"):
                    Time_Info["Timesyncd_Status"] = line.split(":", 1)[1].strip()
                elif line.startswith("RTC in local TZ:"):
                    Time_Info["RTC_In_Local_TZ"] = line.split(":", 1)[1].strip()

            # 查询其它的ntp服务
            ntp_services = ['systemd-timesyncd', 'chronyd', 'ntpd', 'ntp']
            active_services = []
            for service in ntp_services:
                try:
                    service_status = self.run_command(['systemctl', 'is-active', service])
                    if service_status and service_status.strip() == 'active':
                        active_services.append(service)
                except Exception as e:
                    print(f"Error checking service {service}: {e}")
                    continue
            
            if active_services:
                Time_Info["Active_NTP_Service"] = ", ".join(active_services)
            else:
                Time_Info["Active_NTP_Service"] = "N/A"


            self.info["Time_Info"] = Time_Info
            return True

        except Exception as e:
            print(f"Error parsing timedatectl output: {e}")
            self.info["Time_Info"] = Time_Info
            return False
    
    def check_resolve_info(self) -> bool:
        '''
        读取/etc/resolv.conf
        '''
        
        # 参数
        resolv_info = {
            "Conf_Status": "N/A",
            "NameServers": [],
            "SearchDomains": [],
            "Options": [],
            "Service_Info": {},
            "Error": "N/A"
        }
        conf_name = "/etc/resolv.conf"
        
        # 检查文件是否存在
        if not os.path.exists(conf_name):
            resolv_info["Conf_Status"] = "not_exists"
            resolv_info["Error"] = f"File {conf_name} does not exist"
            self.info["Resolv_Info"] = resolv_info
            return False

        # 检查文件是否可读
        if not os.access(conf_name, os.R_OK):
            resolv_info["Conf_Status"] = "no_permission"
            resolv_info["Error"] = f"No read permission for {conf_name}"
            self.info["Resolv_Info"] = resolv_info
            return False
        
        # 读取文件内容
        with open(conf_name, 'r') as f:
            content = f.read().strip()
        if not content:
            resolv_info["Conf_Status"] = "empty"
            self.info["Resolv_Info"] = resolv_info
            return False
        
        resolv_info["Conf_Status"] = "exists"
        # 解析DNS配置信息
        for line in content.split('\n'):
            line = line.strip()
            
            # 跳过空行和注释
            if not line or line.startswith('#'):
                continue
            
            # 解析nameserver
            if line.startswith('nameserver'):
                parts = line.split()
                if len(parts) >= 2:
                    dns_server = parts[1].strip()
                    if dns_server not in resolv_info["NameServers"]:
                        resolv_info["NameServers"].append(dns_server)
            
            # 解析search domain
            elif line.startswith('search'):
                parts = line.split()
                if len(parts) >= 2:
                    domains = parts[1:]
                    resolv_info["SearchDomains"].extend(domains)
            
            # 解析domain
            elif line.startswith('domain'):
                parts = line.split()
                if len(parts) >= 2:
                    domain = parts[1].strip()
                    if domain not in resolv_info["SearchDomains"]:
                        resolv_info["SearchDomains"].append(domain)
            
            # 解析options
            elif line.startswith('options'):
                parts = line.split()
                if len(parts) >= 2:
                    options = parts[1:]
                    resolv_info["Options"].extend(options)
    
        # 检查systemd-resolvd服务是否启动
        resolv_info["Service_Info"] = self.get_service_status("systemd-resolved")

        # 写入info
        self.info["Resolv_Info"] = resolv_info


    # 检查2050的参数, todo
    def check_2050_info(self) -> bool:
        xStream2050_info = {}
        xStream2050_info["is_2050s"] = False,
        xStream2050_info["MediaTransforms"] = []

    def save_to_file(self):
        if(__DEBUG__):
            pass
        else:
            self.generate_filename()
        
        with open(self.output_file, 'w') as f:
            json.dump(self.info, f, indent=4)

    def execute_checks_from_dict(self, check_dict):
        """
        按照传入字典中的 True/False 标记，按顺序执行对应函数
        """
        # 先初始化时间戳
        self.check_timestamp()

        # 按照check_dict顺序执行
        for func_name in check_dict:
            try:
                method_to_call = getattr(self, func_name)
                if callable(method_to_call):
                    print(f"正在执行: {func_name}...")
                    if func_name == "check_processes_status":
                        method_to_call(suma_process_list)
                    elif func_name == "check_sys_log":
                        method_to_call(syslog_check_pattern, syslog_check_record_cnt)
                    else:
                        method_to_call()
                else:
                    print(f"警告: '{func_name}' 不是一个可调用的方法。")
            except AttributeError:
                print(f"警告: 方法 '{func_name}' 不存在。")
        
        # 存入文件
        self.save_to_file()

# ------------------------------

# ------------ 主函数 ------------ 
def main(param_list: list):
    checker = SystemInfoChecker()
    if param_list:
        print(param_list)
    else:
        checker.execute_checks_from_dict(check_list)
# ------------------------------


# ------------ 脚本入口 ------------ 
if __name__ == "__main__":
    param_list = sys.argv[1:]
    main(param_list)
# ------------------------------
