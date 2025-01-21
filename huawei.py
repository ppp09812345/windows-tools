import tkinter as tk
from tkinter import messagebox
from tkinter import ttk
from tkinter import font
from tkinter import filedialog
from netmiko import ConnectHandler
from datetime import datetime
import getpass
import os
import time
import threading
from queue import Queue
import ipaddress

def backup_device_config(host, device_type, username, password, result_queue=None, backup_folder='backup'):
    """备份单个设备的配置"""
    device = {
        'device_type': device_type,
        'host': host,
        'username': username,
        'password': password,
        'timeout': 30
    }

    result = {
        'host': host,
        'message': '',
        'filename': '',
        'backupfile': ''
    }

    try:
        # 连接设备
        print(f"\n正在连接设备 {host}...")
        net_connect = ConnectHandler(**device)
        
        # 获取配置
        print(f"正在获取设备 {host} 的配置...")
        output = net_connect.send_command('display current-configuration')
        
        # 生成文件名：年月日-IP地址
        timestamp = datetime.now().strftime('%Y%m%d')
        filename = f"{timestamp}-{host}.cfg"
        
        # 确保备份目录存在
        os.makedirs(backup_folder, exist_ok=True)
        filepath = os.path.join(backup_folder, filename)
        
        # 保存配置
        with open(filepath, 'w', encoding='utf-8') as f:
            # 添加配置信息头
            f.write(f"! IP地址: {host}\n")
            f.write(f"! 备份时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("!"+ "="*50 + "\n\n")
            f.write(output)
        
        print(f"设备 {host} 配置已保存到 {filename}")
        backupfile = "设备" + host + "配置已保存到" + filename

        result.update({
            'message': '备份成功',
            'filename': filename,
            'backupfile': backupfile
        })

        net_connect.disconnect()
        print(f"设备 {host} 连接已断开。")  # 新增日志

    except Exception as e:
        error_msg = f"备份失败， {str(e)}"
        print(f"设备 {host}: {error_msg}")
        result['message'] = error_msg

    if result_queue is not None:
        result_queue.put(result)
    return result

def get_ip_addresses(ip_text):

    ip_list = []
    for line in ip_text.splitlines():
        line = line.strip()
        if line:  # 只处理非空行
            try:
                # 处理单个IP地址
                ip = ipaddress.ip_address(line)
                ip_list.append(str(ip))
            except ValueError:
                try:
                    # 处理CIDR地址段
                    network = ipaddress.ip_network(line, strict=False)
                    ip_list.extend([str(ip) for ip in network.hosts()])
                except ValueError:
                    try:
                        # 处理IP地址范围
                        start_ip, end_ip = line.split('-')
                        start = int(ipaddress.IPv4Address(start_ip.strip()))
                        end = int(ipaddress.IPv4Address(end_ip.strip()))
                        if start > end:
                            raise ValueError("起始IP不能大于结束IP")
                        ip_list.extend([str(ipaddress.IPv4Address(ip)) for ip in range(start, end + 1)])
                    except Exception:
                        messagebox.showerror("错误", f"无效的IP地址或范围: {line}")
    return ip_list

def start_backup(ip_list, device_type, username, password, progress_bar, result_text):
    result_queue = Queue()
    progress_bar.start()  # 开始进度条

    def backup_thread(ip):
        backup_device_config(ip, device_type, username, password, result_queue)

    threads = []
    for ip in ip_list:
        thread = threading.Thread(target=backup_thread, args=(ip,))
        thread.start()
        threads.append(thread)

    # 等待所有线程完成
    for thread in threads:
        thread.join()

    progress_bar.stop()  # 停止进度条
    results = [result_queue.get() for _ in ip_list]
    #summary = "\n".join([f"{r['host']}: {r['status']},{r['backupstatus']}，{r['message']}" for r in results])
    summary = "\n".join([f"{r['host']}: {r['message']} {r['backupfile']}" for r in results])
    
    # 更新结果文本框
    result_text.config(state=tk.NORMAL)  # 允许编辑
    result_text.delete(1.0, tk.END)  # 清空文本框
    result_text.insert(tk.END, f"备份结果:\n{summary}")  # 插入结果
    result_text.config(state=tk.DISABLED)  # 设置为只读

def on_backup(result_text):

    ip_text = ip_text_area.get("1.0", tk.END)  # 获取文本框内容
    device_type = device_type_entry.get()
    if device_type == "华为":
        device_type = "huawei"  # 将“华为”转换为“huawei”
    elif device_type == "新华三":
        device_type = "hp_comware"  # 将“华三”转换为“hp_comware”
    username = username_entry.get()
    password = password_entry.get()
    if not ip_text.strip() or not username or not password:
        messagebox.showerror("错误", "请填写所有字段")
        return

    ip_list = get_ip_addresses(ip_text)
    if not ip_list:
        return

    # 在新线程中启动备份
    threading.Thread(target=start_backup, args=(ip_list, device_type, username, password, progress_bar, result_text)).start()

# 导出日志的函数
def export_log():
    # 打开文件对话框选择保存位置
    file_path = filedialog.asksaveasfilename(defaultextension=".txt", 
                                               filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
    if file_path:
        with open(file_path, 'w') as file:
            # 获取文本框内容并写入文件
            content = result_text.get("1.0", tk.END)  # 获取所有文本
            file.write(content)

# 创建主窗口
root = tk.Tk()
root.title("网络设备配置备份")
# 设置窗口尺寸
root.geometry("600x500")  # 宽度400，高度400
# 固定窗口尺寸
root.resizable(False, False)  # 禁止水平和垂直调整

# 创建标签页
notebook = ttk.Notebook(root)
notebook.pack(fill='both', expand=True)
# 创建样式
style = ttk.Style()
style.configure("TFrame", background="#ebeef0")

# 创建备份页面
backup_frame = ttk.Frame(notebook, style="TFrame") 
notebook.add(backup_frame, text="备份")


# 创建一个框架来放置标签和下拉框
device_type_frame = tk.Frame(backup_frame,bg="#f0f0f0")
device_type_frame.pack(pady=5)

# 选择厂商
tk.Label(device_type_frame, text="设备厂商：",bg="#f0f0f0").pack(side=tk.LEFT, padx=5)

# 创建下拉框
device_type_entry = ttk.Combobox(device_type_frame, values=["华为", "新华三"], state='readonly', width=8)
device_type_entry.pack(side=tk.LEFT,padx=5)  # 下拉框在右侧
device_type_entry.current(0)  # 默认选择第一个选项

# 创建一个框架来放置IP地址输入框
address_frame = tk.Frame(backup_frame, bg="#f0f0f0")  # 设置框架背景颜色
address_frame.pack(pady=5)


# 使用 LabelFrame 来组织格式备注
format_frame = tk.LabelFrame(address_frame, text="IP地址输入格式", font=("Helvetica", 10), fg="black", labelanchor='n')
format_frame.pack(side=tk.LEFT, padx=10, pady=10)

format_label = tk.Label(format_frame, text="单个IP(192.168.1.1)\nIP地址段(192.168.1.0/24)\nIP地址范围 (192.168.1.1-192.168.1.10)\n通过换行分割", font=("Helvetica", 9), fg="gray")
format_label.pack()

ip_text_area = tk.Text(address_frame, height=8, width=35)
ip_text_area.pack(side=tk.RIGHT, pady=5)


# 创建一个框架来放置用户名和密码输入框
credentials_frame = tk.Frame(backup_frame, bg="#f0f0f0")  # 设置框架背景颜色
credentials_frame.pack(pady=30)

# 用户名输入
tk.Label(credentials_frame, text="用户名：", bg="#f0f0f0").pack(side=tk.LEFT, padx=5)  # 标签在左侧
username_entry = tk.Entry(credentials_frame, width=15)  # 用户名输入框
username_entry.pack(side=tk.LEFT, padx=5)  # 输入框在右侧

# 密码输入
tk.Label(credentials_frame, text="密码：", bg="#f0f0f0").pack(side=tk.LEFT, padx=5)  # 标签在左侧
password_entry = tk.Entry(credentials_frame, show='*', width=20)  # 密码输入框
password_entry.pack(side=tk.LEFT, padx=5)  # 输入框在右侧

# 创建备份按钮
backup_button = tk.Button(backup_frame, text="开始备份", command=lambda: on_backup(result_text),bg="#4CAF50", fg="white",font=("bold"))
backup_button.pack(pady=10)

# 创建进度条
progress_bar = ttk.Progressbar(backup_frame, mode='indeterminate')
progress_bar.pack(pady=10)

# 创建备份结果标签
result_frame = ttk.Frame(notebook)
notebook.add(result_frame, text="备份日志")

# 创建一个框架来放置日志文本框
backup_log = tk.Frame(result_frame, bg="#f0f0f0")  # 设置框架背景颜色
backup_log.pack(pady=5)
# 创建文本框用于显示备份结果
result_text = tk.Text(backup_log, wrap=tk.WORD, height=30, width=80, state=tk.DISABLED)  # 初始为只读
result_text.pack(side=tk.LEFT, pady=10, fill=tk.BOTH, expand=True) 

# 创建滑动条
scrollbar = tk.Scrollbar(backup_log, command=result_text.yview)  # 绑定滑动条到文本框
scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

# 将滑动条与文本框关联
result_text.config(yscrollcommand=scrollbar.set)

# 创建导出日志按钮
export_button = tk.Button(result_frame, text="导出日志", command=export_log)
export_button.pack(pady=5)  # 将按钮放在底部


# 创建说明页面
info_frame = ttk.Frame(notebook)
notebook.add(info_frame, text="说明")

# 添加说明文本
info_text = """\
本程序用于备份华为或华三设备的配置文件，默认使用SSH方式，连接端口为22。
请在“备份”标签页中输入设备的IP地址、用户名和密码，然后点击“开始备份”按钮。
应用程序会自动在当前目录下生存一个名为“backup”的文件夹，用于存放备份文件。
备份文件的命名规则为：年月日-IP地址.cfg
                                      
                                      
                                                                 -----Author: TAO-----
"""
# 创建字体对象
custom_font = font.Font(family="Trebuchet MS", size=14)  # 设置字体为 Trebuchet MS，大小为 14

info_label = tk.Label(info_frame, text=info_text, font=custom_font, justify='left', wraplength=600, padx=10, pady=10)
info_label.pack(pady=10)

# 运行主循环
root.mainloop()
