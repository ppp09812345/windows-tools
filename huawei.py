import tkinter as tk
from tkinter import messagebox
from tkinter import ttk
from tkinter import font
from netmiko import ConnectHandler
from datetime import datetime
import getpass
import os
import time
import threading
from queue import Queue
import ipaddress

def backup_huawei_config(host, username, password, result_queue=None, backup_folder='backup'):
    """备份单个设备的配置"""
    device = {
        'device_type': 'huawei',
        'host': host,
        'username': username,
        'password': password,
        'timeout': 20,
    }

    result = {
        'host': host,
        'status': 'failed',
        'message': '',
        'filename': ''
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
        
        result.update({
            'status': 'success',
            'message': '备份成功',
            'filename': filename
        })
        
        net_connect.disconnect()
        
    except Exception as e:
        error_msg = f"备份失败: {str(e)}"
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


    result_queue = Queue()
    progress_bar.start()  # 开始进度条

    def backup_thread(ip):
        backup_huawei_config(ip, username, password, result_queue)

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
    summary = "\n".join([f"{r['host']}: {r['status']}" for r in results])
    
    # 更新结果标签
    result_label.config(text=f"备份结果:\n{summary}")


    ip_text = ip_text_area.get("1.0", tk.END)  # 获取文本框内容
    username = username_entry.get()
    password = password_entry.get()
    if not ip_text.strip() or not username or not password:
        messagebox.showerror("错误", "请填写所有字段")
        return

    ip_list = get_ip_addresses(ip_text)
    if not ip_list:
        return

    # 在新线程中启动备份
    threading.Thread(target=start_backup, args=(ip_list, username, password, progress_bar, result_label)).start()
    result_queue = Queue()
    progress_bar.start()  # 开始进度条

    def backup_thread(ip):
        backup_huawei_config(ip, username, password, result_queue)

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
    summary = "\n".join([f"{r['host']}: {r['status']}" for r in results])
    
    # 更新结果标签
    result_label.config(text=f"备份结果:\n{summary}")


    ip_text = ip_text_area.get("1.0", tk.END)  # 获取文本框内容
    username = username_entry.get()
    password = password_entry.get()
    if not ip_text.strip() or not username or not password:
        messagebox.showerror("错误", "请填写所有字段")
        return

    ip_list = get_ip_addresses(ip_text)
    if not ip_list:
        return

    # 在新线程中启动备份
    threading.Thread(target=start_backup, args=(ip_list, username, password, progress_bar, result_label)).start()

def start_backup(ip_list, username, password, progress_bar, result_text):
    result_queue = Queue()
    progress_bar.start()  # 开始进度条

    def backup_thread(ip):
        backup_huawei_config(ip, username, password, result_queue)

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
    summary = "\n".join([f"{r['host']}: {r['status']}" for r in results])
    
    # 更新结果文本框
    result_text.config(state=tk.NORMAL)  # 允许编辑
    result_text.delete(1.0, tk.END)  # 清空文本框
    result_text.insert(tk.END, f"备份结果:\n{summary}")  # 插入结果
    result_text.config(state=tk.DISABLED)  # 设置为只读

def on_backup(result_text):

    ip_text = ip_text_area.get("1.0", tk.END)  # 获取文本框内容
    username = username_entry.get()
    password = password_entry.get()
    if not ip_text.strip() or not username or not password:
        messagebox.showerror("错误", "请填写所有字段")
        return

    ip_list = get_ip_addresses(ip_text)
    if not ip_list:
        return

    # 在新线程中启动备份
    threading.Thread(target=start_backup, args=(ip_list, username, password, progress_bar, result_text)).start()

# 创建主窗口
root = tk.Tk()
root.title("华为设备配置备份")

# 设置窗口尺寸
root.geometry("600x450")  # 宽度400，高度400

# 固定窗口尺寸
root.resizable(False, False)  # 禁止水平和垂直调整
# 创建标签页
notebook = ttk.Notebook(root)
notebook.pack(fill='both', expand=True)

# 创建备份页面
backup_frame = ttk.Frame(notebook)
notebook.add(backup_frame, text="备份")

# 创建输入框
tk.Label(backup_frame, text="IP地址（单个、地址段或范围）:").pack(pady=5)
# 添加输入格式备注
format_label = tk.Label(backup_frame, text="格式: 单个IP(192.168.1.1)\nIP地址段(192.168.1.0/24)\nIP地址范围 (192.168.1.1-192.168.1.10)\n 换行分割", font=("Helvetica", 9), fg="gray")
format_label.pack(pady=5)

ip_text_area = tk.Text(backup_frame, height=5, width=35)
ip_text_area.pack(pady=5)

tk.Label(backup_frame, text="用户名:").pack(pady=5)
username_entry = tk.Entry(backup_frame)
username_entry.pack(pady=5)

tk.Label(backup_frame, text="密码:").pack(pady=5)
password_entry = tk.Entry(backup_frame, show='*')
password_entry.pack(pady=5)

# 创建备份按钮
backup_button = tk.Button(backup_frame, text="开始备份", command=lambda: on_backup(result_text))
backup_button.pack(pady=10)

# 创建进度条
progress_bar = ttk.Progressbar(backup_frame, mode='indeterminate')
progress_bar.pack(pady=10)

# 创建备份结果标签
result_frame = ttk.Frame(notebook)
notebook.add(result_frame, text="备份结果")

# 创建文本框用于显示备份结果
result_text = tk.Text(result_frame, height=10, width=40, state=tk.DISABLED)  # 初始为只读
result_text.pack(pady=10)

# 创建说明页面
info_frame = ttk.Frame(notebook)
notebook.add(info_frame, text="说明")

# 添加说明文本
info_text = """\
本程序用于备份华为设备的配置文件。
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
