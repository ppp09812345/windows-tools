from netmiko import ConnectHandler
from datetime import datetime
import getpass
import sys
import ipaddress
import threading
from queue import Queue
import os
import time

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

def get_ip_addresses():
    """获取用户输入的IP地址或地址段"""
    while True:
        print("\n请选择输入方式：")
        print("1. 单个IP地址")
        print("2. IP地址段（CIDR格式，如192.168.1.0/24）")
        print("3. IP地址范围（如192.168.1.1-192.168.1.10）")
        choice = input("请选择 (1/2/3): ").strip()

        try:
            if choice == '1':
                ip = input("请输入IP地址: ").strip()
                # 验证IP地址格式
                ipaddress.ip_address(ip)
                return [ip]
            
            elif choice == '2':
                cidr = input("请输入CIDR地址段 (例如:192.168.1.0/24): ").strip()
                network = ipaddress.ip_network(cidr, strict=False)
                return [str(ip) for ip in network.hosts()]
            
            elif choice == '3':
                start_ip = input("请输入起始IP: ").strip()
                end_ip = input("请输入结束IP: ").strip()
                
                # 转换IP地址为整数进行比较
                start = int(ipaddress.IPv4Address(start_ip))
                end = int(ipaddress.IPv4Address(end_ip))
                
                if start > end:
                    print("起始IP不能大于结束IP")
                    continue
                    
                return [str(ipaddress.IPv4Address(ip)) 
                        for ip in range(start, end + 1)]
            else:
                print("无效的选择，请重试")
                continue
                
        except ValueError as e:
            print(f"输入格式错误: {e}")
            continue
            
        except Exception as e:
            print(f"发生错误: {e}")
            continue

def get_credentials():
    """获取登录凭证"""
    username = input("\n请输入用户名: ").strip()
    password = getpass.getpass("请输入密码: ")
    return username, password

def main():
    try:
        # 创建备份文件夹
        backup_folder = "backup"
        os.makedirs(backup_folder, exist_ok=True)
        print(f"\n备份文件将保存在: {backup_folder}")

        # 获取IP地址列表
        ip_list = get_ip_addresses()
        if not ip_list:
            print("没有有效的IP地址")
            return

        print(f"\n共发现 {len(ip_list)} 个IP地址")
        
        # 获取登录凭证
        username, password = get_credentials()

        # 询问是否使用多线程
        use_threads = input("\n是否使用多线程备份? (y/n): ").strip().lower() == 'y'
        
        # 开始时间
        start_time = time.time()
        
        results = []
        if use_threads:
            threads = []
            result_queue = Queue()
            
            for host in ip_list:
                thread = threading.Thread(
                    target=backup_huawei_config,
                    args=(host, username, password, result_queue, backup_folder)
                )
                thread.start()
                threads.append(thread)
            
            # 等待所有线程完成
            for thread in threads:
                thread.join()
            
            # 收集结果
            while not result_queue.empty():
                results.append(result_queue.get())
        else:
            # 串行处理
            for host in ip_list:
                result = backup_huawei_config(host, username, password,
                                           backup_folder=backup_folder)
                results.append(result)

        # 计算总耗时
        total_time = time.time() - start_time

        # 生成报告文件
        report_file = os.path.join(backup_folder, "backup_report.txt")
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write("配置备份报告\n")
            f.write("=" * 50 + "\n\n")
            f.write(f"备份时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"总设备数: {len(results)}\n")
            f.write(f"成功数量: {sum(1 for r in results if r['status'] == 'success')}\n")
            f.write(f"失败数量: {sum(1 for r in results if r['status'] == 'failed')}\n")
            f.write(f"总耗时: {total_time:.2f} 秒\n\n")
            
            f.write("备份详情:\n")
            f.write("-" * 50 + "\n")
            for r in results:
                status = "成功" if r['status'] == 'success' else "失败"
                f.write(f"IP地址: {r['host']}\n")
                f.write(f"状态: {status}\n")
                if r['status'] == 'success':
                    f.write(f"文件名: {r['filename']}\n")
                else:
                    f.write(f"错误信息: {r['message']}\n")
                f.write("-" * 50 + "\n")

        # 打印总结
        print("\n" + "="*50)
        print("备份任务完成!")
        print("="*50)
        success_count = sum(1 for r in results if r['status'] == 'success')
        print(f"\n总计: {len(results)} 个设备")
        print(f"成功: {success_count} 个")
        print(f"失败: {len(results) - success_count} 个")
        print(f"总耗时: {total_time:.2f} 秒")
        print(f"\n备份文件保存在: {os.path.abspath(backup_folder)}")
        print(f"详细报告已保存到: {report_file}")

        # 打印失败的设备
        failed = [r for r in results if r['status'] == 'failed']
        if failed:
            print("\n失败的设备:")
            for r in failed:
                print(f"- {r['host']}: {r['message']}")

        input("\n按回车键退出...")

    except KeyboardInterrupt:
        print("\n\n程序被用户中断")
    except Exception as e:
        print(f"\n发生错误: {str(e)}")
        input("\n按回车键退出...")

if __name__ == "__main__":
    # 检查必要模块
    try:
        import netmiko
    except ImportError:
        print("请先安装netmiko模块:")
        print("pip install netmiko")
        input("\n按回车键退出...")
        sys.exit(1)
    
    print("=== 华为交换机配置备份工具 ===")
    main()