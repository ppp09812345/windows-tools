import threading
import subprocess
import platform
import time
import ipaddress
import sys
import socket
from queue import Queue

def get_ip_list(ip_input):
    """
    解析输入的IP地址或地址段
    支持格式：
    - 单个IP：192.168.1.1
    - IP段：192.168.1.0/24
    - IP范围：192.168.1.1-192.168.1.100
    """
    try:
        if '-' in ip_input:
            # 处理IP范围
            start_ip, end_ip = ip_input.split('-')
            start_ip = ipaddress.IPv4Address(start_ip.strip())
            end_ip = ipaddress.IPv4Address(end_ip.strip())
            return [str(ipaddress.IPv4Address(ip)) 
                   for ip in range(int(start_ip), int(end_ip) + 1)
                   if not str(ipaddress.IPv4Address(ip)).endswith('.0')]
        elif '/' in ip_input:
            # 处理CIDR格式
            return [str(ip) for ip in ipaddress.IPv4Network(ip_input, strict=False)
                   if not str(ip).endswith('.0')]
        else:
            # 处理单个IP
            if ip_input.endswith('.0'):
                print("错误：不支持以.0结尾的IP地址")
                sys.exit(1)
            ipaddress.IPv4Address(ip_input)  # 验证IP格式
            return [ip_input]
    except Exception as e:
        print(f"IP格式错误: {e}")
        sys.exit(1)

def ping(ip, results):
    """
    对单个IP执行ping操作
    Windows系统专用
    """
    try:
        output = subprocess.check_output(
            f'ping -n 1 -w 1000 {ip}', 
            stderr=subprocess.STDOUT,
            shell=True
        ).decode('gbk', errors='ignore')
        
        if "来自" in output or "from" in output:
            if "时间=" in output:
                delay = output.split("时间=")[-1].split("ms")[0].strip()
            elif "time=" in output:
                delay = output.split("time=")[-1].split("ms")[0].strip()
            else:
                delay = "0"
            results[ip] = f"在线 [{delay}ms]"
        else:
            results[ip] = "离线"
    except subprocess.CalledProcessError:
        results[ip] = "离线"
    except Exception as e:
        results[ip] = "离线"

def multi_ping(ip_list, max_threads=100):
    """
    多线程执行ping操作
    """
    threads = []
    results = {}
    
    total = len(ip_list)
    completed = 0
    
    for ip in ip_list:
        while threading.active_count() > max_threads:
            time.sleep(0.1)
        thread = threading.Thread(target=ping, args=(ip, results))
        thread.start()
        threads.append(thread)
        
        completed += 1
        progress = (completed / total) * 100
        print(f"\r进度: {progress:.1f}% ({completed}/{total})", end='')
    
    print("\n等待所有ping操作完成...")
    for thread in threads:
        thread.join()
    
    return results

def check_tcp_port(ip, port, timeout=0.5):
    """
    检查TCP端口是否开放
    缩短超时时间到0.5秒
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0
    except:
        return False

    """
    检查TCP端口是否开放
    缩短超时时间到0.5秒
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0
    except:
        return False
    """
    检查TCP端口是否开放
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0
    except:
        return False

def check_udp_port(ip, port, timeout=1):
    """
    检查UDP端口是否开放（注意：UDP检测可能不太准确）
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(b'', (ip, port))
        try:
            sock.recvfrom(1024)
            return True
        except socket.timeout:
            return False
    except:
        return False
    finally:
        sock.close()

def port_scan(ip, port_list, protocol='tcp', results=None):
    """
    扫描指定IP的多个端口
    """
    port_status = {}
    for port in port_list:
        if protocol.lower() == 'tcp':
            is_open = check_tcp_port(ip, port)
        else:  # UDP
            is_open = check_udp_port(ip, port)
        port_status[port] = "open" if is_open else "closed"
    
    if results is not None:
        results[ip] = port_status
        
def multi_port_scan(ip_list, port_list, protocol='tcp', max_threads=200):
    """
    多线程端口扫描
    增加默认线程数到200
    """
    threads = []
    results = {}
    
    total_tasks = len(ip_list)
    completed = 0
    
    for ip in ip_list:
        while threading.active_count() > max_threads:
            time.sleep(0.01)  # 减少等待时间
        thread = threading.Thread(target=port_scan, args=(ip, port_list, protocol, results))
        thread.start()
        threads.append(thread)
        
        completed += 1
        progress = (completed / total_tasks) * 100
        print(f"\r进度: {progress:.1f}% ({completed}/{total_tasks})", end='')
    
    print("\n等待所有端口扫描完成...")
    for thread in threads:
        thread.join()
    
    return results
    """
    多线程端口扫描
    增加默认线程数到200
    """
    threads = []
    results = {}
    
    total_tasks = len(ip_list)
    completed = 0
    
    for ip in ip_list:
        while threading.active_count() > max_threads:
            time.sleep(0.01)  # 减少等待时间
        thread = threading.Thread(target=port_scan, args=(ip, port_list, protocol, results))
        thread.start()
        threads.append(thread)
        
        completed += 1
        progress = (completed / total_tasks) * 100
        print(f"\r进度: {progress:.1f}% ({completed}/{total_tasks})", end='')
    
    print("\n等待所有端口扫描完成...")
    for thread in threads:
        thread.join()
    
    return results
    """
    多线程端口扫描
    增加默认线程数到200
    """
    threads = []
    results = {}
    
    # 计算总任务数
    total_tasks = len(ip_list)
    completed = 0
    
    # 创建线程池
    for ip in ip_list:
        while threading.active_count() > max_threads:
            time.sleep(0.01)  # 减少等待时间
        thread = threading.Thread(target=port_scan, args=(ip, port_list, protocol, results))
        thread.start()
        threads.append(thread)
        
        # 更新进度
        completed += 1
        progress = (completed / total_tasks) * 100
        print(f"\r进度: {progress:.1f}% ({completed}/{total_tasks})", end='')
    
    print("\n等待所有端口扫描完成...")
    for thread in threads:
        thread.join()
    
    return results
    """
    多线程端口扫描
    """
    threads = []
    results = {}
    
    total = len(ip_list)
    completed = 0
    
    for ip in ip_list:
        while threading.active_count() > max_threads:
            time.sleep(0.1)
        thread = threading.Thread(target=port_scan, args=(ip, port_list, protocol, results))
        thread.start()
        threads.append(thread)
        
        completed += 1
        progress = (completed / total) * 100
        print(f"\r进度: {progress:.1f}% ({completed}/{total})", end='')
    
    print("\n等待所有端口扫描完成...")
    for thread in threads:
        thread.join()
    
    return results

def parse_ports(port_input):
    """
    解析端口输入
    支持格式：
    - 单个端口：80
    - 端口范围：80-90
    - 端口列表：80,443,3306
    """
    ports = []
    try:
        for part in port_input.split(','):
            if '-' in part:
                start, end = map(int, part.split('-'))
                ports.extend(range(start, end + 1))
            else:
                ports.append(int(part))
        return sorted(list(set(ports)))  # 去重并排序
    except:
        print("端口格式错误！")
        sys.exit(1)

    """
    解析端口输入
    支持格式：
    - 单个端口：80
    - 端口范围：80-90
    - 端口列表：80,443,3306
    """
    ports = []
    try:
        for part in port_input.split(','):
            if '-' in part:
                start, end = map(int, part.split('-'))
                # 直接添加所有端口
                ports.extend(range(start, end + 1))
            else:
                ports.append(int(part))
        return sorted(list(set(ports)))  # 去重并排序
    except:
        print("端口格式错误！")
        sys.exit(1)
    """
    解析端口输入
    支持格式：
    - 单个端口：80
    - 端口范围：80-90
    - 端口列表：80,443,3306
    """
    ports = []
    try:
        for part in port_input.split(','):
            if '-' in part:
                start, end = map(int, part.split('-'))
                ports.extend(range(start, end + 1))
            else:
                ports.append(int(part))
        return sorted(list(set(ports)))
    except:
        print("端口格式错误！")
        sys.exit(1)

def ip_to_int(ip):
    """
    将IP地址转换为整数，用于排序
    """
    return int(ipaddress.IPv4Address(ip))

def main():
    print("请选择操作模式：")
    print("1. Ping测试")
    print("2. 端口扫描")
    mode = input("请输入选择（1或2）: ").strip()

    print("\n请输入IP地址或IP地址段，支持以下格式：")
    print("1. 单个IP：192.168.1.1")
    print("2. IP段：192.168.1.0/24")
    print("3. IP范围：192.168.1.1-192.168.1.100")
    
    ip_input = input("\n请输入: ").strip()
    ip_list = get_ip_list(ip_input)

    if mode == "1":
        # Ping测试模式
        print(f"\n共计 {len(ip_list)} 个IP地址待检测")
        print("\n开始ping测试...")
        start_time = time.time()
        results = multi_ping(ip_list)
        
        # 统计结果
        online = sum(1 for status in results.values() if "在线" in status)
        offline = sum(1 for status in results.values() if status == "离线")
        
        print("\n\n检测结果:")
        print(f"在线: {online} 个")
        print(f"离线: {offline} 个")
        print(f"总耗时: {time.time() - start_time:.2f}秒")
        
        show_detail = input("\n是否显示详细结果？(y/n): ").lower().strip()
        if show_detail == 'y':
            print("\n详细结果:")
            
            # 按IP数值大小排序
            sorted_results = sorted(results.items(), key=lambda x: ip_to_int(x[0]))
            
            # 先显示在线的IP
            print("\n在线的IP:")
            for ip, status in sorted_results:
                if "在线" in status:
                    print(f"IP: {ip:<15} - {status}")
            
            # 再显示离线的IP
            print("\n离线的IP:")
            for ip, status in sorted_results:
                if status == "离线":
                    print(f"IP: {ip:<15} - {status}")

    elif mode == "2":
        # 端口扫描模式
        print("\n请输入要扫描的端口，支持以下格式：")
        print("1. 单个端口：80")
        print("2. 端口范围：80-90")
        print("3. 端口列表：80,443,3306")
        port_input = input("\n请输入端口: ").strip()
        
        print("\n请选择扫描协议：")
        print("1. TCP")
        print("2. UDP")
        protocol = input("请输入选择（1或2）: ").strip()
        protocol = "tcp" if protocol == "1" else "udp"

        # 添加线程数选择
        print("\n请输入最大线程数（建议：100-500，默认200）：")
        try:
            max_threads = int(input("请输入（直接回车使用默认值）: ").strip() or "200")
        except:
            max_threads = 200

        ports = parse_ports(port_input)
        print(f"\n共计 {len(ip_list)} 个IP地址，{len(ports)} 个端口待扫描")
        
        start_time = time.time()
        results = multi_port_scan(ip_list, ports, protocol, max_threads)
        
        print("\n\n扫描结果:")
        
        for ip in sorted(results.keys(), key=ip_to_int):
            port_status = results[ip]
            print(f"\nIP: {ip}")
            
            # 显示端口状态
            open_ports = [port for port, status in port_status.items() if status == "open"]
            if len(ports) <= 10:  # 当端口数量小于等于10个时，显示所有端口状态
                # 显示开放的端口
                if open_ports:
                    print(f"开放的{protocol.upper()}端口: {', '.join(map(str, open_ports))} (状态: open)")
                
                # 显示关闭的端口
                closed_ports = [port for port, status in port_status.items() if status == "closed"]
                if closed_ports:
                    print(f"关闭的{protocol.upper()}端口: {', '.join(map(str, closed_ports))} (状态: closed)")
            else:  # 当端口数量大于10个时，只显示开放的端口
                if open_ports:
                    print(f"开放的{protocol.upper()}端口: {', '.join(map(str, open_ports))} (状态: open)")
                else:
                    print(f"未发现开放的{protocol.upper()}端口")

        print(f"\n总耗时: {time.time() - start_time:.2f}秒")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n程序被用户中断")
        sys.exit(0)