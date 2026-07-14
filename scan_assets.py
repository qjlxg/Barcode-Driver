import socket
import ipaddress
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

def get_config():
    with open('targets.txt', 'r') as f:
        networks = [line.strip() for line in f if line.strip()]
    with open('ports.txt', 'r') as f:
        content = f.read().replace(',', '\n')
        ports = [int(p.strip()) for p in content.splitlines() if p.strip()]
    return networks, ports

def count_tasks(networks, ports):
    total = 0
    for net in networks:
        try:
            total += ipaddress.ip_network(net, strict=False).num_addresses * len(ports)
        except:
            pass
    return total

def ip_port_generator(networks, ports):
    for net in networks:
        try:
            for ip in ipaddress.ip_network(net, strict=False):
                for port in ports:
                    yield str(ip), port
        except ValueError:
            continue

def check_port(target):
    ip, port = target
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1.0)
            if s.connect_ex((ip, port)) == 0:
                return f"{ip}:{port}"
    except:
        pass
    return None

def run_scanner():
    networks, ports = get_config()
    total_tasks = count_tasks(networks, ports)
    print(f"[*] 任务准备就绪：共 {total_tasks} 个扫描点")
    
    # 动态调整线程数
    max_workers = 50
    
    # 边扫边写，避免列表堆积
    alive_count = 0
    processed = 0
    
    try:
        with open("alive_ips.txt", "w") as f:
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                # 使用生成器提交任务，避免大列表
                futures = (executor.submit(check_port, task) for task in ip_port_generator(networks, ports))
                
                for future in as_completed(futures):
                    processed += 1
                    res = future.result()
                    if res:
                        f.write(res + "\n")
                        alive_count += 1
                    
                    if processed % 1000 == 0 or processed == total_tasks:
                        print(f"[*] 进度: {processed}/{total_tasks} | 已发现: {alive_count}")
    
    except KeyboardInterrupt:
        print("\n[!] 用户强制终止，已保存当前结果。")
        sys.exit(0)
    
    print(f"[+] 扫描结束。本次共发现 {alive_count} 个存活资产。")

if __name__ == "__main__":
    run_scanner()
