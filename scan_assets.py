import socket
import ipaddress
import sys
import time
import random
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

# ================== 配置区 ==================
MAX_WORKERS = 50                    # 推荐值，比较安全
DELAY_BETWEEN = 2.8                 # 每个请求间隔（秒），公网建议 0.05~0.15
TIMEOUT = 1.8                       # 连接超时时间
# ===========================================

def get_config():
    # 读取 targets.txt
    if not Path('targets.txt').exists():
        print("[!] 错误：targets.txt 文件不存在！")
        sys.exit(1)
    
    with open('targets.txt', 'r', encoding='utf-8') as f:
        networks = [line.strip() for line in f if line.strip() and not line.startswith('#')]
    
    if not networks:
        print("[!] 错误：targets.txt 为空！")
        sys.exit(1)

    # 读取 ports.txt（严格要求必须存在且有内容）
    if not Path('ports.txt').exists():
        print("[!] 错误：ports.txt 文件不存在！")
        sys.exit(1)
    
    with open('ports.txt', 'r', encoding='utf-8') as f:
        content = f.read().replace(',', '\n')
        ports = [int(p.strip()) for p in content.splitlines() if p.strip() and not p.strip().startswith('#')]
    
    if not ports:
        print("[!] 错误：ports.txt 为空或格式不正确！")
        sys.exit(1)
    
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
            for ip in ipaddress.ip_network(net, strict=False).hosts():
                for port in ports:
                    yield str(ip), port
        except ValueError:
            continue

def check_port(target):
    ip, port = target
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(TIMEOUT)
            if s.connect_ex((ip, port)) == 0:
                return f"{ip}:{port}"
    except:
        pass
    
    # 安全延时
    if DELAY_BETWEEN > 0:
        time.sleep(DELAY_BETWEEN + random.uniform(0, 0.02))
    
    return None

def run_scanner():
    networks, ports = get_config()
    
    total_tasks = count_tasks(networks, ports)
    print(f"[*] 任务准备就绪：共 {total_tasks:,} 个扫描点 | 网络段: {len(networks)} 个 | 端口: {len(ports)} 个 | 线程数: {MAX_WORKERS}")

    alive_count = 0
    processed = 0
    start_time = time.time()

    try:
        with open("alive_ips.txt", "w", encoding='utf-8') as f:
            with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
                futures = (executor.submit(check_port, task) for task in ip_port_generator(networks, ports))
                
                for future in as_completed(futures):
                    processed += 1
                    res = future.result()
                    if res:
                        f.write(res + "\n")
                        f.flush()
                        alive_count += 1
                    
                    if processed % 1000 == 0 or processed == total_tasks:
                        elapsed = time.time() - start_time
                        speed = processed / elapsed if elapsed > 0 else 0
                        print(f"[*] 进度: {processed:,}/{total_tasks:,} | 发现: {alive_count} | 速度: {speed:.1f} ips/s")

    except KeyboardInterrupt:
        print(f"\n[!] 用户终止扫描，已保存当前结果。已处理 {processed:,}/{total_tasks:,}")
        sys.exit(0)
    except Exception as e:
        print(f"[!] 发生错误: {e}")

    elapsed = time.time() - start_time
    print(f"\n[+] 扫描结束！共发现 {alive_count} 个存活端口，用时 {elapsed:.1f} 秒")

if __name__ == "__main__":
    run_scanner()
