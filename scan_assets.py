import socket
import itertools
from concurrent.futures import ThreadPoolExecutor

def get_config():
    # 读取根目录配置
    with open('targets.txt', 'r') as f:
        ips = [line.strip() for line in f if line.strip()]
    with open('ports.txt', 'r') as f:
        # 支持一行一个或逗号分隔
        ports = [p.strip() for line in f for p in line.split(',') if p.strip()]
    return ips, ports

def check_port(ip_port):
    ip, port = ip_port
    try:
        # 设置极短超时，减少误报并提高速度
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.5)
            if s.connect_ex((ip, int(port))) == 0:
                return f"{ip}:{port}"
    except:
        pass
    return None

def run_scanner():
    ips, ports = get_config()
    targets = list(itertools.product(ips, ports))
    
    alive_assets = []
    # 使用多线程，线程数可根据网络环境调整
    with ThreadPoolExecutor(max_workers=50) as executor:
        results = executor.map(check_port, targets)
        for res in results:
            if res:
                alive_assets.append(res)
    
    # 写入结果
    with open("alive_ips.txt", "w") as f:
        f.write("\n".join(sorted(alive_assets)) + "\n")

if __name__ == "__main__":
    run_scanner()
