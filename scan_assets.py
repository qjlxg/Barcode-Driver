import socket
import ipaddress
from concurrent.futures import ThreadPoolExecutor

def get_config():
    # 读取网段，支持 24 等 CIDR 格式
    with open('targets.txt', 'r') as f:
        networks = [line.strip() for line in f if line.strip()]
    
    # 展开所有网段中的 IP
    all_ips = []
    for net in networks:
        try:
            all_ips.extend([str(ip) for ip in ipaddress.ip_network(net, strict=False)])
        except ValueError:
            continue # 跳过无效格式
            
    # 读取端口
    with open('ports.txt', 'r') as f:
        # 支持逗号分隔或每行一个
        content = f.read().replace(',', '\n')
        ports = [p.strip() for p in content.splitlines() if p.strip()]
        
    return all_ips, ports

def check_port(target):
    ip, port = target
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.3) # 超时稍微调短以加快速度
            if s.connect_ex((ip, int(port))) == 0:
                return f"{ip}:{port}"
    except:
        pass
    return None

def run_scanner():
    ips, ports = get_config()
    # 生成所有 IP-Port 组合
    tasks = [(ip, port) for ip in ips for port in ports]
    
    alive_assets = []
    # 使用多线程，针对网段扫描，建议线程数稍大
    with ThreadPoolExecutor(max_workers=100) as executor:
        results = executor.map(check_port, tasks)
        for res in results:
            if res:
                alive_assets.append(res)
    
    # 写入文件，保持格式
    with open("alive_ips.txt", "w") as f:
        if alive_assets:
            f.write("\n".join(sorted(alive_assets)) + "\n")

if __name__ == "__main__":
    run_scanner()
