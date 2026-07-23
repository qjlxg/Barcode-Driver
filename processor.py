import ipaddress
import hashlib
import json
import datetime
from pathlib import Path
from urllib.parse import urlparse

BATCH_SIZE = 35
PROGRESS_FILE = Path('progress.json')

def get_net_id(net_str):
    return hashlib.md5(net_str.encode()).hexdigest()

def process_ip_file(input_file='ip.txt', output_file='targets.txt', batch_size=BATCH_SIZE):
    input_path = Path(input_file)
    if not input_path.exists():
        print("[!] ip.txt不存在")
        return

    # 1. 读取并规范化 (维护插入顺序)
    seen = set()
    networks = []
    with input_path.open('r', encoding='utf-8') as f:
        for line in f:
            target = line.strip()
            if not target: continue
            try:
                # 逻辑：如果包含协议头，用 urlparse 解析；否则视为原始 IP
                if "://" in target:
                    parsed = urlparse(target)
                    ip_part = parsed.hostname
                else:
                    # 去除端口部分
                    ip_part = target.split(':')[0]
                
                # 检查解析出的 ip_part 是否为空
                if not ip_part: continue
                
                net = ipaddress.ip_network(ip_part if '/' in ip_part else f"{ip_part}/24", strict=False)
                net_str = str(net)
                if net_str not in seen:
                    seen.add(net_str)
                    networks.append(net_str)
            except ValueError: continue
    
    print(f"[*] 解析得到 {len(networks)} 个网段")
    
    all_networks = networks[::-1] # 后加入优先
    if not all_networks:
        print("[!] 没有解析出任何网段")
        Path(output_file).write_text("", encoding="utf-8")
        return

    # 2. 读取状态
    state = {"scanned_ids": [], "last_time": ""}
    if PROGRESS_FILE.exists():
        try: state = json.loads(PROGRESS_FILE.read_text())
        except: pass

    # 3. 从当前列表中去掉已扫过的，剩余即为待扫队列
    scanned_ids = set(state.get("scanned_ids", []))
    pending = [n for n in all_networks if get_net_id(n) not in scanned_ids]

    # 4. 全部扫完则重置，重新开始
    if not pending:
        print("[*] 全部网段已扫完，重置进度...")
        scanned_ids = set()
        pending = all_networks

    # 5. 取本批
    batch = pending[:batch_size]

    # 6. 保存状态
    if batch:
        for n in batch:
            scanned_ids.add(get_net_id(n))
        state["scanned_ids"] = list(scanned_ids)
        state["last_time"] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        PROGRESS_FILE.write_text(json.dumps(state, indent=2))

    print(f"[*] 写入文件: {Path(output_file).resolve()}")
    with open(output_file, 'w', encoding='utf-8') as f:
        f.writelines([f"{n}\n" for n in batch])

    print(f"[*] 处理: {len(batch)} 个网段 | 进度: {len(scanned_ids)}/{len(all_networks)}")

if __name__ == "__main__":
    process_ip_file()
