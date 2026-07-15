import ipaddress
import hashlib
import json
import datetime
from pathlib import Path
from urllib.parse import urlparse

BATCH_SIZE = 1
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

    # 2. 计算当前任务队列的哈希 (用于感知内容变化)
    current_list_hash = hashlib.md5("".join(all_networks).encode()).hexdigest()

    # 3. 读取状态
    state = {"list_hash": "", "last_network_id": "", "last_time": ""}
    if PROGRESS_FILE.exists():
        try: state = json.loads(PROGRESS_FILE.read_text())
        except: pass

    # 4. 逻辑判断：如果哈希变了，视为队列更新，重置进度
    if state.get("list_hash", "") != current_list_hash:
        print("[*] 检测到任务列表更新，重置进度...")
        state = {"list_hash": current_list_hash, "last_network_id": "", "last_time": ""}

    # 5. 查找进度
    current_hash_list = [get_net_id(n) for n in all_networks]
    start_index = 0
    if state.get("last_network_id"):
        for i, nid in enumerate(current_hash_list):
            if nid == state.get("last_network_id"):
                start_index = i + 1
                break
    
    if start_index >= len(all_networks): start_index = 0
    end_index = min(start_index + batch_size, len(all_networks))
    batch = all_networks[start_index:end_index]
    
    # 6. 保存状态
    if batch:
        state["last_network_id"] = current_hash_list[end_index - 1]
        state["last_time"] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        PROGRESS_FILE.write_text(json.dumps(state, indent=2))

    print(f"[*] 写入文件: {Path(output_file).resolve()}")
    with open(output_file, 'w', encoding='utf-8') as f:
        f.writelines([f"{n}\n" for n in batch])

    print(f"[*] 处理: {len(batch)} 个网段 | 进度: {end_index}/{len(all_networks)}")

if __name__ == "__main__":
    process_ip_file()
