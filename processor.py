import ipaddress
import hashlib
import json
import datetime
from pathlib import Path
from urllib.parse import urlparse

BATCH_SIZE = 45
PROGRESS_FILE = Path('progress.json')
COLD_FILE = Path('ip_cold.txt')

def get_net_id(net_str):
    return hashlib.md5(net_str.encode()).hexdigest()

def process_ip_file(input_file='ip.txt', output_file='targets.txt', batch_size=BATCH_SIZE):
    input_path = Path(input_file)
    if not input_path.exists():
        print("[!] ip.txt不存在")
        return

    # 0. 读取冷库 (ip_cold.txt) 中的网段用于物理删除
    cold_networks = set()
    if COLD_FILE.exists():
        with COLD_FILE.open('r', encoding='utf-8') as cf:
            for line in cf:
                c_target = line.strip()
                if not c_target: continue
                try:
                    c_ip = c_target.split(':')[0]
                    c_net = ipaddress.ip_network(c_ip if '/' in c_ip else f"{c_ip}/24", strict=False)
                    cold_networks.add(str(c_net))
                except ValueError: continue

    # 1. 读取并规范化 (维护插入顺序)
    seen = set()
    networks = []
    cleaned_lines = []
    removed_count = 0

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
                if not ip_part:
                    cleaned_lines.append(line)
                    continue

                net = ipaddress.ip_network(ip_part if '/' in ip_part else f"{ip_part}/24", strict=False)
                net_str = str(net)

                # 如果命中冷库，则永久从总表中剔除
                if net_str in cold_networks:
                    removed_count += 1
                    continue

                if net_str not in seen:
                    seen.add(net_str)
                    networks.append(net_str)

                cleaned_lines.append(line)
            except ValueError:
                cleaned_lines.append(line)
                continue

    if removed_count > 0:
        with input_path.open('w', encoding='utf-8') as f:
            f.writelines(cleaned_lines)
        print(f"[*] 已从总表 ip.txt 中永久剔除冷库网段: {removed_count} 个")

    print(f"[*] 解析得到 {len(networks)} 个网段")

    all_networks = networks[::-1] # 后加入优先
    if not all_networks:
        print("[!] 没有解析出任何网段")
        Path(output_file).write_text("", encoding="utf-8")
        return

    # 2. 读取进度
    index = 0
    if PROGRESS_FILE.exists():
        try:
            state = json.loads(PROGRESS_FILE.read_text())
            index = state.get("index", 0)
        except Exception:
            index = 0

    # 3. 如果已经到底，重新开始
    if index >= len(all_networks):
        print("[*] 全部扫描完成，重新轮询")
        index = 0

    print(f"[*] 当前进度:\n{index}/{len(all_networks)}")

    # 4. 获取本批
    batch = all_networks[index:index + batch_size]

    # 5. 更新游标并保存状态
    new_index = index + len(batch)
    state = {
        "index": new_index,
        "total": len(all_networks),
        "last_time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    PROGRESS_FILE.write_text(json.dumps(state, indent=2))

    print(f"[*] 写入文件: {Path(output_file).resolve()}")
    with open(output_file, 'w', encoding='utf-8') as f:
        f.writelines([f"{n}\n" for n in batch])

    print(f"[*] 处理: {len(batch)} 个网段 | 新进度: {new_index}/{len(all_networks)}")

if __name__ == "__main__":
    process_ip_file()
