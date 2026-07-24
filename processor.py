import ipaddress
import json
import datetime
from pathlib import Path
from urllib.parse import urlparse

BATCH_SIZE = 30
PROGRESS_FILE = Path('progress.json')
COLD_FILE = Path('ip_cold.txt')

def process_ip_file(input_file='ip.txt', output_file='targets.txt', batch_size=BATCH_SIZE):
    input_path = Path(input_file)
    if not input_path.exists():
        print("[!] ip.txt不存在")
        return

    # 0. 读取冷库（仅过滤，不删除）
    cold_networks = set()
    if COLD_FILE.exists():
        with COLD_FILE.open('r', encoding='utf-8') as cf:
            for line in cf:
                c_target = line.strip()
                if not c_target: continue
                try:
                    c_ip = c_target.split(':')[0].split('/')[0]
                    c_net = ipaddress.ip_network(c_ip + "/24", strict=False)
                    cold_networks.add(str(c_net))
                except ValueError: 
                    continue

    # 1. 读取并规范化（维护相对顺序）
    seen = set()
    networks = []          # 当前所有有效网段（/24）
    skipped_cold_count = 0

    with input_path.open('r', encoding='utf-8') as f:
        for line in f:
            target = line.strip()
            if not target: continue
            try:
                if "://" in target:
                    parsed = urlparse(target)
                    ip_part = parsed.hostname
                else:
                    ip_part = target.split(':')[0]

                if not ip_part:
                    continue

                net = ipaddress.ip_network(
                    ip_part.split('/')[0] + "/24", strict=False
                )
                net_str = str(net)

                if net_str in cold_networks:
                    skipped_cold_count += 1
                    continue

                if net_str not in seen:
                    seen.add(net_str)
                    networks.append(net_str)

            except ValueError:
                continue

    if skipped_cold_count:
        print(f"[*] 已过滤冷库网段: {skipped_cold_count} 个")

    print(f"[*] 解析得到 {len(networks)} 个有效网段")

    if not networks:
        print("[!] 没有有效网段")
        Path(output_file).write_text("", encoding="utf-8")
        return

    all_networks = networks[::-1]   # 保持“后加入优先”

    # ==================== 新的进度逻辑 ====================
    last_scanned = None
    index = 0

    if PROGRESS_FILE.exists():
        try:
            state = json.loads(PROGRESS_FILE.read_text())
            last_scanned = state.get("last_scanned")
            
            if last_scanned:
                # 尝试找到上次扫描的网段位置
                try:
                    idx = all_networks.index(last_scanned)
                    index = idx + 1  # 从下一个开始
                    print(f"[*] 继续上次断点: {last_scanned} 之后")
                except ValueError:
                    # 上次网段已被删除（进冷库），从头开始或合理位置
                    print(f"[*] 上次网段 {last_scanned} 已不在列表中（可能已进入冷库），从头开始")
                    index = 0
        except Exception:
            print("[!] 进度文件读取失败，从头开始")

    # 如果已经到末尾，重新开始新一轮
    if index >= len(all_networks):
        print("[*] 已完成一轮扫描，重新开始新一轮")
        index = 0

    print(f"[*] 当前进度: {index}/{len(all_networks)}")

    # 获取本批
    batch = all_networks[index : index + batch_size]

    # 更新进度（记录本批最后一个网段）
    if batch:
        new_last_scanned = batch[-1]
    else:
        new_last_scanned = last_scanned

    state = {
        "last_scanned": new_last_scanned,
        "total": len(all_networks),      # 仅用于参考
        "last_time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    PROGRESS_FILE.write_text(json.dumps(state, indent=2, ensure_ascii=False))

    # 写入 targets.txt
    print(f"[*] 写入文件: {Path(output_file).resolve()}")
    with open(output_file, 'w', encoding='utf-8') as f:
        f.writelines([f"{n}\n" for n in batch])

    print(f"[*] 本批处理 {len(batch)} 个网段 | 下一断点: {new_last_scanned}")
    print(f"[*] 新进度: {index + len(batch)}/{len(all_networks)}")

if __name__ == "__main__":
    process_ip_file()