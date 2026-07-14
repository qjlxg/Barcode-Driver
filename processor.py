import ipaddress
from pathlib import Path

def process_ip_file(input_file='ip.txt', output_file='targets.txt', batch_size=5):
    input_path = Path(input_file)
    progress_file = Path('progress.txt')
    
    if not input_path.exists():
        print(f"[!] 错误：找不到源文件 {input_file}")
        return

    # 1. 读取并规范化所有网段
    networks = set()
    with input_path.open('r', encoding='utf-8') as f:
        for line in f:
            target = line.strip()
            if not target: continue
            try:
                # 如果输入已经是 CIDR 格式，直接处理；否则添加 /24
                if '/' in target:
                    net = ipaddress.ip_network(target, strict=False)
                else:
                    net = ipaddress.ip_network(f"{target}/24", strict=False)
                networks.add(str(net))
            except ValueError:
                continue
    
    all_networks = sorted(list(networks))
    total = len(all_networks)
    
    # 2. 读取游标 (上次扫到哪了)
    try:
        cursor = int(progress_file.read_text().strip())
    except (FileNotFoundError, ValueError):
        cursor = 0
    
    # 3. 截取本次任务批次
    # 如果游标超过总数，重置为 0
    if cursor >= total:
        cursor = 0
        
    end_index = min(cursor + batch_size, total)
    batch = all_networks[cursor:end_index]
    
    # 4. 更新游标并写入 targets.txt
    next_cursor = end_index if end_index < total else 0
    progress_file.write_text(str(next_cursor))
    
    with open(output_file, 'w', encoding='utf-8') as f:
        for n in batch:
            f.write(f"{n}\n")

    print(f"[*] 执行成功！本次处理: {len(batch)} 个网段")
    print(f"[*] 进度状态: {end_index}/{total} (下次从第 {next_cursor} 个开始)")

if __name__ == "__main__":
    # batch_size=5 表示每次处理 5 个网段，压力平衡
    process_ip_file(batch_size=5)
