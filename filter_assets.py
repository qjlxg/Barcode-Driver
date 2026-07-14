import csv, os
from urllib.parse import urlparse

# 1. 加载历史资产（兼容新旧 CSV 格式）
existing = set()
if os.path.exists('scan_results.csv'):
    with open('scan_results.csv', 'r', encoding='utf-8') as f:
        reader = csv.reader(f)
        for row in reader:
            if not row: continue
            # 新版格式第3列为 host_port，旧版格式第2列为 url
            if len(row) >= 3 and row[2]:
                existing.add(row[2])
            elif len(row) >= 2:
                try: 
                    netloc = urlparse(row[1]).netloc
                    if netloc: existing.add(netloc)
                except: pass

# 2. 过滤产生新任务文件
if os.path.exists('alive_latest.txt'):
    with open('alive_latest.txt', 'r') as f_in, open('alive_new.txt', 'w') as f_out:
        for line in f_in:
            target = line.strip()
            if target and target not in existing:
                f_out.write(target + '\n')
