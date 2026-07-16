import csv
import os
import requests
import shutil
from concurrent.futures import ThreadPoolExecutor

# 配置
INPUT_CSV = 'scan_results.csv'
OUTPUT_DIR = 'results/hash'
TIMEOUT = 8  # 网络请求超时
THREADS = 10  # 并发数

def download_node_file(row):
    """下载单个链接并保存"""
    hash_val = row.get('hash')
    url = row.get('url')
    
    if not hash_val or not url:
        return

    file_path = os.path.join(OUTPUT_DIR, f"{hash_val}.yaml")
    
    try:
        response = requests.get(url, timeout=TIMEOUT, stream=True)
        if response.status_code == 200:
            with open(file_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)
            print(f"[OK] 下载成功: {hash_val}")
        else:
            print(f"[FAIL] 状态码 {response.status_code}: {url}")
            if os.path.exists(file_path): os.remove(file_path)
            
    except Exception as e:
        print(f"[ERROR] 下载失败 {url}: {e}")
        if os.path.exists(file_path): os.remove(file_path)

def run_downloader():
    # 确保目录存在
    if not os.path.exists(OUTPUT_DIR):
        os.makedirs(OUTPUT_DIR)

    # 读取 CSV
    if not os.path.exists(INPUT_CSV):
        print(f"[!] 找不到 {INPUT_CSV}")
        return

    tasks = []
    with open(INPUT_CSV, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        tasks = [row for row in reader]

    # 并发下载
    print(f"开始下载 {len(tasks)} 个节点源...")
    with ThreadPoolExecutor(max_workers=THREADS) as executor:
        executor.map(download_node_file, tasks)

    print("下载流程完成。")

if __name__ == "__main__":
    run_downloader()