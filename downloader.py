import csv
import os
import requests
from concurrent.futures import ThreadPoolExecutor

# 配置
INPUT_CSV = 'scan_results.csv'
OUTPUT_DIR = 'results/hasha'
UNIQUE_URLS_FILE = 'unique_urls.txt'
TIMEOUT = 8  
THREADS = 10 

def download_node_file(row):
    hash_val = row.get('hash')
    url = row.get('url')
    
    if not hash_val or not url:
        return

    file_path = os.path.join(OUTPUT_DIR, f"{hash_val}.yaml")
    
    # 若檔案已存在則跳過
    if os.path.exists(file_path):
        return
    
    try:
        response = requests.get(url, timeout=TIMEOUT, stream=True)
        if response.status_code == 200:
            with open(file_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)
            print(f"[OK] 下載成功: {hash_val}")
        else:
            print(f"[FAIL] 狀態碼 {response.status_code}: {url}")
    except Exception as e:
        print(f"[ERROR] 下載失敗 {url}: {e}")

def run_downloader():
    if not os.path.exists(OUTPUT_DIR):
        os.makedirs(OUTPUT_DIR)

    if not os.path.exists(INPUT_CSV):
        print(f"[!] 找不到 {INPUT_CSV}")
        return

    # 1. 讀取並去重
    with open(INPUT_CSV, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        tasks = [row for row in reader]

    # 提取不重複 URL 並保存
    unique_urls = sorted(list(set(row['url'] for row in tasks if row.get('url'))))
    with open(UNIQUE_URLS_FILE, 'w', encoding='utf-8') as f:
        f.write('\n'.join(unique_urls))
    print(f"[INFO] 已保存 {len(unique_urls)} 個不重複網址至 {UNIQUE_URLS_FILE}")

    # 2. 執行下載
    with ThreadPoolExecutor(max_workers=THREADS) as executor:
        executor.map(download_node_file, tasks)

if __name__ == "__main__":
    run_downloader()
