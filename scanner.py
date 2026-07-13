import aiohttp
import asyncio
import hashlib
import os
import csv
import argparse
import base64
import random
import signal
from tqdm import tqdm
from typing import Dict

# --- 配置 ---
TARGET_PORTS = [80, 443, 1333, 1999, 2052, 2053, 2082, 2083, 2087, 2095, 2096,
                2222, 3002, 3333, 4444, 5555, 6001, 6666, 7777, 8011, 8080, 8081,
                8083, 8443, 8444, 8787, 8888, 8899, 9050, 9981, 9999, 10110, 12202,
                18080, 19999, 54321, 60001, 60002]

PATHS = ["", "/", "/sub", "/subscribe", "/link", "/s/", "/api/sub", "/api/v1/client/subscribe",
         "/api/user/subscribe", "/client/subscribe", "/config.yaml", "/sub.yaml"]

SIGNS = ["proxies:", "proxy-groups:", "vless://", "vmess://", "trojan://", "uuid:",
         "hysteria://", "hysteria2://", "hy2://", "tuic://", "anytls://"]

UA_LIST = ["ClashMeta/1.18", "sing-box/1.8", "ClashforAndroid/2.5", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"]

OUTPUT_DIR = "results"
MAX_SAVE_FILES = 2000
WORKER_COUNT = 28
REQUEST_TIMEOUT = 5

stats = {"req": 0, "saved": 0, "fail": 0}
# 存储 URL -> Hash 的映射，用于对比内容变更
url_history_map: Dict[str, str] = {}

def load_history():
    """加载历史记录，建立 URL 到 Hash 的映射"""
    if os.path.exists('scan_results.csv'):
        try:
            with open('scan_results.csv', 'r', encoding='utf-8') as f:
                reader = csv.reader(f)
                next(reader, None)  # 跳过表头
                for row in reader:
                    if len(row) >= 2:
                        url_history_map[row[1]] = row[0]
        except: pass

async def writer_worker(write_queue: asyncio.Queue):
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    csv_path = 'scan_results.csv'
    # 以追加模式打开，如果文件不存在则创建
    file_exists = os.path.exists(csv_path)
    with open(csv_path, 'a', newline='', encoding='utf-8') as csvfile:
        writer = csv.writer(csvfile)
        if not file_exists:
            writer.writerow(['hash', 'url', 'type'])
        while True:
            row = await write_queue.get()
            if row is None: break
            writer.writerow(row)
            csvfile.flush()
            write_queue.task_done()

async def scanner_worker(queue: asyncio.Queue, write_queue: asyncio.Queue, session: aiohttp.ClientSession, pbar: tqdm):
    while True:
        item = await queue.get()
        if item is None:
            queue.task_done()
            break

        host, port, path = item
        scheme = "https" if port in [443, 2053, 2083, 2087, 2096, 8443] else "http"
        url = f"{scheme}://{host}:{port}{path}"

        try:
            async with session.get(url, headers={"User-Agent": random.choice(UA_LIST)}, 
                                   timeout=aiohttp.ClientTimeout(total=REQUEST_TIMEOUT), 
                                   ssl=False, allow_redirects=True) as resp:
                stats["req"] += 1
                if resp.status == 200:
                    text = (await resp.content.read(350 * 1024)).decode("utf-8", errors="ignore")
                    low = text.lower()
                    hit = any(s in low for s in SIGNS)
                    
                    if hit:
                        current_hash = hashlib.md5(text.encode("utf-8")).hexdigest()[:12]
                        
                        # 核心逻辑：只有当该 URL 不存在，或者内容指纹(Hash)变了才保存
                        if url not in url_history_map or url_history_map[url] != current_hash:
                            ext = ".yaml" if "proxies:" in low or "proxy-groups:" in low else ".txt"
                            save_path = f"{OUTPUT_DIR}/hash/{current_hash}{ext}"
                            with open(save_path, 'w', encoding='utf-8') as f:
                                f.write(text)
                            
                            url_history_map[url] = current_hash
                            stats["saved"] += 1
                            await write_queue.put([current_hash, url, 'found'])
        except: stats["fail"] += 1
        finally:
            queue.task_done()
            pbar.update(1)

async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--file", required=True)
    args = parser.parse_args()
    
    os.makedirs(f"{OUTPUT_DIR}/hash", exist_ok=True)
    load_history()

    with open(args.file, 'r', encoding='utf-8') as f:
        lines = [l.strip() for l in f if l.strip()]

    queue, write_queue = asyncio.Queue(maxsize=5000), asyncio.Queue()
    
    async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=False, limit=WORKER_COUNT*2)) as session:
        pbar = tqdm(total=len(lines) * len(TARGET_PORTS) * len(PATHS))
        workers = [asyncio.create_task(scanner_worker(queue, write_queue, session, pbar)) for _ in range(WORKER_COUNT)]
        writer = asyncio.create_task(writer_worker(write_queue))

        for item in lines:
            host, port = item.rsplit(":", 1) if ":" in item else (item, None)
            ports = [int(port)] if port else TARGET_PORTS
            for p in ports:
                for path in PATHS:
                    await queue.put((host, p, path))

        for _ in range(WORKER_COUNT): await queue.put(None)
        await asyncio.gather(*workers)
        await write_queue.put(None)
        await writer

if __name__ == "__main__":
    asyncio.run(main())
