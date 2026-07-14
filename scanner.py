import aiohttp
import asyncio
import hashlib
import os
import csv
import argparse
import base64
import random
import signal
import sys
from tqdm import tqdm
from typing import List, Tuple

# --- 配置 ---
TARGET_PORTS = [80, 443, 1333, 1999, 2052, 2053, 2082, 2083, 2087, 2095, 2096,
                2222, 3002, 3333, 4444, 5555, 6001, 6666, 7777, 8011, 8080, 8081,
                8083, 8443, 8444, 8787, 8888, 8899, 9050, 9981, 9999, 10110, 12202,
                18080, 19999, 54321, 60001, 60002]

PATHS = ["", "/", "/sub", "/subscribe", "/link", "/s/", "/api/sub", "/api/v1/client/subscribe",
         "/api/user/subscribe", "/client/subscribe", "/config.yaml", "/sub.yaml"]

SIGNS = ["proxies:", "proxy-groups:", "mixed-port", "vless://", "vmess://", "trojan://", "uuid:",
         "hysteria://", "hysteria2://", "hy2://", "tuic://", "anytls://"]

UA_LIST = ["Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"]

OUTPUT_DIR = "results"
MAX_SAVE_FILES = 2000
WORKER_COUNT = 28
REQUEST_TIMEOUT = 5

stats = {"req": 0, "saved": 0, "fail": 0}
visited_content_hashes = set()

def cleanup_files():
    hash_dir = f"{OUTPUT_DIR}/hash"
    if not os.path.exists(hash_dir): return
    files = [os.path.join(hash_dir, f) for f in os.listdir(hash_dir) if os.path.isfile(os.path.join(hash_dir, f))]
    if len(files) > MAX_SAVE_FILES:
        files.sort(key=os.path.getmtime)
        for f in files[:len(files) - MAX_SAVE_FILES]:
            try: os.remove(f)
            except: pass

async def scanner_worker(queue: asyncio.Queue, write_queue: asyncio.Queue, session: aiohttp.ClientSession):
    while True:
        item = await queue.get()
        if item is None:
            queue.task_done()
            break

        host, port, path = item
        # 使用 https
        url = f"https://{host}:{port}{path}"

        try:
            async with session.get(url, headers={"User-Agent": random.choice(UA_LIST), "Host": host}, 
                                   timeout=aiohttp.ClientTimeout(total=REQUEST_TIMEOUT), 
                                   ssl=False, allow_redirects=True) as resp:
                stats["req"] += 1
                if resp.status == 200:
                    text = (await resp.content.read(350 * 1024)).decode("utf-8", errors="ignore")
                    low = text.lower()
                    hit = any(s in low for s in SIGNS)

                    # Base64 解码尝试
                    if not hit and 50 < len(text) < 250000:
                        try:
                            decoded_str = "".join(text.split()).replace("-", "+").replace("_", "/")
                            padding = len(decoded_str) % 4
                            if padding: decoded_str += "=" * (4 - padding)
                            decoded = base64.b64decode(decoded_str, validate=False).decode("utf-8", errors="ignore")
                            hit = any(s in decoded.lower() for s in SIGNS if "://" in s)
                        except: pass

                    if hit:
                        h = hashlib.md5(text.encode("utf-8")).hexdigest()[:12]
                        if h not in visited_content_hashes:
                            cleanup_files()
                            os.makedirs(f"{OUTPUT_DIR}/hash", exist_ok=True)
                            with open(f"{OUTPUT_DIR}/hash/{h}.yaml", 'w', encoding='utf-8') as f: f.write(text)
                            stats["saved"] += 1
                            await write_queue.put([h, url])
        except: stats["fail"] += 1
        finally: queue.task_done()

async def writer_worker(write_queue: asyncio.Queue):
    with open('scan_results.csv', 'a', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        while True:
            row = await write_queue.get()
            if row is None: break
            writer.writerow(row)
            f.flush()
            write_queue.task_done()

async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--file", required=True)
    args = parser.parse_args()

    with open(args.file, 'r', encoding='utf-8') as f:
        lines = [l.strip() for l in f if l.strip()]

    queue = asyncio.Queue()
    write_queue = asyncio.Queue()

    async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=False)) as session:
        workers = [asyncio.create_task(scanner_worker(queue, write_queue, session)) for _ in range(WORKER_COUNT)]
        writer_task = asyncio.create_task(writer_worker(write_queue))

        for item in lines:
            host, port = item.rsplit(":", 1) if ":" in item else (item, 443)
            for path in PATHS:
                await queue.put((host, int(port), path))
        
        for _ in range(WORKER_COUNT): await queue.put(None)
        await asyncio.gather(*workers)
        await write_queue.put(None)
        await writer_task

    print(f"\n[+] 扫描完成！请求: {stats['req']} | 保存: {stats['saved']} | 失败: {stats['fail']}")

if __name__ == "__main__":
    asyncio.run(main())
