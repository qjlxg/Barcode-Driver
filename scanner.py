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

# --- 配置 ---
TARGET_PORTS = [1333, 1999, 2052, 2053, 2082, 2083, 2087, 2095, 2096, 2222, 3002, 3333, 4444, 5555, 6001, 6666, 7777, 80, 8011, 8080, 8081, 8083, 8443, 8444, 8787, 8888, 8899, 9050, 9981, 9999, 10110, 12202, 18080, 19999, 54321, 60001, 60002]
PATHS = ["", "/", "/sub", "/subscribe", "/link", "/s/", "/api/sub", "/api/v1/client/subscribe", "/api/user/subscribe", "/client/subscribe", "/config.yaml", "/sub.yaml"]
SIGNS = ["proxies:", "proxy-groups:", "vless://", "vmess://", "trojan://", "uuid:", "hysteria://", "hysteria2://", "hy2://", "tuic://", "anytls://"]
UA_LIST = ["ClashMeta/1.1", "sing-box/1.8", "ClashforAndroid/2.5", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"]
OUTPUT_DIR = "results"
MAX_SAVE_FILES = 2000
WORKER_COUNT = 100 

stats = {"req": 0, "saved": 0, "other": 0}
visited_hash = set()
existing_urls = set()

def cleanup_files():
    hash_dir = f"{OUTPUT_DIR}/hash"
    if not os.path.exists(hash_dir): return
    files = [os.path.join(hash_dir, f) for f in os.listdir(hash_dir)]
    if len(files) > MAX_SAVE_FILES:
        files.sort(key=os.path.getmtime)
        for f in files[:len(files) - MAX_SAVE_FILES]: os.remove(f)

def load_history():
    hash_dir = f"{OUTPUT_DIR}/hash"
    if os.path.exists(hash_dir):
        for f in os.listdir(hash_dir): visited_hash.add(f.split(".")[0])
    if os.path.exists('scan_results.csv'):
        with open('scan_results.csv', 'r', encoding='utf-8') as f:
            for row in csv.reader(f):
                if len(row) > 1: existing_urls.add(row[1])

async def writer_worker(write_queue):
    with open('scan_results.csv', 'a', newline='', encoding='utf-8') as csvfile:
        writer = csv.writer(csvfile)
        if csvfile.tell() == 0: writer.writerow(['hash', 'url', 'type'])
        while True:
            row = await write_queue.get()
            if row is None: break
            if row[1] not in existing_urls:
                writer.writerow(row)
                csvfile.flush()
                existing_urls.add(row[1])
            write_queue.task_done()

async def scanner_worker(queue, write_queue, session, pbar, file_lock):
    while True:
        item = await queue.get()
        if item is None:
            queue.task_done()
            break
        host, port, path = item
        url = f"{'https' if port in [443, 2053, 2083, 2087, 2096, 8443] else 'http'}://{host}:{port}{path}"
        try:
            async with session.get(url, headers={"User-Agent": random.choice(UA_LIST)}, timeout=aiohttp.ClientTimeout(total=4), ssl=False) as resp:
                stats["req"] += 1
                if resp.status == 200:
                    text = (await resp.content.read(300 * 1024)).decode("utf-8", errors="ignore")
                    low = text.lower()
                    hit = any(s in low for s in SIGNS)
                    if not hit and 20 < len(text) < 200000:
                        decoded = "".join(text.split()).replace("-", "+").replace("_", "/")
                        padding = len(decoded) % 4
                        if padding: decoded += "=" * (4 - padding)
                        try: hit = any(s in base64.b64decode(decoded, validate=False).decode("utf8", errors="ignore").lower() for s in SIGNS if "://" in s)
                        except: pass
                    
                    if hit:
                        h = hashlib.md5(text.encode()).hexdigest()[:12]
                        if h not in visited_hash:
                            visited_hash.add(h)
                            cleanup_files()
                            ext = ".yaml" if "proxies:" in low else ".txt"
                            with open(f"{OUTPUT_DIR}/hash/{h}{ext}", 'w', encoding='utf-8') as f: f.write(text)
                            stats["saved"] += 1
                            await write_queue.put([h, url.lower().rstrip("/"), 'found'])
        except: stats["other"] += 1
        finally:
            queue.task_done()
            pbar.update(1)
            if stats["req"] % 500 == 0: pbar.set_postfix_str(f"Req: {stats['req']} | Saved: {stats['saved']}")

async def main():
    try: signal.signal(signal.SIGALRM, lambda s, f: os._exit(0)); signal.alarm(19800)
    except: pass
    parser = argparse.ArgumentParser(); parser.add_argument("--file", required=True); args = parser.parse_args()
    os.makedirs(f"{OUTPUT_DIR}/hash", exist_ok=True); load_history()
    with open(args.file, 'r') as f: lines = [l.strip() for l in f if l.strip()]
    
    total = sum(len(PATHS) * (len(TARGET_PORTS) if ":" not in l else 1) for l in lines)
    queue, write_queue = asyncio.Queue(maxsize=5000), asyncio.Queue()
    file_lock = asyncio.Lock()
    
    async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=False, limit=WORKER_COUNT, ttl_dns_cache=300)) as session:
        pbar = tqdm(total=total, desc="Scanning", unit="task", mininterval=5)
        workers = [asyncio.create_task(scanner_worker(queue, write_queue, session, pbar, file_lock)) for _ in range(WORKER_COUNT)]
        writer = asyncio.create_task(writer_worker(write_queue))
        for item in lines:
            if ":" in item: host, port = item.rsplit(":", 1); [await queue.put((host, int(port), path)) for path in PATHS]
            else: [await queue.put((item, port, path)) for port in TARGET_PORTS for path in PATHS]
        for _ in range(WORKER_COUNT): await queue.put(None)
        await asyncio.gather(*workers); await write_queue.put(None); await writer; pbar.close()

if __name__ == "__main__": asyncio.run(main())
