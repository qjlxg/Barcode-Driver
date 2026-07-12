import aiohttp
import asyncio
import yaml
import hashlib
import os
import csv
import argparse
import base64
import time
import signal
from tqdm import tqdm

# --- 配置 ---
TARGET_PORTS = [12202, 2096, 8443, 8081,8888]
PATHS = ["", "/s/", "/sub", "/subscribe", "/link", "/api/sub", "/getsub", "/clash", "/config", "/", "/config.yaml", "/sub.yaml", "/subscription", "/client/subscribe"]
UA_LIST = ["clash", "ClashMeta", "mihomo", "ClashforAndroid", "sing-box", "Mozilla/5.0"]
OUTPUT_DIR = "results"
WORKER_COUNT = 300 
QUEUE_SIZE = 5000
MAX_RESPONSE_SIZE = 300 * 1024 

# --- 全局统计 ---
stats = {"req": 0, "yaml_ok": 0, "base64_ok": 0, "saved": 0}
stats_lock = asyncio.Lock()
visited_hash = set()
hit_keys = set()
hit_lock = asyncio.Lock()

async def update_stats(key):
    async with stats_lock: stats[key] += 1

def count_total_tasks(file_path):
    count = 0
    with open(file_path, 'r') as f:
        for line in f:
            item = line.strip()
            if not item: continue
            if ":" in item: count += len(PATHS)
            else: count += (len(TARGET_PORTS) * len(PATHS))
    return count

async def producer(queue, file_path):
    with open(file_path, 'r') as f:
        for line in f:
            item = line.strip()
            if not item: continue
            if ":" in item:
                host, port = item.rsplit(":", 1)
                for path in PATHS: await queue.put((host, int(port), path))
            else:
                for port in TARGET_PORTS:
                    for path in PATHS: await queue.put((item, port, path))
    for _ in range(WORKER_COUNT): await queue.put(None)

async def scanner_worker(queue, session, pbar, file_lock):
    while True:
        item = await queue.get()
        if item is None:
            queue.task_done()
            break
        host, port, path = item
        hit_key = f"{host}:{port}"

        async with hit_lock:
            if hit_key in hit_keys:
                queue.task_done()
                pbar.update(1)
                continue

        # 还原协议判断逻辑
        scheme = "https" if port in [2096, 8443, 12202] else "http"
        url = f"{scheme}://{host}:{port}{path}"
        
        try:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=4), ssl=False) as resp:
                await update_stats("req")
                if resp.status == 200:
                    text = (await resp.content.read(MAX_RESPONSE_SIZE)).decode("utf-8", errors="ignore")
                    h = hashlib.md5(text.encode()).hexdigest()[:12]
                    
                    found = False
                    try:
                        cfg = yaml.safe_load(text)
                        if isinstance(cfg, dict) and any(k in cfg for k in ["proxies", "proxy-groups"]):
                            found = True
                            await update_stats("yaml_ok")
                    except: pass
                    
                    if not found and any(s in text.lower() for s in ["vless://", "vmess://", "ss://"]):
                        found = True
                        await update_stats("base64_ok")

                    if found:
                        async with file_lock:
                            if h not in visited_hash:
                                visited_hash.add(h)
                                with open(f"{OUTPUT_DIR}/hash/{h}.txt", 'w', encoding='utf-8') as f: f.write(text)
                                await update_stats("saved")
                                hit_keys.add(hit_key)
        except: pass
        finally:
            queue.task_done()
            pbar.update(1)
            pbar.set_postfix_str(f"Req: {stats['req']} | Saved: {stats['saved']}")

async def main():
    signal.signal(signal.SIGALRM, lambda s, f: os._exit(0))
    signal.alarm(5 * 3600 + 30 * 60)
    
    parser = argparse.ArgumentParser()
    parser.add_argument("--file", required=True)
    args = parser.parse_args()
    
    total = count_total_tasks(args.file)
    os.makedirs(f"{OUTPUT_DIR}/hash", exist_ok=True)

    async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=False, limit=WORKER_COUNT)) as session:
        pbar = tqdm(total=total, desc="Scanning", unit="task")
        workers = [asyncio.create_task(scanner_worker(queue, session, pbar, file_lock := asyncio.Lock())) for _ in range(WORKER_COUNT)]
        await producer(queue := asyncio.Queue(maxsize=QUEUE_SIZE), args.file)
        await asyncio.gather(*workers)
        pbar.close()

if __name__ == "__main__":
    asyncio.run(main())
