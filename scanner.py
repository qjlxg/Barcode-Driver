import aiohttp
import asyncio
import yaml
import hashlib
import os
import csv
import argparse
import base64
from tqdm import tqdm

# --- 配置 ---
TARGET_PORTS = [12202, 2096, 8443]
PATHS = ["", "/sub", "/subscribe", "/link", "/api/sub", "/getsub", "/clash", 
         "/config", "/", "/config.yaml", "/sub.yaml", "/subscription", "/client/subscribe"]
UA_LIST = ["clash", "ClashMeta", "mihomo", "ClashforAndroid", "sing-box", "Mozilla/5.0"]
OUTPUT_DIR = "results"
WORKER_COUNT = 300 
QUEUE_SIZE = 5000
MAX_RESPONSE_SIZE = 300 * 1024 

# --- 初始化 ---
def load_hashes():
    hashes = set()
    path = f"{OUTPUT_DIR}/hash"
    if os.path.exists(path):
        for f in os.listdir(path):
            if f.endswith((".yaml", ".txt")):
                hashes.add(f.split('.')[0])
    return hashes

visited_hash = load_hashes()
initial_count = len(visited_hash)
hit_hosts = set() # 锁定已发现节点的域名
hit_lock = asyncio.Lock()

known_manifest = set()
if os.path.exists('scan_manifest.csv'):
    with open('scan_manifest.csv', 'r') as f:
        reader = csv.reader(f)
        for row in reader:
            if row: known_manifest.add(row[0])

class StatsManager:
    def __init__(self):
        self.stats = {"req": 0, "yaml_ok": 0, "base64_ok": 0, "saved": 0, "network_err": 0}
        self.lock = asyncio.Lock()
    async def update(self, key):
        async with self.lock: self.stats[key] += 1
    def summary(self):
        return " | ".join([f"{k}: {v}" for k, v in self.stats.items()])

stats = StatsManager()

# --- 核心逻辑 ---
async def producer(queue, file_path):
    with open(file_path, 'r') as f:
        total_tasks = 0
        for line in f:
            host = line.strip()
            if not host: continue
            for port in TARGET_PORTS:
                for path in PATHS:
                    await queue.put((host, port, path))
                    total_tasks += 1
    for _ in range(WORKER_COUNT): await queue.put(None)
    return total_tasks

async def scanner_worker(queue, write_queue, manifest_queue, session, pbar, file_lock):
    while True:
        item = await queue.get()
        if item is None:
            queue.task_done()
            break
        host, port, path = item
        
        # 核心：检查是否已发现此域名的节点
        async with hit_lock:
            if host in hit_hosts:
                queue.task_done()
                pbar.update(1)
                continue

        url = f"{'https' if port in [443, 8443, 2096] else 'http'}://{host}:{port}{path}"
        if url in known_manifest:
            queue.task_done()
            pbar.update(1)
            continue

        try:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=4), ssl=False) as resp:
                await stats.update("req")
                if resp.status == 200:
                    data = await resp.content.read(MAX_RESPONSE_SIZE)
                    text = data.decode("utf-8", errors="ignore")
                    h = hashlib.md5(text.encode()).hexdigest()[:12]
                    
                    is_valid = False
                    try:
                        cfg = yaml.safe_load(text)
                        if isinstance(cfg, dict) and (isinstance(cfg.get("proxies"), list) or "proxy-providers" in cfg):
                            is_valid = True
                            await stats.update("yaml_ok")
                    except: pass
                    
                    if not is_valid and len(text) > 50 and any(s in text.lower() for s in ["vless://", "vmess://", "ss://", "trojan://"]):
                        is_valid = True
                        await stats.update("base64_ok")

                    if is_valid:
                        async with hit_lock: hit_hosts.add(host) # 锁定域名，后续该域名任务会被跳过
                        async with file_lock:
                            if h not in visited_hash:
                                visited_hash.add(h)
                                with open(f"{OUTPUT_DIR}/hash/{h}.{'yaml' if 'proxies' in text else 'txt'}", 'w', encoding='utf-8') as f: f.write(text)
                                await stats.update("saved")
                        await write_queue.put([h, url, resp.headers.get("Server", ""), resp.headers.get("Content-Type", "")])
                        await manifest_queue.put([url, f"{h}.{'yaml' if 'proxies' in text else 'txt'}"])
                        known_manifest.add(url)
        except: await stats.update("network_err")
        finally:
            queue.task_done()
            pbar.update(1)

async def writer_worker(write_queue, manifest_queue):
    with open('scan_results.csv', 'a', newline='') as f1, open('scan_manifest.csv', 'a', newline='') as f2:
        w1, w2 = csv.writer(f1), csv.writer(f2)
        while True:
            row = await write_queue.get()
            if row is None: break
            w1.writerow(row)
            write_queue.task_done()
        while True:
            row = await manifest_queue.get()
            if row is None: break
            w2.writerow(row)
            manifest_queue.task_done()

async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--file", required=True)
    args = parser.parse_args()
    os.makedirs(f"{OUTPUT_DIR}/hash", exist_ok=True)

    queue = asyncio.Queue(maxsize=QUEUE_SIZE)
    wq, mq = asyncio.Queue(), asyncio.Queue()
    
    total = await producer(queue, args.file)
    pbar = tqdm(total=total, desc="Scanning", unit="task")
    
    async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=False)) as session:
        workers = [asyncio.create_task(scanner_worker(queue, wq, mq, session, pbar, asyncio.Lock())) for _ in range(WORKER_COUNT)]
        writer = asyncio.create_task(writer_worker(wq, mq))
        await asyncio.gather(*workers)
        await wq.put(None); await mq.put(None)
        await writer
    print(stats.summary())

if __name__ == "__main__":
    asyncio.run(main())
