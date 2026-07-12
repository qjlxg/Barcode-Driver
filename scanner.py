import aiohttp
import asyncio
import yaml
import hashlib
import os
import csv
import argparse
import base64
import time
from tqdm import tqdm

# --- 配置 ---
TARGET_PORTS = [12202,2096,8443]
# 优先扫描 "" (根路径)，然后扫描其他路径
PATHS = ["", "/sub", "/subscribe", "/link", "/api/sub", "/getsub", "/clash", 
         "/config", "/", "/config.yaml", "/sub.yaml", "/subscription", "/client/subscribe"]
UA_LIST = ["clash", "ClashMeta", "mihomo", "ClashforAndroid", "sing-box", "Mozilla/5.0"]
OUTPUT_DIR = "results"
WORKER_COUNT = 300 
QUEUE_SIZE = 5000
MAX_RESPONSE_SIZE = 300 * 1024 

# --- 初始化与状态 ---
def load_hashes():
    hashes = set()
    path = f"{OUTPUT_DIR}/hash"
    if os.path.exists(path):
        for f in os.listdir(path):
            if f.endswith(".yaml") or f.endswith(".txt"):
                hashes.add(f.split('.')[0])
    return hashes

initial_hashes = load_hashes()
visited_hash = set(initial_hashes)
initial_count = len(visited_hash)

# 加载已有的 manifest 以便去重
known_manifest = set()
if os.path.exists('scan_manifest.csv'):
    with open('scan_manifest.csv', 'r') as f:
        reader = csv.reader(f)
        for row in reader:
            if row: known_manifest.add(row[0]) # 存储 'url'

hit_hosts = set()
hit_lock = asyncio.Lock()

class StatsManager:
    def __init__(self):
        self.stats = {
            "req": 0, "yaml_ok": 0, "base64_ok": 0, "saved": 0, 
            "timeout": 0, "network_err": 0, "yaml_err": 0, "status_codes": {}
        }
        self.lock = asyncio.Lock()

    async def update(self, key, is_status=False):
        async with self.lock:
            if is_status:
                self.stats["status_codes"][key] = self.stats["status_codes"].get(key, 0) + 1
            else:
                self.stats[key] = self.stats.get(key, 0) + 1

    def summary(self):
        current_count = len(visited_hash)
        added_count = current_count - initial_count
        res = ", ".join([f"{k}: {v}" for k, v in self.stats.items() if k != "status_codes"])
        return f"{res} | New_Nodes_Added: {added_count} | Status: {dict(self.stats['status_codes'])}"

stats = StatsManager()

# --- 辅助函数 ---
def looks_like_base64(s):
    s = "".join(s.split())
    return len(s) > 50 and len(s) % 4 in (0, 2, 3)

def decode_base64(text):
    text = "".join(text.split()).replace("-", "+").replace("_", "/")
    padding = len(text) % 4
    if padding: text += "=" * (4 - padding)
    try:
        raw = base64.b64decode(text, validate=False)
        return raw.decode("utf8", errors="ignore")
    except: return ""

# --- 核心逻辑 ---
async def producer(queue, file_path):
    with open(file_path, 'r') as f:
        lines = f.readlines()
        total_tasks = 0
        for line in lines:
            item = line.strip()
            if not item: continue
            if ":" in item:
                host, port = item.rsplit(":", 1)
                for path in PATHS:
                    await queue.put((host, int(port), path))
                    total_tasks += 1
            else:
                for port in TARGET_PORTS:
                    for path in PATHS:
                        await queue.put((item, port, path))
                        total_tasks += 1
    for _ in range(WORKER_COUNT): await queue.put(None)
    return total_tasks

async def writer_worker(write_queue, manifest_queue):
    file_exists = os.path.exists('scan_results.csv')
    with open('scan_results.csv', 'a', newline='') as csvfile, \
         open('scan_manifest.csv', 'a', newline='') as mfile:
        writer = csv.writer(csvfile)
        mwriter = csv.writer(mfile)
        if not file_exists: writer.writerow(['hash', 'url', 'server', 'ctype'])
        
        while True:
            row = await write_queue.get()
            if row is None: break
            writer.writerow(row)
            csvfile.flush()
            write_queue.task_done()
        
        while True:
            m_row = await manifest_queue.get()
            if m_row is None: break
            mwriter.writerow(m_row)
            mfile.flush()
            manifest_queue.task_done()

async def scanner_worker(queue, write_queue, manifest_queue, session, pbar, file_lock):
    while True:
        item = await queue.get()
        if item is None:
            queue.task_done()
            break
        host, port, path = item
        url = f"{'https' if port == 443 else 'http'}://{host}:{port}{path}"
        
        if url in known_manifest:
            queue.task_done()
            pbar.update(1)
            continue

        ua = UA_LIST[hash(host) % len(UA_LIST)]
        headers = {"User-Agent": ua, "Accept-Encoding": "gzip, deflate, br"}

        try:
            async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=4), ssl=False) as resp:
                await stats.update("req")
                await stats.update(resp.status, is_status=True)

                if resp.status == 200:
                    data = await resp.content.read(MAX_RESPONSE_SIZE)
                    text = data.decode("utf-8", errors="ignore")
                    h = hashlib.md5(text.encode()).hexdigest()[:12]
                    
                    saved_now = False
                    try:
                        cfg = yaml.safe_load(text)
                        if isinstance(cfg, dict) and (isinstance(cfg.get("proxies"), list) or isinstance(cfg.get("proxy-providers"), dict)):
                            async with file_lock:
                                if h not in visited_hash:
                                    visited_hash.add(h)
                                    with open(f"{OUTPUT_DIR}/hash/{h}.yaml", 'w', encoding='utf-8') as f: f.write(text)
                                    await stats.update("saved")
                            saved_now = True
                            await stats.update("yaml_ok")
                    except: await stats.update("yaml_err")

                    if not saved_now and looks_like_base64(text) and any(s in text.lower() for s in ["vless://", "vmess://", "ss://", "trojan://"]):
                        async with file_lock:
                            if h not in visited_hash:
                                visited_hash.add(h)
                                with open(f"{OUTPUT_DIR}/hash/{h}.txt", 'w', encoding='utf-8') as f: f.write(text)
                                await stats.update("saved")
                        await stats.update("base64_ok")
                        saved_now = True

                    if saved_now:
                        await write_queue.put([h, url, resp.headers.get("Server", ""), resp.headers.get("Content-Type", "")])
                        await manifest_queue.put([url, f"{h}.yaml" if text.strip().startswith(('proxies:', 'proxy-')) else f"{h}.txt"])
                        known_manifest.add(url)
        except: await stats.update("network_err")
        finally:
            queue.task_done()
            pbar.update(1)

async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--file", required=True)
    args = parser.parse_args()
    os.makedirs(f"{OUTPUT_DIR}/hash", exist_ok=True)

    queue = asyncio.Queue(maxsize=QUEUE_SIZE)
    write_queue = asyncio.Queue()
    manifest_queue = asyncio.Queue()
    file_lock = asyncio.Lock()

    print("正在加载任务并初始化清单...")
    total_tasks = await producer(queue, args.file)
    
    connector = aiohttp.TCPConnector(ssl=False, limit=WORKER_COUNT, limit_per_host=10)
    async with aiohttp.ClientSession(connector=connector) as session:
        # 使用 tqdm 实现进度条与自动 ETA (预计剩余时间) 计算
        pbar = tqdm(total=total_tasks, desc="Scanning", unit="url", ncols=100)
        workers = [asyncio.create_task(scanner_worker(queue, write_queue, manifest_queue, session, pbar, file_lock)) for _ in range(WORKER_COUNT)]
        writer_task = asyncio.create_task(writer_worker(write_queue, manifest_queue))
        
        await asyncio.gather(*workers)
        await write_queue.put(None)
        await manifest_queue.put(None)
        await writer_task
        pbar.close()
        print("\n--- 任务完成 ---")
        print(stats.summary())

if __name__ == "__main__":
    asyncio.run(main())
