import aiohttp
import asyncio
import yaml
import hashlib
import os
import csv
import argparse
import base64
import brotli # 增加 br 支持
from tqdm import tqdm

# 配置
TARGET_PORTS = [443, 80, 8080]
PATHS = [
    "/sub", "/subscribe", "/link", "/api/sub", "/getsub", "/clash", 
    "/config", "/", "/config.yaml", "/sub.yaml", "/subscription", "/client/subscribe"
]
UA_LIST = ["clash", "ClashMeta", "mihomo", "ClashforAndroid", "sing-box", "Mozilla/5.0"]
OUTPUT_DIR = "results"
WORKER_COUNT = 300 # 提升并发，配合 limit_per_host
QUEUE_SIZE = 5000
MAX_RESPONSE_SIZE = 300 * 1024 

# 启动时加载 Hash
def load_hashes():
    hashes = set()
    path = f"{OUTPUT_DIR}/hash"
    if os.path.exists(path):
        for f in os.listdir(path):
            if f.endswith(".yaml") or f.endswith(".txt"):
                hashes.add(f.split('.')[0])
    return hashes

visited_hash = load_hashes()
sample_lock = asyncio.Lock()
SAMPLE_COLLECTED = 0

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
        res = ", ".join([f"{k}: {v}" for k, v in self.stats.items() if k != "status_codes"])
        return res + f" | Status: {dict(self.stats['status_codes'])}"

stats = StatsManager()

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

async def producer(queue, file_path):
    # 采用流式生产，避免内存溢出
    with open(file_path, 'r') as f:
        for line in f:
            host = line.strip()
            if not host: continue
            for port in TARGET_PORTS:
                for path in PATHS:
                    await queue.put((host, port, path))
    for _ in range(WORKER_COUNT): await queue.put(None)

async def writer_worker(write_queue):
    file_exists = os.path.exists('scan_results.csv')
    with open('scan_results.csv', 'a', newline='') as csvfile:
        writer = csv.writer(csvfile)
        if not file_exists: writer.writerow(['hash', 'url', 'server', 'ctype'])
        while True:
            row = await write_queue.get()
            if row is None: break
            writer.writerow(row)
            csvfile.flush()
            write_queue.task_done()

async def scanner_worker(queue, write_queue, session, pbar, file_lock):
    global SAMPLE_COLLECTED
    while True:
        item = await queue.get()
        if item is None:
            queue.task_done()
            break
        host, port, path = item
        url = f"{'https' if port == 443 else 'http'}://{host}:{port}{path}"
        # 稳定 UA 分配
        ua = UA_LIST[hash(host) % len(UA_LIST)]
        headers = {"User-Agent": ua, "Accept-Encoding": "gzip, deflate, br"}
        
        try:
            async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=8), ssl=False) as resp:
                await stats.update("req")
                await stats.update(resp.status, is_status=True)
                
                if resp.status == 200:
                    ctype = resp.headers.get("Content-Type", "").lower()
                    if not any(x in ctype for x in ["text", "yaml", "json"]): continue
                    
                    try: cl = int(resp.headers.get("Content-Length", 0))
                    except: cl = 0
                    if cl > MAX_RESPONSE_SIZE: continue
                    
                    data = await resp.content.read(MAX_RESPONSE_SIZE)
                    text = data.decode("utf-8", errors="ignore")
                    
                    # 保存 YAML / Base64 逻辑
                    h = hashlib.md5(text.encode()).hexdigest()[:12]
                    yaml_match = False
                    
                    # 1. 评分制 YAML
                    try:
                        cfg = yaml.safe_load(text)
                        if isinstance(cfg, dict):
                            score = 0
                            if isinstance(cfg.get("proxies"), list): score += 2
                            if isinstance(cfg.get("proxy-providers"), dict): score += 3
                            if isinstance(cfg.get("proxy-groups"), list): score += 2
                            if score >= 2:
                                yaml_match = True
                                await stats.update("yaml_ok")
                                async with file_lock:
                                    if h not in visited_hash:
                                        visited_hash.add(h)
                                        with open(f"{OUTPUT_DIR}/hash/{h}.yaml", 'w', encoding='utf-8') as f: f.write(text)
                                        await stats.update("saved")
                    except: await stats.update("yaml_err")
                    
                    # 2. Base64
                    base64_match = False
                    if looks_like_base64(text):
                        decoded = decode_base64(text)
                        if any(s in text.lower() or s in decoded.lower() for s in ["vless://", "vmess://", "ss://", "trojan://"]):
                            base64_match = True
                            await stats.update("base64_ok")
                            async with file_lock:
                                if h not in visited_hash:
                                    visited_hash.add(h)
                                    with open(f"{OUTPUT_DIR}/hash/{h}.txt", 'w', encoding='utf-8') as f: f.write(text)
                                    await stats.update("saved")
                    
                    # 统一记录来源 (无论 hash 是否新，都记录 url)
                    if yaml_match or base64_match:
                        await write_queue.put([h, url, resp.headers.get("Server", ""), ctype])
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
    file_lock = asyncio.Lock()
    
    # 适配 VPS 环境的连接池
    connector = aiohttp.TCPConnector(ssl=False, limit=WORKER_COUNT, limit_per_host=10)
    async with aiohttp.ClientSession(connector=connector) as session:
        pbar = tqdm(desc="Scanning")
        workers = [asyncio.create_task(scanner_worker(queue, write_queue, session, pbar, file_lock)) for _ in range(WORKER_COUNT)]
        writer_task = asyncio.create_task(writer_worker(write_queue))
        await producer(queue, args.file)
        await asyncio.gather(*workers)
        await write_queue.put(None)
        await writer_task
        pbar.close()
        print(stats.summary())

if __name__ == "__main__":
    asyncio.run(main())
