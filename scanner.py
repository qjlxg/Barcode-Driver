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
# 字典定义：端口: 是否强制使用 HTTPS
TARGET_PORTS = {12202: True, 2096: True, 8443: True, 8081: False}
PATHS = [
    "", "/s/", "/sub", "/subscribe", "/link", "/api/sub", "/getsub", "/clash", 
    "/config", "/", "/config.yaml", "/sub.yaml", "/subscription", "/client/subscribe"
]
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

# 精细化去重：记录 host:port
hit_keys = set()
hit_lock = asyncio.Lock()

start_time = time.time()
total_items = 0

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
        
        elapsed = time.time() - start_time
        reqs = self.stats["req"]
        eta_str = "Calculating..."
        if reqs > 0 and total_items > 0:
            avg_time = elapsed / reqs
            eta = (total_items - reqs) * avg_time
            eta_str = f"{int(eta // 3600)}h {int((eta % 3600) // 60)}m {int(eta % 60)}s"
            
        return f"{res} | Added: {added_count} | Status: {dict(self.stats['status_codes'])} | ETA: {eta_str}"

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
    global total_items
    with open(file_path, 'r') as f:
        items = [line.strip() for line in f if line.strip()]
    
    for item in items:
        # 支持 IP:PORT 格式，如果未指定端口则遍历 TARGET_PORTS
        if ":" in item:
            host, port = item.rsplit(":", 1)
            for path in PATHS:
                await queue.put((host, int(port), False, path))
                total_items += 1
        else:
            for port, is_https in TARGET_PORTS.items():
                for path in PATHS:
                    await queue.put((item, port, is_https, path))
                    total_items += 1
    for _ in range(WORKER_COUNT): await queue.put(None)

async def scanner_worker(queue, write_queue, session, pbar, file_lock):
    while True:
        item = await queue.get()
        if item is None:
            queue.task_done()
            break
        host, port, is_https, path = item
        hit_key = f"{host}:{port}"

        async with hit_lock:
            if hit_key in hit_keys:
                queue.task_done()
                pbar.update(1)
                continue

        scheme = "https" if is_https else "http"
        url = f"{scheme}://{host}:{port}{path}"
        headers = {"User-Agent": UA_LIST[hash(host) % len(UA_LIST)], "Accept-Encoding": "gzip, deflate, br"}

        try:
            async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=4), ssl=False) as resp:
                await stats.update("req")
                await stats.update(resp.status, is_status=True)

                if resp.status == 200:
                    data = await resp.content.read(MAX_RESPONSE_SIZE)
                    text = data.decode("utf-8", errors="ignore")
                    h = hashlib.md5(text.encode()).hexdigest()[:12]
                    
                    # 订阅检测逻辑
                    yaml_match = False
                    try:
                        cfg = yaml.safe_load(text)
                        if isinstance(cfg, dict) and any(k in cfg for k in ["proxies", "proxy-groups"]):
                            yaml_match = True
                            await stats.update("yaml_ok")
                            async with file_lock:
                                if h not in visited_hash:
                                    visited_hash.add(h)
                                    with open(f"{OUTPUT_DIR}/hash/{h}.yaml", 'w', encoding='utf-8') as f: f.write(text)
                                    await stats.update("saved")
                    except: await stats.update("yaml_err")

                    base64_match = False
                    if not yaml_match and looks_like_base64(text):
                        decoded = decode_base64(text)
                        if any(s in decoded.lower() for s in ["vless://", "vmess://", "ss://", "trojan://"]):
                            base64_match = True
                            await stats.update("base64_ok")
                            async with file_lock:
                                if h not in visited_hash:
                                    visited_hash.add(h)
                                    with open(f"{OUTPUT_DIR}/hash/{h}.txt", 'w', encoding='utf-8') as f: f.write(text)
                                    await stats.update("saved")

                    if yaml_match or base64_match:
                        async with hit_lock: hit_keys.add(hit_key)
                        await write_queue.put([h, url, resp.headers.get("Server", ""), resp.headers.get("Content-Type", "")])
        except asyncio.TimeoutError: await stats.update("timeout")
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

    connector = aiohttp.TCPConnector(ssl=False, limit=WORKER_COUNT, limit_per_host=10)
    async with aiohttp.ClientSession(connector=connector) as session:
        pbar = tqdm(total=total_items, desc="Scanning")
        workers = [asyncio.create_task(scanner_worker(queue, write_queue, session, pbar, file_lock)) for _ in range(WORKER_COUNT)]
        asyncio.create_task(asyncio.to_thread(lambda: open('scan_results.csv', 'a').close())) # Init file
        
        await producer(queue, args.file)
        await asyncio.gather(*workers)
        pbar.close()
        print("\n--- 任务完成 ---\n" + stats.summary())

if __name__ == "__main__":
    asyncio.run(main())
