import aiohttp
import asyncio
import yaml
import hashlib
import os
import csv
import argparse
from tqdm import tqdm

# 配置
TARGET_PORTS = [443, 80, 8080]
PATHS = [
    "/", "/sub", "/subscribe", "/clash", "/config", 
    "/api/sub", "/api/v1/client/subscribe", "/link", 
    "/profile", "/getfile", "/download", "/config.yaml"
]
OUTPUT_DIR = "results"
WORKER_COUNT = 300
QUEUE_SIZE = 5000

# 全局状态
visited_hash = set()

class StatsManager:
    def __init__(self):
        self.stats = {
            "req": 0, "yaml_ok": 0, "saved": 0, 
            "timeout": 0, "network_err": 0, "yaml_err": 0, "status_codes": {}
        }
        self.lock = asyncio.Lock()
    
    async def update(self, key, is_status_code=False):
        async with self.lock:
            if is_status_code:
                code = f"http_{key}"
                self.stats["status_codes"][code] = self.stats["status_codes"].get(code, 0) + 1
            else:
                self.stats[key] = self.stats.get(key, 0) + 1
    
    def summary(self):
        lines = [f"{k}: {v}" for k, v in self.stats.items() if k != "status_codes"]
        lines.append("状态码分布:")
        for k, v in self.stats["status_codes"].items():
            lines.append(f"  {k}: {v}")
        return "\n".join(lines)

stats = StatsManager()

async def producer(queue, file_path):
    with open(file_path, 'r') as f:
        ips = [line.strip() for line in f if line.strip()]
    
    for ip in ips:
        for port in TARGET_PORTS:
            for path in PATHS:
                await queue.put((ip, port, path))
                
    for _ in range(WORKER_COUNT): await queue.put(None)

async def writer_worker(write_queue):
    data_map = {}
    while True:
        row = await write_queue.get()
        if row is None: break
        h, ip_port_path = row
        if h not in data_map:
            data_map[h] = {"count": 0, "urls": []}
        data_map[h]["count"] += 1
        if len(data_map[h]["urls"]) < 100:
            data_map[h]["urls"].append(ip_port_path)
        write_queue.task_done()
    
    with open('scan_results.csv', 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(['hash', 'count', 'urls'])
        for h, info in data_map.items():
            writer.writerow([h, info["count"], "|".join(info["urls"])])

async def monitor(pbar):
    while True:
        await asyncio.sleep(5)
        pbar.write(f"\n--- 实时诊断 ---\n{stats.summary()}\n----------------")

async def scanner_worker(queue, write_queue, session, pbar, file_lock):
    while True:
        item = await queue.get()
        if item is None:
            queue.task_done()
            break
        ip, port, path = item
        
        try:
            url = f"{'https' if port == 443 else 'http'}://{ip}:{port}{path}"
            headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
            async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=8, connect=3), ssl=False) as resp:
                await stats.update("req")
                await stats.update(resp.status, is_status_code=True)
                
                if resp.status == 200:
                    # 性能保护：超过 2MB 跳过
                    cl = int(resp.headers.get("Content-Length", 0))
                    if cl > 2 * 1024 * 1024: continue
                    
                    ctype = resp.headers.get("Content-Type", "").lower()
                    server = resp.headers.get("Server", "unknown")
                    
                    async with file_lock:
                        with open("success_stats.csv", "a", newline='') as f:
                            csv.writer(f).writerow([ip, port, path, ctype, server, cl])
                    
                    data = await resp.content.read(1024 * 1024)
                    text = data.decode("utf-8", errors="ignore")
                    lower_text = text.lower()
                    
                    yaml_sign = ["\nproxies:", "\nproxy-groups:", "\nmixed-port:", "\nallow-lan:", "\nexternal-controller:"]
                    if any(x in lower_text for x in yaml_sign):
                        try:
                            cfg = yaml.safe_load(text)
                            if isinstance(cfg, dict) and "proxies" in cfg and isinstance(cfg["proxies"], list) and len(cfg["proxies"]) > 0:
                                await stats.update("yaml_ok")
                                h = hashlib.md5(text.encode()).hexdigest()[:12]
                                async with file_lock:
                                    if h not in visited_hash:
                                        visited_hash.add(h)
                                        with open(f"{OUTPUT_DIR}/hash/{h}.yaml", 'w', encoding='utf-8') as f: f.write(text)
                                        await stats.update("saved")
                                await write_queue.put([h, f"{ip}:{port}{path}"])
                        except yaml.YAMLError: await stats.update("yaml_err")
        except asyncio.TimeoutError: await stats.update("timeout")
        except aiohttp.ClientError: await stats.update("network_err")
        except Exception: await stats.update("network_err")
        finally:
            queue.task_done()
            pbar.update(1)

async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--file", required=True)
    args = parser.parse_args()
    os.makedirs(f"{OUTPUT_DIR}/hash", exist_ok=True)
    
    if not os.path.exists("success_stats.csv"):
        with open("success_stats.csv", "w", newline='') as f:
            csv.writer(f).writerow(['ip', 'port', 'path', 'ctype', 'server', 'length'])
            
    queue = asyncio.Queue(maxsize=QUEUE_SIZE)
    write_queue = asyncio.Queue()
    file_lock = asyncio.Lock()
    
    async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=False, limit=WORKER_COUNT)) as session:
        pbar = tqdm(desc="Scanning")
        monitor_task = asyncio.create_task(monitor(pbar))
        workers = [asyncio.create_task(scanner_worker(queue, write_queue, session, pbar, file_lock)) for _ in range(WORKER_COUNT)]
        writer_task = asyncio.create_task(writer_worker(write_queue))
        await producer(queue, args.file)
        await asyncio.gather(*workers)
        await write_queue.put(None)
        await writer_task
        monitor_task.cancel()
        pbar.close()
        print(stats.summary())

if __name__ == "__main__":
    asyncio.run(main())
