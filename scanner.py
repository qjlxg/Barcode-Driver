import aiohttp
import asyncio
import yaml
import hashlib
import os
import csv
import argparse
from tqdm import tqdm

# 配置区域
TARGET_PORTS = [80, 443, 7890, 8080, 8888, 9090]
TARGET_PATHS = ["/", "/sub", "/subscribe", "/clash", "/config"]
OUTPUT_DIR = "results"
WORKER_COUNT = 300
QUEUE_SIZE = 5000

class StatsManager:
    def __init__(self):
        self.stats = {
            "req": 0, "keyword": 0, "yaml_ok": 0, "found": 0, "saved": 0, "errors": 0,
            "status_codes": {}
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
        for line in f:
            ip = line.strip()
            if not ip: continue
            for port in TARGET_PORTS:
                for path in TARGET_PATHS:
                    await queue.put((ip, port, path))
    for _ in range(WORKER_COUNT):
        await queue.put(None)

async def writer_worker(write_queue):
    with open('scan_results.csv', 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(['ip', 'port', 'path', 'size', 'hash'])
        while True:
            row = await write_queue.get()
            if row is None: break
            writer.writerow(row)
            write_queue.task_done()

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
            scheme = "https" if port == 443 else "http"
            url = f"{scheme}://{ip}:{port}{path}"
            timeout = aiohttp.ClientTimeout(sock_connect=2, sock_read=3)
            async with session.get(url, timeout=timeout, ssl=False) as resp:
                await stats.update("req")
                await stats.update(resp.status, is_status_code=True)
                if resp.status == 200:
                    data = await resp.read()
                    if len(data) < 1024 * 1024:
                        text = data.decode("utf-8", errors="ignore")
                        if "proxies:" in text:
                            await stats.update("keyword")
                            try:
                                cfg = yaml.safe_load(text)
                                if isinstance(cfg, dict) and "proxies" in cfg:
                                    await stats.update("yaml_ok")
                                    await stats.update("found")
                                    h = hashlib.md5(text.encode()).hexdigest()[:8]
                                    f_path = f"{OUTPUT_DIR}/hash/{h}.yaml"
                                    async with file_lock:
                                        if not os.path.exists(f_path):
                                            with open(f_path, 'w', encoding='utf-8') as f: f.write(text)
                                            await stats.update("saved")
                                    await write_queue.put([ip, port, path, len(text), h])
                            except Exception: await stats.update("errors")
        except Exception: await stats.update("errors")
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
    with open(args.file) as f: total = sum(1 for _ in f) * len(TARGET_PORTS) * len(TARGET_PATHS)
    
    connector = aiohttp.TCPConnector(ssl=False, limit=WORKER_COUNT, ttl_dns_cache=300, 
                                     enable_cleanup_closed=True, force_close=False)
    async with aiohttp.ClientSession(connector=connector) as session:
        pbar = tqdm(total=total, desc="Scanning")
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
