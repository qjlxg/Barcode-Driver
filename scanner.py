import aiohttp
import asyncio
import yaml
import hashlib
import os
import csv
import argparse
from tqdm import tqdm

# 配置
TARGET_PORTS = [80, 443, 7890, 8080, 8888, 9090]
TARGET_PATHS = ["/", "/sub", "/subscribe", "/clash", "/config", "/api/v1/client/subscribe", "/api/sub"]
OUTPUT_DIR = "results"
WORKER_COUNT = 300
QUEUE_SIZE = 5000
SAMPLE_LIMIT = 50

class StatsManager:
    def __init__(self):
        self.stats = {
            "req": 0, "keyword_proxies": 0, "keyword_base64": 0, "yaml_ok": 0, "saved": 0, "errors": 0, "status_codes": {}
        }
        self.samples_collected = 0
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
    for _ in range(WORKER_COUNT): await queue.put(None)

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
            url = f"{'https' if port == 443 else 'http'}://{ip}:{port}{path}"
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=5), ssl=False) as resp:
                await stats.update("req")
                await stats.update(resp.status, is_status_code=True)
                
                if resp.status == 200:
                    cl = resp.headers.get("Content-Length")
                    if cl and int(cl) > 1024 * 1024: continue # 防阻塞大文件
                    
                    data = await resp.read()
                    text = data.decode("utf-8", errors="ignore")
                    lower_text = text.lower()
                    
                    # 1. 指纹采集与特征分析
                    async with stats.lock:
                        if stats.samples_collected < SAMPLE_LIMIT:
                            with open("samples.txt", "a", encoding="utf8") as f:
                                f.write(f"\nURL:{url}\nTYPE:{resp.headers.get('content-type')}\n{text[:500]}\n================\n")
                            stats.samples_collected += 1
                    
                    # 2. 多重指纹匹配逻辑
                    match_count = sum(1 for f in ["proxies:", "proxy-groups:", "uuid:", "- name:", "geox-url:"] if f in lower_text)
                    if match_count >= 1:
                        await stats.update("keyword_proxies")
                        try:
                            cfg = yaml.safe_load(text)
                            if isinstance(cfg, dict) and "proxies" in cfg:
                                await stats.update("yaml_ok")
                                h = hashlib.md5(text.encode()).hexdigest()[:8]
                                f_path = f"{OUTPUT_DIR}/hash/{h}.yaml"
                                async with file_lock:
                                    if not os.path.exists(f_path):
                                        with open(f_path, 'w', encoding='utf-8') as f: f.write(text)
                                        await stats.update("saved")
                                await write_queue.put([ip, port, path, len(text), h])
                        except: await stats.update("errors")
                    elif any(k in lower_text for k in ["vmess://", "vless://", "ss://"]):
                        await stats.update("keyword_base64")
        except: await stats.update("errors")
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
    async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=False, limit=WORKER_COUNT)) as session:
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
