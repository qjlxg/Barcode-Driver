import aiohttp, asyncio, yaml, hashlib, os, csv, argparse, base64, time
from urllib.parse import urlparse

# --- 配置 ---
TARGET_PORTS = [443, 80, 8080, 8443, 2096, 2053, 2083, 2087, 12202]
HTTPS_PORTS = [443, 8443, 2096, 2053, 2083, 2087, 12202]
TARGET_PROTOCOLS = ["vless://", "hysteria://", "hysteria2://", "tuic://", "anytls://"]
# 去掉 ROOT_PATHS，逻辑内嵌在 producer 中
SUB_PATHS = ["/sub", "/s/", "/subscribe", "/link", "/api/sub", "/getsub", "/clash", "/config", "/config.yaml", "/sub.yaml", "/subscription", "/client/subscribe"]
WORKER_COUNT = 100
MAX_RESPONSE_SIZE = 300 * 1024 
OUTPUT_DIR = "results"

class GlobalState:
    def __init__(self):
        self.visited_hashes = set()
        self.known_manifest = set()
        self.total_tasks = 0
        self.file_lock = asyncio.Lock()
        self.stats = {"req": 0, "yaml": 0, "b64": 0, "saved": 0, "done": 0, "timeout": 0, "error": 0}
        self.stats_lock = asyncio.Lock()
        
        if os.path.exists(OUTPUT_DIR):
            for f in os.listdir(OUTPUT_DIR):
                if f.endswith((".yaml", ".b64")): self.visited_hashes.add(f.rsplit(".", 1)[0])
        if os.path.exists('scan_manifest.csv'):
            with open('scan_manifest.csv', 'r') as f:
                for row in csv.reader(f):
                    if row: self.known_manifest.add(row[0])
state = GlobalState()

def is_valid_asset(text):
    if "<html" in text.lower()[:200] and "://" not in text:
        return False, None

    if any(x in text.lower() for x in ["proxies:", "proxy-providers:", "proxy-groups:", "mixed-port:", "allow-lan:", "mode:"]):
        try:
            cfg = yaml.safe_load(text)
            if isinstance(cfg, dict):
                if (isinstance(cfg.get("proxies"), list) and any(isinstance(x, dict) and ("server" in x or "type" in x) for x in cfg["proxies"])) or \
                   isinstance(cfg.get("proxy-providers"), dict):
                    return True, "yaml"
        except Exception: pass

    try:
        raw = text.strip().replace("-", "+").replace("_", "/")
        pad = len(raw) % 4
        if pad: raw += "=" * (4 - pad)
        decoded = base64.b64decode(raw, validate=False).decode(errors="ignore")
        if len(decoded) > 50 and any(p in decoded for p in TARGET_PROTOCOLS):
            return True, "b64"
    except Exception: pass
    return False, None

async def writer_worker(save_queue):
    with open('scan_results.csv', 'a', newline='') as f1, open('scan_manifest.csv', 'a', newline='') as f2:
        w1, w2 = csv.writer(f1), csv.writer(f2)
        while True:
            item = await save_queue.get()
            if item is None: break
            tag, data = item
            if tag == "res": w1.writerow(data)
            else: w2.writerow(data)
            save_queue.task_done()

async def scanner_worker(queue, save_queue, session):
    while True:
        task = await queue.get()
        if task is None: queue.task_done(); break
        host, port, path, is_root = task
        proto = "https" if port in HTTPS_PORTS else "http"
        url = f"{proto}://{host}:{port}{path}"
        
        if url in state.known_manifest:
            queue.task_done(); continue

        try:
            async with session.get(url, timeout=4, ssl=False, allow_redirects=False) as resp:
                async with state.stats_lock: state.stats["req"] += 1
                if resp.status in [301, 302] and is_root:
                    loc = resp.headers.get("Location", "")
                    loc_path = urlparse(loc).path
                    # 匹配逻辑优化：覆盖更多子路径变体
                    if any(loc_path.startswith(x) for x in SUB_PATHS):
                        async with state.stats_lock: state.total_tasks += 1
                        await queue.put((host, port, loc_path, False))
                if resp.status == 200:
                    data = await resp.content.read(MAX_RESPONSE_SIZE)
                    text = data.decode("utf-8", errors="ignore")
                    valid, ftype = is_valid_asset(text)
                    if valid:
                        async with state.stats_lock: state.stats[ftype] += 1
                        h = hashlib.md5(text.encode()).hexdigest()[:12]
                        async with state.file_lock:
                            if h not in state.visited_hashes:
                                state.visited_hashes.add(h)
                                with open(f"{OUTPUT_DIR}/{h}.{ftype}", 'w', encoding='utf-8') as f: f.write(text)
                                await save_queue.put(("res", [h, url, resp.headers.get("Server", "")]))
                                await save_queue.put(("man", [url, f"{h}.{ftype}"]))
                                state.known_manifest.add(url)
                                async with state.stats_lock: state.stats["saved"] += 1
                        if is_root:
                            for sp in SUB_PATHS:
                                async with state.stats_lock: state.total_tasks += 1
                                await queue.put((host, port, sp, False))
        except asyncio.TimeoutError:
            async with state.stats_lock: state.stats["timeout"] += 1
        except aiohttp.ClientError:
            async with state.stats_lock: state.stats["error"] += 1
        finally: 
            queue.task_done()
            async with state.stats_lock: state.stats["done"] += 1

async def stats_reporter():
    start_time = time.time()
    try:
        while True:
            await asyncio.sleep(10)
            async with state.stats_lock:
                elapsed = time.time() - start_time
                done = state.stats["done"]
                speed = done / elapsed if elapsed > 0 else 0
                remaining = max(0, state.total_tasks - done)
                rem = remaining / speed if speed > 0 else 0
                print(f"[监控] 任务:{done}/{state.total_tasks} | 发现:{state.stats['saved']} | 错误:{state.stats['error']} | 速度:{speed:.1f}t/s | ETA:{rem/60:.1f}m")
    except asyncio.CancelledError: pass

async def producer(args, queue):
    unique_hosts = set()
    with open(args.file) as f:
        for line in f:
            host = line.strip()
            if host and host not in unique_hosts:
                unique_hosts.add(host)
                for p in TARGET_PORTS:
                    async with state.stats_lock: state.total_tasks += 1
                    await queue.put((host, p, "", True))

async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--file", required=True)
    args = parser.parse_args()
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    
    queue = asyncio.Queue(maxsize=5000)
    save_queue = asyncio.Queue()
    
    connector = aiohttp.TCPConnector(ssl=False, limit=300, limit_per_host=10, ttl_dns_cache=300)
    
    producer_task = asyncio.create_task(producer(args, queue))
    reporter_task = asyncio.create_task(stats_reporter())
    
    async with aiohttp.ClientSession(connector=connector) as session:
        workers = [asyncio.create_task(scanner_worker(queue, save_queue, session)) for _ in range(WORKER_COUNT)]
        writer = asyncio.create_task(writer_worker(save_queue))
        
        await producer_task
        await queue.join()
        for _ in range(WORKER_COUNT): await queue.put(None)
        await asyncio.gather(*workers)
        await save_queue.join()
        await save_queue.put(None)
        await writer
        
    reporter_task.cancel()
    try: await reporter_task
    except asyncio.CancelledError: pass
    print(f"扫描结束 | 最终统计: {state.stats}")

if __name__ == "__main__":
    asyncio.run(main())
