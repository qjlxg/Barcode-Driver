import aiohttp
import asyncio
import hashlib
import os
import csv
import argparse
import base64
import random
import signal
import sys
from tqdm import tqdm

# 配置 - 尽量保持和原脚本一致
TARGET_PORTS = [80, 443, 1333, 1999, 2052, 2053, 2082, 2083, 2087, 2095, 2096,
                2222, 3002, 3333, 4444, 5555, 6001, 6666, 7777, 8011, 8080, 8081,
                8083, 8443, 8444, 8787, 8888, 8899, 9050, 9981, 9999, 10110, 12202,
                18080, 19999, 54321, 60001, 60002]

PATHS = ["", "/", "/sub", "/subscribe", "/link", "/s/", "/api/sub", "/api/v1/client/subscribe",
         "/api/user/subscribe", "/client/subscribe", "/config.yaml", "/sub.yaml"]

SIGNS = ["proxies:", "proxy-groups:", "mixed-port", "vless://", "vmess://", "trojan://", "uuid:",
         "hysteria://", "hysteria2://", "hy2://", "tuic://", "anytls://"]

UA_LIST = ["ClashMeta/1.18", "sing-box/1.8", "ClashforAndroid/2.5",
           "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"]

OUTPUT_DIR = "results"
MAX_SAVE_FILES = 2000
WORKER_COUNT = 40
REQUEST_TIMEOUT = 8   # 稍微放宽

stats = {"req": 0, "saved": 0, "fail": 0}
visited_hashes = set()
content_lock = asyncio.Lock()

def cleanup_files():
    if stats["saved"] % 20 != 0: return
    hash_dir = f"{OUTPUT_DIR}/hash"
    if not os.path.exists(hash_dir): return
    files = [os.path.join(hash_dir, f) for f in os.listdir(hash_dir) if os.path.isfile(os.path.join(hash_dir, f))]
    if len(files) > MAX_SAVE_FILES:
        files.sort(key=os.path.getmtime)
        for f in files[:len(files) - MAX_SAVE_FILES]:
            try: os.remove(f)
            except: pass

def load_history():
    if os.path.exists('scan_results.csv'):
        try:
            with open('scan_results.csv', 'r', encoding='utf-8') as f:
                reader = csv.reader(f)
                next(reader, None)
                for row in reader:
                    if len(row) >= 1: visited_hashes.add(row[0])
        except: pass

def get_addr(item):
    try:
        if item.startswith("["):
            host = item.split("]")[0] + "]"
            port = int(item.split("]:")[1]) if "]:" in item else 443
            return host, port
        elif ":" in item:
            h, p = item.rsplit(":", 1)
            return h, int(p)
        return item, None
    except:
        return item, None

async def writer_worker(write_queue):
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    csv_path = 'scan_results.csv'
    exists = os.path.exists(csv_path)
    with open(csv_path, 'a', newline='', encoding='utf-8') as csvfile:
        writer = csv.writer(csvfile)
        if not exists: writer.writerow(['hash', 'url', 'type'])
        while True:
            row = await write_queue.get()
            if row is None: break
            writer.writerow(row)
            write_queue.task_done()

async def scanner_worker(queue, write_queue, session, pbar):
    while True:
        item = await queue.get()
        if item is None:
            break
        host, port, path = item
        schemes = ["https", "http"] if port in [443, 2053, 2083, 2087, 2096, 8443, 8444] else ["http", "https"]
        found = False

        for scheme in schemes:
            try:
                url = f"{scheme}://{host}:{port}{path}"
                async with session.get(url, headers={"User-Agent": random.choice(UA_LIST)},
                                      timeout=aiohttp.ClientTimeout(total=REQUEST_TIMEOUT),
                                      ssl=False, allow_redirects=False) as resp:
                    stats["req"] += 1
                    if resp.status == 200:
                        text = (await resp.content.read(400 * 1024)).decode("utf-8", errors="ignore")
                        low = text.lower()
                        hit = any(s in low for s in SIGNS)

                        if not hit and 20 < len(text) < 300000:
                            try:
                                d = "".join(text.split()).replace("-", "+").replace("_", "/")
                                padding = len(d) % 4
                                if padding: d += "=" * (4 - padding)
                                decoded = base64.b64decode(d, validate=False).decode("utf-8", errors="ignore")
                                hit = any(s in decoded.lower() for s in SIGNS if "://" in s)
                            except:
                                pass

                        if hit:
                            h = hashlib.md5(text.encode("utf-8")).hexdigest()[:12]
                            async with content_lock:
                                if h not in visited_hashes:
                                    cleanup_files()
                                    os.makedirs(f"{OUTPUT_DIR}/hash", exist_ok=True)
                                    ext = "yaml" if "proxies:" in low else "txt"
                                    with open(f"{OUTPUT_DIR}/hash/{h}.{ext}", 'w', encoding='utf-8') as f:
                                        f.write(text)
                                    stats["saved"] += 1
                                    visited_hashes.add(h)
                                    await write_queue.put([h, url, 'found'])
                                    print(f"\n[+] 发现有效配置: {url}")
                            found = True
                            break
            except:
                continue

        if not found:
            stats["fail"] += 1

        queue.task_done()
        pbar.update(1)
        if stats["req"] % 200 == 0:
            pbar.set_postfix(Req=stats["req"], Saved=stats["saved"], Fail=stats["fail"])

async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--file", required=True)
    args = parser.parse_args()

    load_history()
    if not os.path.exists(args.file):
        print(f"Error: 文件 {args.file} 不存在")
        return

    with open(args.file, 'r', encoding='utf-8') as f:
        lines = [l.strip() for l in f if l.strip()]

    print(f"[*] 已加载 {len(lines)} 个目标 IP")

    total_tasks = sum(len(PATHS) if get_addr(l)[1] else len(TARGET_PORTS)*len(PATHS) for l in lines)
    print(f"[*] 预计任务量: {total_tasks}")

    queue = asyncio.Queue(maxsize=10000)
    write_queue = asyncio.Queue()

    pbar = tqdm(total=total_tasks, desc="Scanning", unit="task")

    async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=False, limit=WORKER_COUNT*2, force_close=True)) as session:
        workers = [asyncio.create_task(scanner_worker(queue, write_queue, session, pbar)) for _ in range(WORKER_COUNT)]
        writer_task = asyncio.create_task(writer_worker(write_queue))

        for item in lines:
            host, port = get_addr(item)
            if port:
                for path in PATHS:
                    await queue.put((host, port, path))
            else:
                for pv in TARGET_PORTS:
                    for path in PATHS:
                        await queue.put((host, pv, path))

        for _ in range(WORKER_COUNT):
            await queue.put(None)

        await asyncio.gather(*workers, return_exceptions=True)
        await write_queue.put(None)
        await writer_task
        pbar.close()

    print(f"\n[*] 扫描结束 → 总请求: {stats['req']} | 保存: {stats['saved']} | 失败: {stats['fail']}")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[!] 已停止")
        sys.exit(0)