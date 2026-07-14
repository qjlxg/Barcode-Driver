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

# ====================== 配置 ======================
TARGET_PORTS = [80, 443, 1333, 1999, 2052, 2053, 2082, 2083, 2087, 2095, 2096,
                2222, 3002, 3333, 4444, 5555, 6001, 6666, 7777, 8011, 8080, 8081,
                8083, 8443, 8444, 8787, 8888, 8899, 9050, 9981, 9999, 10110, 12202,
                18080, 19999, 54321, 60001, 60002]

PATHS = ["", "/", "/sub", "/subscribe", "/link", "/s/", "/api/sub",
         "/api/v1/client/subscribe", "/api/user/subscribe", "/client/subscribe",
         "/config.yaml", "/sub.yaml"]

SIGNS = ["proxies:", "proxy-groups:", "mixed-port", "vless://", "vmess://",
         "trojan://", "uuid:", "hysteria://", "hysteria2://", "hy2://",
         "tuic://", "anytls://"]

UA_LIST = [
    "ClashMeta/1.18", "sing-box/1.8", "ClashforAndroid/2.5",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
]

OUTPUT_DIR = "results"
MAX_SAVE_FILES = 2000
WORKER_COUNT = 60          # 可根据你的带宽调整（40~80 较稳）
REQUEST_TIMEOUT = 5
# =================================================

stats = {"req": 0, "saved": 0, "fail": 0}
visited_hashes = set()
content_lock = asyncio.Lock()

def cleanup_files():
    if stats["saved"] % 30 != 0:
        return
    hash_dir = f"{OUTPUT_DIR}/hash"
    if not os.path.exists(hash_dir):
        return
    files = [os.path.join(hash_dir, f) for f in os.listdir(hash_dir) if os.path.isfile(os.path.join(hash_dir, f))]
    if len(files) > MAX_SAVE_FILES:
        files.sort(key=os.path.getmtime)
        for f in files[:len(files) - MAX_SAVE_FILES]:
            try:
                os.remove(f)
            except:
                pass

def load_history():
    if os.path.exists('scan_results.csv'):
        try:
            with open('scan_results.csv', 'r', encoding='utf-8') as f:
                reader = csv.reader(f)
                next(reader, None)
                for row in reader:
                    if len(row) >= 1:
                        visited_hashes.add(row[0])
        except:
            pass

def get_addr(item: str):
    """支持 IPv6 和 IPv4:port"""
    try:
        if item.startswith("["):  # IPv6
            host = item.split("]")[0] + "]"
            port = int(item.split("]:")[1]) if "]:" in item else 443
            return host, port
        elif ":" in item and not item.replace(".", "").replace(":", "").isdigit():  # IPv4:port
            h, p = item.rsplit(":", 1)
            return h, int(p)
        elif ":" in item:  # 纯 IPv6 无端口
            return item, 443
        return item, None
    except:
        return item, None

async def writer_worker(write_queue: asyncio.Queue):
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    csv_path = 'scan_results.csv'
    exists = os.path.exists(csv_path)
    with open(csv_path, 'a', newline='', encoding='utf-8') as csvfile:
        writer = csv.writer(csvfile)
        if not exists:
            writer.writerow(['hash', 'url', 'type'])
        while True:
            row = await write_queue.get()
            if row is None:
                break
            writer.writerow(row)
            if stats["saved"] % 20 == 0:
                csvfile.flush()
            write_queue.task_done()

async def scanner_worker(queue: asyncio.Queue, write_queue: asyncio.Queue, session: aiohttp.ClientSession, pbar: tqdm):
    try:
        while True:
            item = await queue.get()
            if item is None:
                break

            host, port = item
            schemes = ["https", "http"] if port in [443, 2053, 2083, 2087, 2096, 8443, 8444] else ["http", "https"]
            found = False

            for scheme in schemes:
                url = f"{scheme}://{host}:{port}"
                try:
                    async with session.get(f"{url}{path}",  # path 来自外层循环
                        headers={"User-Agent": random.choice(UA_LIST), "Connection": "close"},
                        timeout=aiohttp.ClientTimeout(total=REQUEST_TIMEOUT),
                        ssl=False,
                        allow_redirects=False
                    ) as resp:
                        stats["req"] += 1
                        if resp.status == 200:
                            text = (await resp.content.read(350 * 1024)).decode("utf-8", errors="ignore")
                            low = text.lower()
                            hit = any(s in low for s in SIGNS)

                            # Base64 尝试
                            if not hit and 50 < len(text) < 250000:
                                try:
                                    d = "".join(text.split()).replace("-", "+").replace("_", "/")
                                    d += "=" * (4 - len(d) % 4)
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
                                        await write_queue.put([h, f"{url}{path}", 'found'])
                                found = True
                                break
                except:
                    continue

            if not found:
                stats["fail"] += 1

            queue.task_done()
            pbar.update(1)
            pbar.set_postfix(Req=stats["req"], Saved=stats["saved"], Fail=stats["fail"])
    except asyncio.CancelledError:
        pass

async def main():
    parser = argparse.ArgumentParser(description="订阅链接扫描器")
    parser.add_argument("--file", required=True, help="IP 列表文件")
    args = parser.parse_args()

    load_history()

    if not os.path.exists(args.file):
        print(f"Error: 文件 {args.file} 不存在")
        return

    with open(args.file, 'r', encoding='utf-8') as f:
        lines = [l.strip() for l in f if l.strip()]

    print(f"[*] 已加载 {len(lines)} 个目标 IP")

    # 计算总任务量
    total_tasks = 0
    for item in lines:
        _, p = get_addr(item)
        total_tasks += len(PATHS) if p else len(TARGET_PORTS) * len(PATHS)

    print(f"[*] 预计总任务量: {total_tasks:,}")

    queue = asyncio.Queue(maxsize=10000)
    write_queue = asyncio.Queue()

    pbar = tqdm(total=total_tasks, desc="Scanning", unit="task")

    async with aiohttp.ClientSession(
        connector=aiohttp.TCPConnector(ssl=False, limit=WORKER_COUNT*2, force_close=True, ttl_dns_cache=300)
    ) as session:

        workers = [asyncio.create_task(scanner_worker(queue, write_queue, session, pbar)) for _ in range(WORKER_COUNT)]
        writer_task = asyncio.create_task(writer_worker(write_queue))

        # 填充队列
        for item in lines:
            host, port = get_addr(item)
            if port:
                for path in PATHS:
                    await queue.put((host, port))
            else:
                for pv in TARGET_PORTS:
                    for path in PATHS:
                        await queue.put((host, pv))

        # 结束信号
        for _ in range(WORKER_COUNT):
            await queue.put(None)

        # 优雅退出
        stop_event = asyncio.Event()
        loop = asyncio.get_event_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                loop.add_signal_handler(sig, stop_event.set)
            except:
                pass

        await asyncio.wait(
            [asyncio.gather(*workers, return_exceptions=True), asyncio.create_task(stop_event.wait())],
            return_when=asyncio.FIRST_COMPLETED
        )

        for w in workers:
            w.cancel()

        await write_queue.put(None)
        await writer_task
        pbar.close()

    print(f"\n[*] 扫描完成！保存 {stats['saved']} 个有效配置")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[!] 用户中断")
        sys.exit(0)
