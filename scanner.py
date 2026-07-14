import aiohttp
import asyncio
import hashlib
import os
import csv
import argparse
import base64
import random
import signal
from tqdm import tqdm
from typing import List, Tuple

# --- 配置 ---
TARGET_PORTS = [80, 443, 1333, 1999, 2052, 2053, 2082, 2083, 2087, 2095, 2096,
                2222, 3002, 3333, 4444, 5555, 6001, 6666, 7777, 8011, 8080, 8081,
                8083, 8443, 8444, 8787, 8888, 8899, 9050, 9981, 9999, 10110, 12202,
                18080, 19999, 54321, 60001, 60002]

PATHS = ["", "/", "/sub", "/subscribe", "/link", "/s/", "/api/sub", "/api/v1/client/subscribe",
         "/api/user/subscribe", "/client/subscribe", "/config.yaml", "/sub.yaml"]

SIGNS = ["proxies:", "proxy-groups:", "mixed-port", "vless://", "vmess://", "trojan://", "uuid:",
         "hysteria://", "hysteria2://", "hy2://", "tuic://", "anytls://"]

UA_LIST = [
    "ClashMeta/1.18", "sing-box/1.8", "ClashforAndroid/2.5",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
]

OUTPUT_DIR = "results"
MAX_SAVE_FILES = 2000
WORKER_COUNT = 28          # 建议 60~120，根据你的服务器带宽调整
REQUEST_TIMEOUT = 5

stats = {"req": 0, "saved": 0, "fail": 0}
# 改为记录内容指纹，全局去重
visited_content_hashes = set()
existing_urls = set()

def cleanup_files():
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
    # 读取已有的 scan_results.csv 建立全局指纹库，防止重复写入
    if os.path.exists('scan_results.csv'):
        try:
            with open('scan_results.csv', 'r', encoding='utf-8') as f:
                reader = csv.reader(f)
                next(reader, None)
                for row in reader:
                    if len(row) >= 2:
                        visited_content_hashes.add(row[0])
                        existing_urls.add(row[1])
        except:
            pass

async def writer_worker(write_queue: asyncio.Queue):
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    csv_path = 'scan_results.csv'
    with open(csv_path, 'a', newline='', encoding='utf-8') as csvfile:
        writer = csv.writer(csvfile)
        if os.path.getsize(csv_path) == 0:
            writer.writerow(['hash', 'url', 'type'])
        while True:
            row = await write_queue.get()
            if row is None:
                break
            # 只有内容指纹是新的，才写入 CSV
            if row[0] not in visited_content_hashes:
                writer.writerow(row)
                csvfile.flush()
                visited_content_hashes.add(row[0])
            write_queue.task_done()

async def scanner_worker(queue: asyncio.Queue, write_queue: asyncio.Queue, session: aiohttp.ClientSession, pbar: tqdm):
    while True:
        item = await queue.get()
        if item is None:
            queue.task_done()
            break

        host, port, path = item
        scheme = "https" if port in [443, 2053, 2083, 2087, 2096, 8443] else "http"
        url = f"{scheme}://{host}:{port}{path}"

        try:
            async with session.get(
                url,
                headers={"User-Agent": random.choice(UA_LIST)},
                timeout=aiohttp.ClientTimeout(total=REQUEST_TIMEOUT),
                ssl=False,
                allow_redirects=True
            ) as resp:
                stats["req"] += 1
                if resp.status == 200:
                    text = (await resp.content.read(350 * 1024)).decode("utf-8", errors="ignore")
                    
                    # --- 插入调试逻辑 (保留原结构) ---
                    print(f"[DEBUG] URL: {url} | 长度: {len(text)} | 预览: {text[:100].strip()}")
                    # ------------------------------

                    low = text.lower()
                    hit = any(s in low for s in SIGNS)

                    # Base64 尝试解码
                    if not hit and 50 < len(text) < 250000:
                        try:
                            decoded_str = "".join(text.split()).replace("-", "+").replace("_", "/")
                            padding = len(decoded_str) % 4
                            if padding:
                                decoded_str += "=" * (4 - padding)
                            decoded = base64.b64decode(decoded_str, validate=False).decode("utf-8", errors="ignore")
                            hit = any(s in decoded.lower() for s in SIGNS if "://" in s)
                        except:
                            pass

                    if hit:
                        # 生成内容唯一指纹
                        h = hashlib.md5(text.encode("utf-8")).hexdigest()[:12]

                        # 核心去重：如果该内容指纹已处理过，直接跳过
                        if h not in visited_content_hashes and url not in existing_urls:
                            cleanup_files()

                            ext = ".yaml" if "proxies:" in low or "proxy-groups:" in low else ".txt"
                            save_path = f"{OUTPUT_DIR}/hash/{h}{ext}"
                            with open(save_path, 'w', encoding='utf-8') as f:
                                f.write(text)

                            stats["saved"] += 1
                            await write_queue.put([h, url, 'found'])
        except asyncio.TimeoutError:
            stats["fail"] += 1
        except Exception:
            stats["fail"] += 1
        finally:
            queue.task_done()
            pbar.update(1)
            if stats["req"] % 300 == 0:
                pbar.set_postfix({"Req": stats["req"], "Saved": stats["saved"], "Fail": stats["fail"]})

async def main():
    try:
        signal.signal(signal.SIGALRM, lambda s, f: os._exit(0))
        signal.alarm(19800)
    except:
        pass

    parser = argparse.ArgumentParser(description="Proxy Subscription Scanner")
    parser.add_argument("--file", required=True, help="Input file (alive_ips.txt)")
    args = parser.parse_args()

    os.makedirs(f"{OUTPUT_DIR}/hash", exist_ok=True)
    load_history()

    with open(args.file, 'r', encoding='utf-8') as f:
        lines = [l.strip() for l in f if l.strip()]

    total = 0
    for l in lines:
        if ":" in l:
            total += len(PATHS)
        else:
            total += len(TARGET_PORTS) * len(PATHS)

    queue: asyncio.Queue = asyncio.Queue(maxsize=8000)
    write_queue: asyncio.Queue = asyncio.Queue()

    async with aiohttp.ClientSession(
        connector=aiohttp.TCPConnector(ssl=False, limit=WORKER_COUNT*2, ttl_dns_cache=300, force_close=False),
        headers={"Connection": "close"}
    ) as session:
        pbar = tqdm(total=total, desc="Scanning", unit="task", mininterval=3)

        workers = [asyncio.create_task(scanner_worker(queue, write_queue, session, pbar)) for _ in range(WORKER_COUNT)]
        writer_task = asyncio.create_task(writer_worker(write_queue))

        for item in lines:
            if ":" in item:
                try:
                    host, port_str = item.rsplit(":", 1)
                    port = int(port_str)
                    for path in PATHS:
                        await queue.put((host, port, path))
                except:
                    continue
            else:
                for port in TARGET_PORTS:
                    for path in PATHS:
                        await queue.put((item, port, path))

        for _ in range(WORKER_COUNT):
            await queue.put(None)

        await asyncio.gather(*workers)
        await write_queue.put(None)
        await writer_task
        pbar.close()

    print(f"\n[+] 扫描完成！请求: {stats['req']} | 保存: {stats['saved']} | 失败: {stats['fail']}")

if __name__ == "__main__":
    asyncio.run(main())
