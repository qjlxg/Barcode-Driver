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

# --- 配置 ---
TARGET_PORTS = [80, 443, 1333, 1999, 2052, 2053, 2082, 2083, 2087, 2095, 2096,
                2222, 3002, 3333, 4444, 5555, 6001, 6666, 7777, 8011, 8080, 8081,
                8083, 8443, 8444, 8787, 8888, 8899, 9050, 9981, 9999, 10110, 12202,
                18080, 19999, 54321, 60001, 60002]

PATHS = ["", "/", "/sub", "/subscribe", "/link", "/s/", "/api/sub", "/api/v1/client/subscribe",
         "/api/user/subscribe", "/client/subscribe", "/config.yaml", "/sub.yaml"]

# 确保 SIGNS 格式干净，避免任何编码干扰
SIGNS = ["proxies:", "proxy-groups:", "mixed-port", "vless://", "vmess://", "trojan://", "uuid:",
         "hysteria://", "hysteria2://", "hy2://", "tuic://", "anytls://"]

UA_LIST = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
]

OUTPUT_DIR = "results"
REQUEST_TIMEOUT = 5

async def scanner_worker(queue, write_queue, session, pbar):
    while True:
        item = await queue.get()
        if item is None:
            queue.task_done()
            break

        host, port, path = item
        scheme = "https" if port in [443, 2053, 2083, 2087, 2096, 8443] else "http"
        url = f"{scheme}://{host}:{port}{path}"

        try:
            async with session.get(url, headers={"User-Agent": random.choice(UA_LIST)}, 
                                   timeout=aiohttp.ClientTimeout(total=REQUEST_TIMEOUT), 
                                   ssl=False, allow_redirects=True) as resp:
                if resp.status == 200:
                    text = await resp.text(errors="ignore")
                    low = text.lower()
                    
                    # --- 强制日志输出 ---
                    print(f"\n[DEBUG] 成功请求: {url}")
                    print(f"[DEBUG] 内容长度: {len(text)}")
                    print(f"[DEBUG] 前100字符: {text[:100].replace(chr(10), ' ')}")
                    
                    hit = any(s in low for s in SIGNS)
                    print(f"[DEBUG] 命中结果: {hit}")
                    # --------------------

                    if hit:
                        h = hashlib.md5(text.encode("utf-8")).hexdigest()[:12]
                        os.makedirs(f"{OUTPUT_DIR}/hash", exist_ok=True)
                        with open(f"{OUTPUT_DIR}/hash/{h}.yaml", 'w', encoding='utf-8') as f:
                            f.write(text)
                        await write_queue.put([h, url, 'found'])
        except Exception as e:
            pass
        finally:
            queue.task_done()
            pbar.update(1)

async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--file", required=True)
    args = parser.parse_args()

    with open(args.file, 'r', encoding='utf-8') as f:
        lines = [l.strip() for l in f if l.strip()]

    queue = asyncio.Queue()
    write_queue = asyncio.Queue()
    
    async with aiohttp.ClientSession() as session:
        pbar = tqdm(total=len(lines) * len(PATHS))
        workers = [asyncio.create_task(scanner_worker(queue, write_queue, session, pbar)) for _ in range(20)]
        
        for item in lines:
            host, port = item.rsplit(":", 1) if ":" in item else (item, 443)
            for path in PATHS:
                await queue.put((host, int(port), path))
        
        for _ in range(20): await queue.put(None)
        await asyncio.gather(*workers)
        pbar.close()

if __name__ == "__main__":
    asyncio.run(main())
