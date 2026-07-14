import aiohttp
import asyncio
import hashlib
import os
import csv
import argparse
import random
import sys
from typing import List, Tuple

# --- 配置 ---
PATHS = ["", "/", "/sub", "/subscribe", "/link", "/s/", "/api/sub", "/api/v1/client/subscribe",
         "/api/user/subscribe", "/client/subscribe", "/config.yaml", "/sub.yaml"]

SIGNS = ["proxies:", "proxy-groups:", "mixed-port", "vless://", "vmess://", "trojan://", "uuid:",
         "hysteria://", "hysteria2://", "hy2://", "tuic://", "anytls://"]

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

stats = {"req": 0, "saved": 0, "fail": 0}

async def fetch(session: aiohttp.ClientSession, url: str, host: str):
    headers = {"User-Agent": UA, "Host": host, "Connection": "close"}
    try:
        # 尝试请求
        async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=5), ssl=False) as resp:
            stats["req"] += 1
            if resp.status == 200:
                text = (await resp.content.read(350 * 1024)).decode("utf-8", errors="ignore")
                if any(s in text.lower() for s in SIGNS):
                    h = hashlib.md5(text.encode("utf-8")).hexdigest()[:12]
                    os.makedirs("results/hash", exist_ok=True)
                    with open(f"results/hash/{h}.yaml", 'w', encoding='utf-8') as f: f.write(text)
                    stats["saved"] += 1
                    return True
            return False
    except:
        return False

async def scanner_worker(queue: asyncio.Queue, session: aiohttp.ClientSession):
    while True:
        item = await queue.get()
        if item is None:
            queue.task_done()
            break

        host, port, path = item
        # 优先尝试 HTTPS，失败则回退 HTTP
        success = await fetch(session, f"https://{host}:{port}{path}", host)
        if not success:
            await fetch(session, f"http://{host}:{port}{path}", host)
            
        queue.task_done()

async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--file", required=True)
    args = parser.parse_args()

    with open(args.file, 'r', encoding='utf-8') as f:
        lines = [l.strip() for l in f if l.strip()]

    queue = asyncio.Queue()
    async with aiohttp.ClientSession() as session:
        workers = [asyncio.create_task(scanner_worker(queue, session)) for _ in range(20)]
        for item in lines:
            host, port = item.rsplit(":", 1) if ":" in item else (item, 8080)
            for path in PATHS:
                await queue.put((host, int(port), path))
        
        for _ in range(20): await queue.put(None)
        await asyncio.gather(*workers)

    print(f"\n[+] 扫描完成！请求: {stats['req']} | 保存: {stats['saved']} | 失败: {stats['fail']}")

if __name__ == "__main__":
    asyncio.run(main())
