import aiohttp
import asyncio
import hashlib
import os
import csv
import argparse
import random
import sys

# --- 配置 ---
PATHS = ["", "/", "/sub", "/subscribe", "/link", "/s/", "/api/sub", "/api/v1/client/subscribe",
         "/api/user/subscribe", "/client/subscribe", "/config.yaml", "/sub.yaml"]

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

async def scanner_worker(queue: asyncio.Queue, session: aiohttp.ClientSession):
    while True:
        item = await queue.get()
        if item is None:
            queue.task_done()
            break

        host, port, path = item
        url = f"http://{host}:{port}{path}"

        try:
            # 强化请求头：模拟一个从该域名首页跳转过来的正常浏览器请求
            headers = {
                "User-Agent": UA,
                "Host": host,
                "Referer": f"http://{host}:{port}/",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
                "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
                "Connection": "keep-alive"
            }
            
            async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                # 打印状态码和服务器返回的原因短语
                sys.stdout.write(f"[DEBUG] URL: {url} | Status: {resp.status} | Reason: {resp.reason}\n")
                sys.stdout.flush()
                
        except Exception as e:
            sys.stdout.write(f"[ERROR] URL: {url} | 异常: {type(e).__name__}\n")
            sys.stdout.flush()
        finally:
            queue.task_done()

async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--file", required=True)
    args = parser.parse_args()

    with open(args.file, 'r', encoding='utf-8') as f:
        lines = [l.strip() for l in f if l.strip()]

    queue = asyncio.Queue()
    async with aiohttp.ClientSession() as session:
        workers = [asyncio.create_task(scanner_worker(queue, session)) for _ in range(10)]
        
        for item in lines:
            host, port = item.rsplit(":", 1) if ":" in item else (item, 8080)
            for path in PATHS:
                await queue.put((host, int(port), path))
        
        for _ in range(10): await queue.put(None)
        await asyncio.gather(*workers)

if __name__ == "__main__":
    asyncio.run(main())
