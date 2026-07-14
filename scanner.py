import aiohttp
import asyncio
import argparse
import sys

async def scanner_worker(queue: asyncio.Queue, session: aiohttp.ClientSession):
    while True:
        item = await queue.get()
        if item is None:
            queue.task_done()
            break

        host, port, path = item
        # 强制使用 HTTPS 协议进行尝试
        url = f"https://{host}:{port}{path}"

        try:
            # 剥离 Host 中的端口号，很多面板只接受域名/IP作为 Host
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                "Host": host, 
                "Connection": "close"
            }
            
            async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=5), ssl=False) as resp:
                sys.stdout.write(f"[DEBUG] URL: {url} | Status: {resp.status}\n")
                sys.stdout.flush()
        except Exception as e:
            sys.stdout.write(f"[ERROR] URL: {url} | 错误: {type(e).__name__}\n")
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
    # 允许连接异常
    async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=False)) as session:
        workers = [asyncio.create_task(scanner_worker(queue, session)) for _ in range(10)]
        for item in lines:
            host, port = item.rsplit(":", 1) if ":" in item else (item, 8080)
            for path in ["", "/sub", "/subscribe"]: # 先测试这三个核心路径
                await queue.put((host, int(port), path))
        for _ in range(10): await queue.put(None)
        await asyncio.gather(*workers)

if __name__ == "__main__":
    asyncio.run(main())
