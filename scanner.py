import aiohttp
import asyncio
import ipaddress
import yaml
import hashlib
import os

# --- 配置区域 ---
TARGET_CIDR = "45.124.0.0/16"
TARGET_PORTS = [80, 443, 7890, 8080, 8888, 9090]
TARGET_PATHS = ["/", "/sub", "/subscribe", "/clash", "/config"]
OUTPUT_DIR = "results"
WORKER_COUNT = 100  # 固定 worker 数量
# ----------------

# 全局去重集合
seen_hashes = set()

async def worker(queue, session):
    while True:
        # 从队列获取任务
        ip, port, path = await queue.get()
        try:
            for scheme in ["http", "https"]:
                url = f"{scheme}://{ip}:{port}{path}"
                # 优化点：使用 Range 头只获取前 64KB
                headers = {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                    "Range": "bytes=0-65535"
                }
                try:
                    async with session.get(url, timeout=3, headers=headers, ssl=False) as resp:
                        if resp.status in [200, 206]:
                            content = await resp.content.read(65536)
                            text = content.decode('utf-8', errors='ignore')
                            
                            # 预筛选：如果文本连 proxies 都没有，直接丢弃，不进 YAML 解析
                            if "proxies" not in text: continue
                            
                            # 结构化校验
                            cfg = yaml.safe_load(text)
                            if isinstance(cfg, dict):
                                # 严格评分系统
                                required = sum([k in cfg for k in ["proxies", "proxy-groups", "rules"]])
                                if required >= 2:
                                    content_hash = hashlib.md5(text.encode()).hexdigest()
                                    if content_hash not in seen_hashes:
                                        seen_hashes.add(content_hash)
                                        server = resp.headers.get("Server", "Unknown")
                                        file_path = f"{OUTPUT_DIR}/{ip}_{port}_{content_hash[:8]}.yaml"
                                        with open(file_path, 'w', encoding='utf-8') as f:
                                            f.write(f"# Server: {server}\n{text}")
                                        print(f"[+] Found: {url} | Server: {server}")
                except: continue
        finally:
            queue.task_done()

async def main():
    if not os.path.exists(OUTPUT_DIR): os.makedirs(OUTPUT_DIR)
    
    queue = asyncio.Queue()
    ips = [str(ip) for ip in ipaddress.IPv4Network(TARGET_CIDR, strict=False)]
    
    # 填充任务队列
    for ip in ips:
        for port in TARGET_PORTS:
            for path in TARGET_PATHS:
                queue.put_nowait((ip, port, path))

    # 创建固定数量的 Worker，复用同一个 Session
    connector = aiohttp.TCPConnector(limit=WORKER_COUNT, ssl=False)
    async with aiohttp.ClientSession(connector=connector) as session:
        workers = [asyncio.create_task(worker(queue, session)) for _ in range(WORKER_COUNT)]
        await queue.join() # 等待所有任务完成
        for w in workers: w.cancel() # 取消所有 worker

if __name__ == "__main__":
    asyncio.run(main())
