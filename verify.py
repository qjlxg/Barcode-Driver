import asyncio
import aiohttp
import csv
import base64

# --- 配置 ---
PORTS = [80, 443, 8080, 8443]
TEST_PATHS = ["/sub", "/subscribe", "/link", "/api/sub", "/config", "/sub.yaml"]
HIGH_VAL = ["proxies:", "proxy-groups:", "vmess://", "vless://", "trojan://", "ss://"]
LOW_VAL = ["uuid", "cipher", "server", "port", "type", "allow-lan"]

async def worker(queue, session, writer, lock):
    while True:
        target = await queue.get()
        ip, port, path = target
        url = f"https://{ip}:{port}{path}" if port == 443 else f"http://{ip}:{port}{path}"
        
        try:
            # 增加 SNI 兼容：若某些目标要求严格 SNI，此处可尝试设置 ssl=aiohttp.Fingerprint(...)
            async with session.get(url, timeout=3, ssl=False) as resp:
                raw = await resp.read()
                text = raw.decode("utf-8", errors="ignore")
                
                # 增强版特征检测
                content_lower = text.lower()
                high_hits = sum(1 for h in HIGH_VAL if h in content_lower)
                low_hits = sum(1 for l in LOW_VAL if l in content_lower)
                
                # 评分逻辑：高权重满足其一，或低权重满足三个以上
                if resp.status == 200 and (high_hits >= 1 or low_hits >= 3):
                    # HTML 宽松过滤
                    if not ("<html" in content_lower and len(text) < 2000):
                        server = resp.headers.get("Server", "Unknown")
                        async with lock:
                            writer.writerow([ip, port, path, resp.status, len(raw), server])
                            print(f"[!] Hit: {url} | Server: {server}")
        except: pass
        finally: queue.task_done()

async def main():
    # 1. 初始化队列
    queue = asyncio.Queue()
    with open("alive_ips.txt") as f:
        ips = [line.strip() for line in f if line.strip()]
    
    for ip in ips:
        for port in PORTS:
            for path in TEST_PATHS:
                queue.put_nowait((ip, port, path))

    # 2. 连接池配置
    connector = aiohttp.TCPConnector(limit=200, ssl=False, ttl_dns_cache=300)
    async with aiohttp.ClientSession(connector=connector) as session:
        lock = asyncio.Lock()
        with open("result.csv", "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["IP", "PORT", "PATH", "STATUS", "SIZE", "SERVER"])
            
            # 3. 启动 100 个 Worker 消费队列
            workers = [asyncio.create_task(worker(queue, session, writer, lock)) for _ in range(100)]
            await queue.join()
            for w in workers: w.cancel()

if __name__ == "__main__":
    asyncio.run(main())
