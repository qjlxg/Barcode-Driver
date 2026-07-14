import asyncio
import aiohttp
import csv
import hashlib
import base64

# --- 配置 ---
CONFIG = {
    "ports": [80, 443, 8080, 8443],
    "paths": ["/sub", "/subscribe", "/link", "/api/sub", "/config", "/sub.yaml"],
    "high_vals": ["proxies:", "proxy-groups:", "vmess://", "vless://", "trojan://", "ss://"],
    "low_vals": ["uuid", "cipher", "server", "port", "type", "allow-lan"],
    "max_queue": 5000,
    "workers": 200
}

async def producer(queue, ip_file):
    with open(ip_file) as f:
        for line in f:
            target = line.strip().replace("http://", "").replace("https://", "").split("/")[0]
            if not target: continue
            for port in CONFIG["ports"]:
                for path in CONFIG["paths"]:
                    await queue.put((target, port, path))
    # 任务完成后，通知所有 worker 退出
    for _ in range(CONFIG["workers"]):
        await queue.put(None)

async def result_writer(res_queue):
    with open("result.csv", "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["IP", "PORT", "PATH", "STATUS", "SIZE", "HASH", "SERVER"])
        seen_hashes = set()
        while True:
            data = await res_queue.get()
            if data is None:
                res_queue.task_done()
                break
            if data['hash'] not in seen_hashes:
                writer.writerow([data['ip'], data['port'], data['path'], data['status'], data['size'], data['hash'], data['server']])
                seen_hashes.add(data['hash'])
            res_queue.task_done()

async def worker(queue, res_queue, session):
    while True:
        item = await queue.get()
        if item is None:
            queue.task_done()
            break
        ip, port, path = item
        
        # 优化协议探测顺序
        protos = ["https", "http"] if port in [443, 8443] else ["http", "https"]
        
        for proto in protos:
            url = f"{proto}://{ip}:{port}{path}"
            try:
                async with session.get(url, timeout=aiohttp.ClientTimeout(sock_connect=2, sock_read=5)) as resp:
                    raw = await resp.read()
                    text = raw.decode("utf-8", errors="ignore")
                    
                    # Base64 严谨过滤
                    candidate = text.strip()
                    decoded = ""
                    if 50 < len(candidate) < 10000 and "\n" not in candidate and len(candidate) % 4 == 0:
                        try: decoded = base64.b64decode(candidate + "===").decode("utf8", errors="ignore")
                        except: pass
                    
                    content = (text + decoded).lower()
                    high_hits = sum(1 for h in CONFIG["high_vals"] if h in content)
                    low_hits = sum(1 for l in CONFIG["low_vals"] if l in content)
                    
                    if resp.status == 200 and (high_hits >= 1 or low_hits >= 3):
                        if not ("<html" in content[:500] and len(raw) < 2000):
                            await res_queue.put({
                                "ip": ip, "port": port, "path": path, "status": resp.status,
                                "size": len(raw), "hash": hashlib.sha256(raw).hexdigest(),
                                "server": resp.headers.get("Server", "Unknown")
                            })
                            break 
            except Exception: continue
        queue.task_done()

async def main():
    queue = asyncio.Queue(maxsize=CONFIG["max_queue"])
    res_queue = asyncio.Queue()
    
    async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=False, limit=300, ttl_dns_cache=300)) as session:
        # 1. 启动任务
        producer_task = asyncio.create_task(producer(queue, "alive_ips.txt"))
        workers = [asyncio.create_task(worker(queue, res_queue, session)) for _ in range(CONFIG["workers"])]
        writer_task = asyncio.create_task(result_writer(res_queue))
        
        # 2. 严格生命周期管理
        await producer_task       # 等待生产结束
        await queue.join()         # 等待所有任务处理完毕
        await res_queue.put(None)  # 通知写入器结束
        await writer_task          # 等待写入器结束
        await asyncio.gather(*workers) # 回收所有 worker

if __name__ == "__main__":
    asyncio.run(main())
