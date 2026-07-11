import aiohttp
import asyncio
import ipaddress
import yaml
import hashlib
import os

# --- 配置区域 ---
TARGET_CIDR = "38.207.177.0/24"
TARGET_PORTS = [80, 443, 7890, 8080, 8888, 9090]
TARGET_PATHS = ["/", "/sub", "/subscribe", "/clash", "/config"]
OUTPUT_DIR = "results"
CONCURRENT_LIMIT = 100 # Semaphore 限制
# ----------------

sem = asyncio.Semaphore(CONCURRENT_LIMIT)

async def check_target(session, ip, port, path):
    async with sem:
        for scheme in ["http", "https"]:
            url = f"{scheme}://{ip}:{port}{path}"
            try:
                timeout = aiohttp.ClientTimeout(connect=2, sock_read=5)
                async with session.get(url, timeout=timeout, ssl=False) as resp:
                    if resp.status == 200:
                        content = await resp.content.read(65536) # 只读前 64KB
                        text = content.decode('utf-8', errors='ignore')
                        
                        # 结构化校验
                        try:
                            cfg = yaml.safe_load(text)
                            if isinstance(cfg, dict) and any(k in cfg for k in ["proxies", "proxy-groups"]):
                                # 唯一性校验
                                content_hash = hashlib.md5(text.encode()).hexdigest()
                                file_path = f"{OUTPUT_DIR}/{ip}_{port}_{content_hash[:8]}.yaml"
                                with open(file_path, 'w', encoding='utf-8') as f:
                                    f.write(text)
                                return f"[+] Found: {url} saved to {file_path}"
                        except:
                            continue
            except:
                continue
    return None

async def main():
    if not os.path.exists(OUTPUT_DIR): os.makedirs(OUTPUT_DIR)
    
    ips = [str(ip) for ip in ipaddress.IPv4Network(TARGET_CIDR, strict=False)]
    connector = aiohttp.TCPConnector(ssl=False)
    
    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = []
        for ip in ips:
            for port in TARGET_PORTS:
                for path in TARGET_PATHS:
                    tasks.append(check_target(session, ip, port, path))
        
        # 使用 as_completed 实时获取进度，不再一次性 gather
        for task in asyncio.as_completed(tasks):
            res = await task
            if res: print(res)

if __name__ == "__main__":
    asyncio.run(main())
