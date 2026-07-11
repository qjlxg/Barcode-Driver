import aiohttp
import asyncio
import yaml
import hashlib
import os
import argparse

# --- 配置 ---
TARGET_PORTS = [80, 443, 7890, 8080, 8888, 9090]
TARGET_PATHS = ["/", "/sub", "/subscribe", "/clash", "/config"]
OUTPUT_DIR = "results"
CONCURRENT_LIMIT = 100

sem = asyncio.Semaphore(CONCURRENT_LIMIT)
seen_hashes = set()

async def check_target(session, ip, port, path):
    async with sem:
        for scheme in ["http", "https"]:
            url = f"{scheme}://{ip}:{port}{path}"
            headers = {"User-Agent": "Mozilla/5.0", "Range": "bytes=0-65535"}
            try:
                async with session.get(url, timeout=3, headers=headers, ssl=False) as resp:
                    if resp.status in [200, 206]:
                        text = (await resp.content.read(65536)).decode('utf-8', errors='ignore')
                        if "proxies" in text:
                            cfg = yaml.safe_load(text)
                            if isinstance(cfg, dict) and sum([k in cfg for k in ["proxies", "proxy-groups"]]) >= 2:
                                chash = hashlib.md5(text.encode()).hexdigest()
                                if chash not in seen_hashes:
                                    seen_hashes.add(chash)
                                    with open(f"{OUTPUT_DIR}/{ip}_{port}_{chash[:8]}.yaml", 'w', encoding='utf-8') as f:
                                        f.write(f"# Server: {resp.headers.get('Server', 'Unknown')}\n{text}")
                                    print(f"[+] Found: {url}")
            except: continue

async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--file", required=True)
    args = parser.parse_args()
    
    if not os.path.exists(OUTPUT_DIR): os.makedirs(OUTPUT_DIR)
    with open(args.file, 'r') as f:
        ips = [line.strip() for line in f if line.strip()]

    async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=False)) as session:
        tasks = [asyncio.create_task(check_target(session, ip, port, path)) 
                 for ip in ips for port in TARGET_PORTS for path in TARGET_PATHS]
        await asyncio.gather(*tasks)

if __name__ == "__main__":
    asyncio.run(main())
