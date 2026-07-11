import aiohttp
import asyncio
import yaml
import hashlib
import os
import argparse
from tqdm import asyncio as tqdm_asyncio

# 配置项
TARGET_PORTS = [80, 443, 7890, 8080, 8888, 9090]
TARGET_PATHS = ["/", "/sub", "/subscribe", "/clash", "/config"]
OUTPUT_DIR = "results"
CONCURRENT_LIMIT = 200

# 统计字典
stats = {"found": 0, "non_yaml": 0, "conn_error": 0}

async def check_target(session, ip, port, path):
    url = f"http://{ip}:{port}{path}"
    try:
        async with session.get(url, timeout=3, headers={"User-Agent": "Mozilla/5.0"}, ssl=False) as resp:
            if resp.status == 200:
                text = await resp.text(errors='ignore')
                # 宽松匹配：只要包含 proxies 关键字
                if "proxies" in text:
                    try:
                        # 尝试解析 YAML
                        cfg = yaml.safe_load(text)
                        if isinstance(cfg, dict):
                            h = hashlib.md5(text.encode()).hexdigest()[:8]
                            with open(f"{OUTPUT_DIR}/{ip}_{port}_{h}.yaml", 'w', encoding='utf-8') as f:
                                f.write(text)
                            stats["found"] += 1
                            print(f"[+] Found: {url}")
                            return
                    except: pass
                stats["non_yaml"] += 1
    except:
        stats["conn_error"] += 1

async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--file", required=True)
    args = parser.parse_args()
    
    if not os.path.exists(OUTPUT_DIR): os.makedirs(OUTPUT_DIR)
    with open(args.file, 'r') as f:
        ips = [line.strip() for line in f if line.strip()]

    print(f"[*] 开始处理 {len(ips)} 个目标...")
    async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=False)) as session:
        tasks = [check_target(session, ip, port, path) for ip in ips for port in TARGET_PORTS for path in TARGET_PATHS]
        await tqdm_asyncio.gather(*tasks)
    
    print(f"\n[*] 扫描结束。统计结果: {stats}")

if __name__ == "__main__":
    asyncio.run(main())
