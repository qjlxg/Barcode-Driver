import aiohttp
import asyncio
import yaml
import hashlib
import os
import argparse
from tqdm import tqdm

# 配置项
TARGET_PORTS = [80, 443, 7890, 8080, 8888, 9090]
TARGET_PATHS = ["/", "/sub", "/subscribe", "/clash", "/config"]
OUTPUT_DIR = "results"

# 统计字典
stats = {"found": 0, "non_yaml": 0, "conn_error": 0}

async def check_target(session, ip, port, path):
    url = f"http://{ip}:{port}{path}"
    try:
        # 增加超时限制和请求头
        async with session.get(url, timeout=3, headers={"User-Agent": "Mozilla/5.0"}, ssl=False) as resp:
            if resp.status == 200:
                text = await resp.text(errors='ignore')
                if "proxies" in text:
                    try:
                        cfg = yaml.safe_load(text)
                        if isinstance(cfg, dict):
                            h = hashlib.md5(text.encode()).hexdigest()[:8]
                            # 确保文件夹存在
                            if not os.path.exists(OUTPUT_DIR): os.makedirs(OUTPUT_DIR)
                            with open(f"{OUTPUT_DIR}/{ip}_{port}_{h}.yaml", 'w', encoding='utf-8') as f:
                                f.write(text)
                            stats["found"] += 1
                            return
                    except: pass
                stats["non_yaml"] += 1
    except:
        stats["conn_error"] += 1

async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--file", required=True)
    args = parser.parse_args()
    
    with open(args.file, 'r') as f:
        ips = [line.strip() for line in f if line.strip()]

    print(f"[*] 开始处理 {len(ips)} 个目标...")
    async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=False)) as session:
        tasks = [check_target(session, ip, port, path) for ip in ips for port in TARGET_PORTS for path in TARGET_PATHS]
        # 使用 as_completed 结合 tqdm 修复报错
        for f in tqdm(asyncio.as_completed(tasks), total=len(tasks)):
            await f
    
    print(f"\n[*] 扫描结束。统计结果: {stats}")

if __name__ == "__main__":
    asyncio.run(main())
