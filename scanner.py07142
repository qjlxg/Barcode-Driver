import aiohttp, asyncio, hashlib, os, csv, argparse, random
from tqdm import tqdm

# --- 配置 ---
TARGET_PORTS = [80, 443, 1333, 1999, 2052, 2053, 2082, 2083, 2087, 2095, 2096, 2222, 3002, 3333, 4444, 5555, 6001, 6666, 7777, 8011, 8080, 8081, 8083, 8443, 8444, 8787, 8888, 8899, 9050, 9981, 9999, 10110, 12202, 18080, 19999, 54321, 60001, 60002]
PATHS = ["", "/", "/sub", "/subscribe", "/link", "/s/", "/api/sub", "/api/v1/client/subscribe", "/api/user/subscribe", "/client/subscribe", "/config.yaml", "/sub.yaml"]
SIGNS = ["proxies:", "proxy-groups:", "vless://", "vmess://", "trojan://", "uuid:", "hysteria://", "hysteria2://", "hy2://", "tuic://", "anytls://"]
WORKER_COUNT = 100 

stats = {"req": 0, "saved": 0}
found_results = [] # 记录已找到的 URL 避免重复

async def scan(session, host, port, path, pbar):
    for scheme in ["https", "http"]:
        url = f"{scheme}://{host}:{port}{path}"
        try:
            async with session.get(url, timeout=3, ssl=False) as resp:
                stats["req"] += 1
                if resp.status == 200:
                    text = await resp.text(errors="ignore")
                    if any(s in text.lower() for s in SIGNS):
                        if url not in found_results:
                            found_results.append(url)
                            stats["saved"] += 1
                            # 写入文件
                            with open("results.csv", "a", encoding="utf-8") as f:
                                f.write(f"{url}\n")
                        return # 找到即停止尝试该端口
        except: continue
    pbar.update(1)

async def main():
    parser = argparse.ArgumentParser(); parser.add_argument("--file", required=True); args = parser.parse_args()
    with open(args.file) as f: lines = [l.strip() for l in f if l.strip()]
    
    tasks = []
    for line in lines:
        if ":" in line:
            host, port = line.rsplit(":", 1)
            for path in PATHS: tasks.append((host, port, path))
        else:
            for port in TARGET_PORTS:
                for path in PATHS: tasks.append((line, port, path))

    print(f"[*] 任务总数: {len(tasks)}")
    pbar = tqdm(total=len(tasks))
    
    async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=False, limit=WORKER_COUNT)) as session:
        # 分批执行，避免内存溢出
        for i in range(0, len(tasks), WORKER_COUNT):
            batch = tasks[i:i+WORKER_COUNT]
            await asyncio.gather(*(scan(session, h, p, path, pbar) for h, p, path in batch))
            
    print(f"\n[*] 扫描完成！共命中: {stats['saved']} 个")

if __name__ == "__main__": asyncio.run(main())
