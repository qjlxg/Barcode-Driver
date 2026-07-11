import aiohttp
import asyncio
import ipaddress
import csv
import os

# --- 配置区域 ---
TARGET_CIDR = "38.207.177.0/24"
TARGET_PORTS = [80, 443, 7890, 8080, 8888, 9090]
CONCURRENT_REQUESTS = 100
OUTPUT_DIR = "results"
# ----------------

async def check_target(session, ip, port):
    for scheme in ["http", "https"]:
        url = f"{scheme}://{ip}:{port}/"
        try:
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
            async with session.get(url, timeout=2, headers=headers, ssl=False) as response:
                if response.status == 200:
                    text = await response.text()
                    if "proxies" in text and "name" in text:
                        return [str(ip), port, scheme, "Detected"]
        except Exception:
            continue
    return None

async def main():
    if not os.path.exists(OUTPUT_DIR):
        os.makedirs(OUTPUT_DIR)
    
    ips = [str(ip) for ip in ipaddress.IPv4Network(TARGET_CIDR, strict=False)]
    connector = aiohttp.TCPConnector(limit=CONCURRENT_REQUESTS, ssl=False)
    
    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = []
        for ip in ips:
            for port in TARGET_PORTS:
                tasks.append(check_target(session, ip, port))
        
        results = await asyncio.gather(*tasks)
    
    valid_results = [r for r in results if r]
    
    # 存入结果
    file_path = f"{OUTPUT_DIR}/scan_results.csv"
    with open(file_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(["IP", "Port", "Scheme", "Status"])
        writer.writerows(valid_results)
    print(f"[*] 扫描完成，发现 {len(valid_results)} 个有效资产。")

if __name__ == "__main__":
    asyncio.run(main())
