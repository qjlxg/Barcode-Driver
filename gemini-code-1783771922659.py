import aiohttp
import asyncio
import ipaddress
import csv

# 修改点：使用 CIDR 格式
TARGET_CIDR = "192.168.1.0/24"  # 例如：扫描整个 C 段
PORT = 7890
OUTPUT_FILE = "results.csv"
CONCURRENT_REQUESTS = 100 

async def check_ip(session, ip):
    url = f"http://{ip}:{PORT}/"
    try:
        async with session.get(url, timeout=2) as response:
            if response.status == 200:
                text = await response.text()
                # 增强筛选逻辑，减少误报
                if "proxies" in text and "name" in text:
                    print(f"[+] Found Target: {url}")
                    return [str(ip), PORT, "Detected"]
    except Exception:
        pass
    return None

async def main():
    # 动态生成 IP 列表
    ips = [ip for ip in ipaddress.IPv4Network(TARGET_CIDR, strict=False)]
    print(f"[*] 开始扫描 {TARGET_CIDR}，共计 {len(ips)} 个地址...")

    connector = aiohttp.TCPConnector(limit=CONCURRENT_REQUESTS)
    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = [check_ip(session, ip) for ip in ips]
        results = await asyncio.gather(*tasks)

    valid_results = [r for r in results if r]
    
    if valid_results:
        with open(OUTPUT_FILE, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(["IP", "Port", "Status"])
            writer.writerows(valid_results)
        print(f"[*] 扫描完成，发现 {len(valid_results)} 个匹配项。")
    else:
        print("[*] 扫描结束，未发现匹配目标。")

if __name__ == "__main__":
    asyncio.run(main())