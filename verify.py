import aiohttp
import asyncio
import os

# 核心路径
TEST_PATHS = ["/sub", "/subscribe", "/link", "/api/sub", "/config"]
# 更像真实浏览器的 UA
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

async def verify_ip(session, ip, port):
    for path in TEST_PATHS:
        url = f"https://{ip}:{port}{path}"
        try:
            async with session.get(url, headers={"User-Agent": UA}, timeout=3, ssl=False) as resp:
                text = await resp.text()
                if resp.status == 200:
                    # 过滤 HTML 干扰
                    if "<html" in text.lower() or "<!doctype" in text.lower():
                        continue
                    
                    # 订阅特征匹配
                    if any(s in text.lower() for s in ["proxies:", "vless://", "vmess://", "ss://", "trojan://"]):
                        print(f"[!] 发现有效订阅: {url}")
                        if not os.path.exists("temp_hash"): os.makedirs("temp_hash")
                        with open(f"temp_hash/{ip}_{port}.yaml", "w", encoding="utf-8") as f:
                            f.write(text[:2000])
                        return True
                    else:
                        print(f"[DEBUG] {ip} 返回 200，内容不含订阅特征 (前50字符: {text[:50]})")
                else:
                    # 打印非 200 状态码
                    pass 
        except Exception:
            continue
    return False

async def main():
    if not os.path.exists("alive_ips.txt"):
        print("[-] 未找到 alive_ips.txt")
        return

    with open("alive_ips.txt") as f:
        ips = [line.strip() for line in f if line.strip()]
    
    print(f"[*] 开始验证 {len(ips)} 个 IP...")
    
    conn = aiohttp.TCPConnector(limit=50)
    async with aiohttp.ClientSession(connector=conn) as session:
        tasks = [verify_ip(session, ip, 443) for ip in ips]
        await asyncio.gather(*tasks)
    
    print("[*] 验证完成。")

if __name__ == "__main__":
    # 修复：使用 asyncio.run
    asyncio.run(main())
