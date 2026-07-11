import aiohttp
import asyncio
import os
import csv
import base64

# --- 配置 ---
PORTS = [443, 80, 8080, 8443]
TEST_PATHS = [
    "/sub", "/subscribe", "/link", "/api/sub", "/config", 
    "/api/v1/client/subscribe", "/clash/proxies", "/sub.yaml"
]
KEYWORDS = ["proxies", "proxy-groups", "vless://", "vmess://", "ss://", "trojan://", "uuid", "cipher"]
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
SEM = asyncio.Semaphore(100) # 限制并发

def decode_base64(text):
    try:
        text = "".join(text.split()).replace("-", "+").replace("_", "/")
        padding = len(text) % 4
        if padding: text += "=" * (4 - padding)
        return base64.b64decode(text).decode("utf8", errors="ignore")
    except: return ""

async def verify_ip(session, ip, port, path):
    url = f"https://{ip}:{port}{path}" if port == 443 else f"http://{ip}:{port}{path}"
    async with SEM:
        try:
            # 增加 SNI 兼容：若不行，可尝试传 host 参数
            async with session.get(url, headers={"User-Agent": UA}, timeout=3, ssl=False) as resp:
                raw = await resp.read()
                text = raw.decode("utf-8", errors="ignore")
                
                # 兼容 Base64 编码的订阅
                decoded_text = decode_base64(text)
                full_content = (text + decoded_text).lower()
                
                # 检查特征
                if resp.status == 200 and any(k in full_content for k in KEYWORDS):
                    # 排除 HTML 干扰
                    if "<html" not in text.lower():
                        print(f"[!] Found: {url}")
                        return [ip, port, path, resp.status, "Valid"]
        except Exception:
            pass
    return None

async def main():
    if not os.path.exists("alive_ips.txt"): return
    with open("alive_ips.txt") as f:
        ips = [line.strip() for line in f if line.strip()]

    # 全局连接池优化
    connector = aiohttp.TCPConnector(ssl=False, limit=0)
    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = []
        for ip in ips:
            for port in PORTS:
                for path in TEST_PATHS:
                    tasks.append(verify_ip(session, ip, port, path))
        
        results = await asyncio.gather(*tasks)
        
        # CSV 统一输出
        with open("result.csv", "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["IP", "PORT", "PATH", "STATUS", "TYPE"])
            writer.writerows([r for r in results if r])

if __name__ == "__main__":
    asyncio.run(main())
