import asyncio
import aiohttp
import random

PATHS = [
    "/", "/sub", "/subscribe", "/clash", "/config", "/api/sub", 
    "/api/v1/client/subscribe", "/link", "/profile", "/getfile", 
    "/download", "/config.yaml", "/sub.yaml"
]

UA_LIST = [
    "clash", "ClashforWindows/0.20.39", "mihomo/1.18.3", 
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Clash-Verge/1.3.8", "sing-box/1.9.0"
]

# 扩充特征库：涵盖 V2Ray, Reality, Sing-box 等
SIGNS = [
    "proxies:", "proxy-groups:", "proxy-providers:", "mixed-port:", 
    "allow-lan:", "mode:", "vmess://", "vless://", "trojan://", 
    "ss://", "hysteria", "tuic://", "server:", "uuid:", 
    "password:", "client-fingerprint:", "reality-opts:", "flow:", "alpn:"
]

async def check_target(session, item):
    # 修复：更鲁棒的拆分逻辑
    if ":" in item:
        ip, port = item.rsplit(":", 1)
    else:
        ip, port = item, "80"  # 默认为 80 端口
        
    scheme = "https" if str(port) == "443" else "http"
    base_url = f"{scheme}://{ip}:{port}"
    
    headers = {"User-Agent": random.choice(UA_LIST)}
    
    for path in PATHS:
        url = f"{base_url}{path}"
        try:
            async with session.get(url, timeout=3.0, ssl=False, allow_redirects=True, headers=headers) as response:
                if response.status not in [200, 301, 302]:
                    continue
                
                buffer = b""
                async for chunk in response.content.iter_chunked(4096):
                    buffer += chunk
                    content_str = buffer.decode('utf-8', errors='ignore').lower()
                    if any(sign in content_str for sign in SIGNS):
                        return True
                    if len(buffer) > 50 * 1024:
                        break
        except:
            continue
    return False

async def main():
    try:
        with open("cleaned_ips.txt", "r") as f:
            items = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print("[!] 错误: cleaned_ips.txt 不存在。")
        return
    
    refined_items = []
    connector = aiohttp.TCPConnector(ssl=False, limit=100)
    async with aiohttp.ClientSession(connector=connector) as session:
        for i in range(0, len(items), 100):
            batch = items[i:i+100]
            tasks = [check_target(session, item) for item in batch]
            results = await asyncio.gather(*tasks)
            
            for idx, is_valid in enumerate(results):
                if is_valid:
                    refined_items.append(batch[idx])
            
            if i % 1000 == 0:
                print(f"[*] 精炼进度: {i}/{len(items)} | 当前保留: {len(refined_items)}")

    with open("refined_ips.txt", "w") as f:
        f.write("\n".join(refined_items))
    print(f"[*] 完成。剩余有效资产: {len(refined_items)}")

if __name__ == "__main__":
    asyncio.run(main())
