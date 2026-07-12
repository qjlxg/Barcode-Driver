import asyncio
import aiohttp
import random

PATHS = [
    "/sub", "/subscribe", "/link", "/api/sub", "/clash", 
    "/config", "/config.yaml", "/sub.yaml", "/subscription", "/client/subscribe"
]
UA_LIST = ["clash", "ClashMeta", "mihomo", "Mozilla/5.0"]

# 组合特征检查逻辑
YAML_SIGNS = ["proxies:", "proxy-groups:", "proxy-providers:", "mixed-port:"]
BASE_SIGNS = ["vmess://", "vless://", "trojan://", "ss://", "hysteria", "tuic://"]

async def check_target(session, item, sem):
    async with sem:
        if ":" in item: ip, port = item.rsplit(":", 1)
        else: ip, port = item, "80"

        schemes = ["https", "http"] if str(port) == "443" else ["http"]
        
        for scheme in schemes:
            base_url = f"{scheme}://{ip}:{port}"
            for path in PATHS:
                try:
                    async with session.get(f"{base_url}{path}", timeout=1.5, ssl=False, headers={"User-Agent": random.choice(UA_LIST)}) as resp:
                        # 提前过滤：只处理 text/yaml/json
                        ctype = resp.headers.get("Content-Type", "").lower()
                        if not any(x in ctype for x in ["text", "yaml", "json"]): continue
                        if resp.status != 200: continue
                        
                        data = await resp.content.read(32768)
                        content = data.decode('utf-8', errors='ignore').lower()
                        
                        # 特征加权判定
                        yaml_score = sum(sign in content for sign in YAML_SIGNS)
                        if yaml_score >= 2 or any(s in content for s in BASE_SIGNS):
                            return item
                except: continue
        return None

async def main():
    sem = asyncio.Semaphore(500)
    connector = aiohttp.TCPConnector(ssl=False, limit=500, limit_per_host=5)
    
    async with aiohttp.ClientSession(connector=connector) as session:
        refined_count = 0
        tasks = []
        with open("cleaned_ips.txt", "r") as f_in, open("refined_ips.txt", "w") as f_out:
            for line in f_in:
                item = line.strip()
                if not item: continue
                tasks.append(check_target(session, item, sem))
                
                if len(tasks) >= 2000:
                    results = await asyncio.gather(*tasks)
                    for res in results:
                        if res:
                            f_out.write(res + "\n")
                            refined_count += 1
                    tasks = []
                    print(f"[*] 精炼中... 有效: {refined_count}")
            
            # 处理尾部任务
            if tasks:
                results = await asyncio.gather(*tasks)
                for res in results:
                    if res: f_out.write(res + "\n")

if __name__ == "__main__":
    asyncio.run(main())
