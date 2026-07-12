import asyncio
import aiohttp
import random

# --- 配置区 ---
# 在这里直接修改你想探测的端口列表
TARGET_PORTS = {"12202", "2096", "8443", "8081"}
# -------------

PATHS = [
    "/sub", "/subscribe", "/link", "/api/sub", "/clash", 
    "/config", "/config.yaml", "/sub.yaml", "/subscription", "/client/subscribe"
]
UA_LIST = ["clash", "ClashMeta", "mihomo", "Mozilla/5.0"]

YAML_SIGNS = ["proxies:", "proxy-groups:", "proxy-providers:", "mixed-port:"]
BASE_SIGNS = ["vmess://", "vless://", "trojan://", "ss://", "hysteria", "tuic://"]

async def check_target(session, item, sem):
    async with sem:
        if ":" in item: 
            ip, port = item.rsplit(":", 1)
        else: 
            ip, port = item, "80"

        # --- 新增逻辑：如果端口不在目标范围内，直接跳过 ---
        if port not in TARGET_PORTS:
            return None
        # --------------------------------------------

        schemes = ["https", "http"] if str(port) == "443" else ["http"]

        for scheme in schemes:
            base_url = f"{scheme}://{ip}:{port}"
            for path in PATHS:
                try:
                    async with session.get(f"{base_url}{path}", timeout=1.5, ssl=False, headers={"User-Agent": random.choice(UA_LIST)}) as resp:
                        ctype = resp.headers.get("Content-Type", "").lower()
                        if not any(x in ctype for x in ["text", "yaml", "json"]): continue
                        if resp.status != 200: continue

                        data = await resp.content.read(32768)
                        content = data.decode('utf-8', errors='ignore').lower()

                        yaml_score = sum(sign in content for sign in YAML_SIGNS)
                        if yaml_score >= 2 or any(s in content for s in BASE_SIGNS):
                            return item
                except: continue
        return None

async def main():
    sem = asyncio.Semaphore(500)
    connector = aiohttp.TCPConnector(ssl=False, limit=500, limit_per_host=5)

    refined_count = 0
    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = []
        with open("alive_ips.txt", "r") as f_in, open("refined_ips.txt", "w") as f_out:
            for line in f_in:
                item = line.strip()
                if not item: continue
                tasks.append(check_target(session, item, sem))

                if len(tasks) >= 100:
                    results = await asyncio.gather(*tasks)
                    for res in results:
                        if res:
                            f_out.write(res + "\n")
                            f_out.flush() # 确保数据即时写入
                            refined_count += 1
                    tasks = []
                    print(f"[*] 精炼中 (仅探测 {TARGET_PORTS})... 已存活: {refined_count}")

            if tasks:
                results = await asyncio.gather(*tasks)
                for res in results:
                    if res: 
                        f_out.write(res + "\n")
                        refined_count += 1

    print(f"[*] 完成！总计筛选出有效资产: {refined_count}")

if __name__ == "__main__":
    asyncio.run(main())
