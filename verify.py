import aiohttp
import asyncio
import os

# 1. 核心路径，这些是订阅最常见的入口
TEST_PATHS = ["/sub", "/subscribe", "/link", "/api/sub", "/getsub"]
# 2. 强制使用 Clash/Mihomo 的典型标识符作为 UA
UA = "mihomo/1.18.0" 

async def verify_ip(session, ip, port):
    """
    深度验证单个 IP 是否返回合法的订阅配置
    """
    for path in TEST_PATHS:
        url = f"http://{ip}:{port}{path}"
        try:
            async with session.get(url, headers={"User-Agent": UA}, timeout=3) as resp:
                if resp.status == 200:
                    text = await resp.text()
                    
                    # 过滤 HTML 干扰：如果包含 HTML 标签，直接判定为无效页面
                    if "<html" in text.lower() or "<!doctype" in text.lower():
                        continue
                    
                    # 关键特征校验：包含订阅节点核心协议字符串
                    # 如果这几个协议都没出现，那多半是垃圾页面
                    if any(s in text.lower() for s in ["proxies:", "vless://", "vmess://", "ss://", "trojan://"]):
                        print(f"[!] 发现有效订阅: {url}")
                        
                        # 确保本地文件夹存在
                        if not os.path.exists("temp_hash"): 
                            os.makedirs("temp_hash")
                        
                        # 保存到本地，用于人工确认
                        with open(f"temp_hash/{ip}_{port}.yaml", "w", encoding="utf-8") as f:
                            f.write(text[:2000]) # 保存前 2000 字符，足够判断配置结构
                        return True
        except: 
            continue
    return False

async def main():
    # 假设你有一个包含待测 IP 的文件
    if not os.path.exists("alive_ips.txt"):
        print("[-] 未找到 alive_ips.txt，请先放入需要测试的 IP 列表")
        return

    with open("alive_ips.txt") as f:
        ips = [line.strip() for line in f if line.strip()]
    
    print(f"[*] 开始验证 {len(ips)} 个 IP...")
    
    conn = aiohttp.TCPConnector(limit=50) # 适当限制并发
    async with aiohttp.ClientSession(connector=conn) as session:
        tasks = [verify_ip(session, ip, 443) for ip in ips] # 默认测试 443
        await asyncio.gather(*tasks)
    
    print("[*] 验证完成。有效配置已保存至 temp_hash/ 目录。")

if __name__ == "__main__":
    asyncio.run(main())
