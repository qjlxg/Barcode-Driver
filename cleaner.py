import asyncio

# 定义需要探测的端口矩阵
TARGET_PORTS = [80, 443, 1333, 1999, 2052, 2053, 2082, 2083, 2087, 2095, 2096, 2222, 3002, 3333, 4444, 5555, 6001, 6666, 7777, 8011, 8080, 8081, 8083, 8443, 8444, 8787, 8888, 8899, 9050, 9981, 9999, 10110, 12202, 18080, 19999, 54321, 60001, 60002]

async def check_port(ip, port, timeout=1.0):
    """加固 TCP 测试：超时延长至 1s，适应全球网络波动"""
    try:
        conn = asyncio.open_connection(ip, port)
        reader, writer = await asyncio.wait_for(conn, timeout=timeout)
        writer.close()
        await writer.wait_closed()
        return True
    except:
        return False

async def main():
    try:
        with open("alive_ips.txt", "r") as f:
            raw_items = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print("[!] 错误: alive_ips.txt 不存在。")
        return

    valid_items = []
    batch_size = 500
    
    # 扩展任务池：如果输入只有 IP，则自动为每个 IP 生成多个端口扫描任务
    tasks_pool = []
    for item in raw_items:
        if ":" in item:
            # 处理标准 IP:Port 或 [IPv6]:Port
            ip, port = item.rsplit(":", 1)
            if ip.startswith("[") and ip.endswith("]"):
                ip = ip[1:-1]  # 去除方括号
            tasks_pool.append((ip, int(port)))
        else:
            # 如果只有 IP，自动扩展探测所有预设端口
            for p in TARGET_PORTS:
                tasks_pool.append((item, p))

    print(f"[*] 准备处理 {len(tasks_pool)} 个探测任务 (IP+端口组合)...")

    # 分批处理
    for i in range(0, len(tasks_pool), batch_size):
        batch = tasks_pool[i : i + batch_size]
        tasks = [check_port(ip, port) for ip, port in batch]
        results = await asyncio.gather(*tasks)
        
        for idx, is_alive in enumerate(results):
            if is_alive:
                ip, port = batch[idx]
                valid_items.append(f"{ip}:{port}")
        
        if i % 2000 == 0:
            print(f"[*] 进度: {i}/{len(tasks_pool)} | 存活: {len(valid_items)}")

    with open("cleaned_ips.txt", "w") as f:
        f.write("\n".join(valid_items))
    
    print(f"[*] 清洗完成，最终有效资产: {len(valid_items)}")

if __name__ == "__main__":
    asyncio.run(main())
