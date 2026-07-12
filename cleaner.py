import asyncio
import socket
import sys

async def check_port(ip, port, timeout=0.5):
    """极简 TCP 握手测试"""
    try:
        conn = asyncio.open_connection(ip, port)
        reader, writer = await asyncio.wait_for(conn, timeout=timeout)
        writer.close()
        await writer.wait_closed()
        return True
    except:
        return False

async def main():
    # 1. 加载并去重
    with open("alive_ips.txt", "r") as f:
        # 假设原始格式是 IP:PORT 或 IP
        raw_items = sorted(list(set(f.read().splitlines())))
    
    print(f"[*] 初始条目: {len(raw_items)}")
    
    # 2. 快速连通性测试 (轻量级)
    valid_items = []
    # 这里建议分批处理，否则 49 万个协程会耗尽文件句柄
    for i in range(0, len(raw_items), 1000):
        batch = raw_items[i:i+1000]
        tasks = []
        for item in batch:
            if ":" in item:
                ip, port = item.split(":")
                tasks.append(check_port(ip, int(port)))
            else:
                # 如果只有 IP，默认测 80
                tasks.append(check_port(item, 80))
        
        results = await asyncio.gather(*tasks)
        for idx, is_alive in enumerate(results):
            if is_alive:
                valid_items.append(batch[idx])
        print(f"[*] 已处理 {i+len(batch)}/{len(raw_items)}...")

    # 3. 保存清洗后的列表
    with open("cleaned_ips.txt", "w") as f:
        f.write("\n".join(valid_items))
    print(f"[*] 清洗完成，剩余有效条目: {len(valid_items)}")

if __name__ == "__main__":
    asyncio.run(main())
