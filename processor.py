import ipaddress
from pathlib import Path

def process_ip_file(input_file='ip.txt', output_file='targets.txt'):
    input_path = Path(input_file)
    if not input_path.exists():
        print(f"[!] 错误：找不到文件 {input_file}")
        return

    networks = set()
    
    with input_path.open('r', encoding='utf-8') as f:
        for line_num, line in enumerate(f, 1):
            target = line.strip()
            if not target: continue
            
            try:
                # 如果输入已经是 CIDR 格式，直接处理；否则添加 /24
                if '/' in target:
                    net = ipaddress.ip_network(target, strict=False)
                else:
                    net = ipaddress.ip_network(f"{target}/24", strict=False)
                
                # 将网段规范化并加入集合
                networks.add(str(net))
            except ValueError:
                print(f"[!] 第 {line_num} 行格式无效，已跳过: {target}")

    # 将结果排序并写入
    with open(output_file, 'w', encoding='utf-8') as f:
        for n in sorted(networks):
            f.write(f"{n}\n")
            
    print(f"[*] 处理完成！共提取 {len(networks)} 个唯一网段，保存至 {output_file}")

if __name__ == "__main__":
    process_ip_file()
