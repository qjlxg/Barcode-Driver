import ipaddress

def process_ip_file(input_file='ip.txt', output_file='targets.txt'):
    networks = set()
    try:
        with open(input_file, 'r') as f:
            for line in f:
                target = line.strip()
                if not target: continue
                try:
                    # 扩展为 /24 网段并添加到集合中去重
                    net = ipaddress.ip_network(f"{target}/24", strict=False)
                    networks.add(str(net))
                except ValueError:
                    continue 
        
        with open(output_file, 'w') as f:
            for n in sorted(networks):
                f.write(n + '\n')
        print(f"[*] 成功从 {input_file} 提取并扩展 {len(networks)} 个网段到 {output_file}")
    except FileNotFoundError:
        print(f"[!] 错误：找不到文件 {input_file}")

if __name__ == "__main__":
    process_ip_file()
