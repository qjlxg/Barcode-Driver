import requests
import ipaddress
import re
import json
import time
import random
from datetime import datetime
from pathlib import Path

# ================= 配置区域 =================
BASE_DIR = Path(__file__).resolve().parent
CONFIG_DIR = BASE_DIR / "config"
ASN_SEED_FILE = CONFIG_DIR / "asn_seed.txt"
ASN_IP_FILE = BASE_DIR / "asn_ip.txt"          # 过程缓存，也可按需保留
IP_FILE = BASE_DIR / "ip.txt"                  # 最终运行结果保存到根目录下 ip.txt
ASN_HISTORY_FILE = CONFIG_DIR / "asn_history.json"

# 保护机制
MAX_TOTAL_CIDRS = 25         # 全局总网段硬上限
MAX_PER_ASN = 300            # 单个 ASN 最大允许录入的 /24 数量
FETCH_DELAY = (3, 7)         # 随机延迟范围（秒），防止被 HE.net 封禁
EXPIRY_DAYS = 180            # 历史记录过期天数

# 扩展后的 CDN 及 基础运营商 ASN 黑名单
EXCLUDE_ASNS = {
    "AS13335", "AS20940", "AS16625", "AS22822", "AS36183", "AS54113",
    "AS11878", "AS16509", "AS14618", "AS15169", "AS396983", "AS8075",
    "AS8068", "AS15133", "AS3356", "AS1299", "AS174"
}

# ================= 工具函数 =================

def setup_env():
    """初始化环境"""
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    if not ASN_SEED_FILE.exists():
        ASN_SEED_FILE.write_text("# 在此输入ASN，每行一个，如：AS12345\n", encoding="utf-8")
        print(f"[*] 已创建种子文件: {ASN_SEED_FILE}，请填入 ASN 后重新运行。")
        return False
    return True

def load_history():
    if ASN_HISTORY_FILE.exists():
        try:
            return json.loads(ASN_HISTORY_FILE.read_text(encoding="utf-8"))
        except Exception:
            return {}
    return {}

def save_history(history_data):
    ASN_HISTORY_FILE.write_text(json.dumps(history_data, indent=2, ensure_ascii=False), encoding="utf-8")

def get_prefixes_from_he(asn):
    """从 HE.net 获取前缀，带重试机制"""
    asn_digit = asn.upper().replace("AS", "")
    url = f"https://bgp.he.net/AS{asn_digit}#_prefixes"
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Referer": "https://bgp.he.net/",
        "Upgrade-Insecure-Requests": "1"
    }

    try:
        time.sleep(random.uniform(*FETCH_DELAY))
        r = requests.get(url, headers=headers, timeout=20)
        if r.status_code == 404:
            print(f"    [!] ASN {asn} 不存在 (404)")
            return set()
        if "maintaining this site" in r.text or r.status_code == 429:
            print(f"    [!] 触发 HE.net 反爬虫限制，请更换 IP 或稍后再试")
            return set()

        prefixes = set(re.findall(r'/net/(\d+\.\d+\.\d+\.\d+/\d+)', r.text))
        return prefixes
    except Exception as e:
        print(f"    [!] 网络请求失败: {e}")
        return set()

def process_to_24(prefix_set):
    """将获取到的网段统一转换为 /24"""
    results = set()
    for p in prefix_set:
        try:
            net = ipaddress.ip_network(p, strict=False)
            if not net.is_global: continue

            if net.prefixlen < 24:
                if net.prefixlen < 16:
                    print(f"    [?] 跳过超大型网段 (>{net.prefixlen}) 以防溢出: {p}")
                    continue
                for subnet in net.subnets(new_prefix=24):
                    results.add(str(subnet))
            elif net.prefixlen == 24:
                results.add(str(net))
            else:
                results.add(str(net.supernet(new_prefix=24)))
        except:
            continue
    return results

# ================= 主程序 =================

def collect():
    if not setup_env(): return

    history = load_history()
    # 状态数据存在 progress 结构中，不干扰原有的 asn 历史详情
    progress_meta = history.get("_progress", {"last_index": 0})
    last_index = progress_meta.get("last_index", 0)

    # 载入现有 ip.txt 或 asn_ip.txt 中的资产
    existing_cidrs = set()
    if IP_FILE.exists():
        existing_cidrs = {l.strip() for l in IP_FILE.read_text(encoding="utf-8").splitlines() if l.strip()}
    elif ASN_IP_FILE.exists():
        existing_cidrs = {l.strip() for l in ASN_IP_FILE.read_text(encoding="utf-8").splitlines() if l.strip()}

    print(f"[*] 任务开始 | 当前全量资产数: {len(existing_cidrs)} | 上限: {MAX_TOTAL_CIDRS}")

    if len(existing_cidrs) >= MAX_TOTAL_CIDRS:
        print("[!] 当前资产库达到上限，将继续检查已有ASN，不新增")

    # 获取待处理 ASN 种子
    raw_asns = [
        l.strip().upper()
        for l in ASN_SEED_FILE.read_text(encoding="utf-8").splitlines()
        if re.match(r"^AS\d+$", l.strip().upper())
    ]

    total_asns = len(raw_asns)
    if total_asns == 0:
        print("[!] asn_seed.txt 中未发现有效的 ASN")
        return

    # 如果上次已经全部抓完，支持循环重置或提示
    if last_index >= total_asns:
        print("[*] 所有 ASN 已遍历完成，重置抓取进度开始新一轮循环...")
        last_index = 0

    current_time_str = datetime.now().strftime("%Y-%m-%d %H:%M")
    current_date_obj = datetime.now()

    # 从上次停止的位置开始
    processed_count = 0
    for i in range(last_index, total_asns):
        asn = raw_asns[i]
        
        if len(existing_cidrs) >= MAX_TOTAL_CIDRS:
            print("\n[!] 已达到资产硬上限，停止新增采集")
            break

        if asn in EXCLUDE_ASNS:
            print(f"[*] 跳过名单内 ASN: {asn}")
            last_index = i + 1
            continue

        print(f"\n[*] 正在采集 [{i+1}/{total_asns}] {asn}...")
        raw_prefixes = get_prefixes_from_he(asn)

        if not raw_prefixes:
            print(f"    [!] 未能获取到前缀，跳过")
            last_index = i + 1
            # 记录当前进度
            history["_progress"] = {"last_index": last_index}
            save_history(history)
            continue

        current_asn_cidrs = process_to_24(raw_prefixes)

        old_asn_record = history.get(asn, {})
        old_asn_cidrs_dict = old_asn_record.get("cidrs", {})

        active_old_cidrs = set()
        for cidr, meta in old_asn_cidrs_dict.items():
            last_added_str = meta.get("last_added", meta.get("first_seen", current_time_str))
            try:
                last_added_date = datetime.strptime(last_added_str.split()[0], "%Y-%m-%d")
                if (current_date_obj - last_added_date).days < EXPIRY_DAYS:
                    active_old_cidrs.add(cidr)
            except Exception:
                active_old_cidrs.add(cidr)

        new_potential = current_asn_cidrs - active_old_cidrs
        new_potential = new_potential - existing_cidrs

        print(f"    -> 提取网段: {len(current_asn_cidrs)} | 待入库新增: {len(new_potential)}")

        added_count = 0
        newly_accepted_dict = {}

        for cidr in sorted(list(new_potential)):
            if added_count >= MAX_PER_ASN:
                print(f"    [!] 已达到单 ASN 录入上限 ({MAX_PER_ASN})")
                break
            if len(existing_cidrs) >= MAX_TOTAL_CIDRS:
                break

            existing_cidrs.add(cidr)

            if cidr in old_asn_cidrs_dict:
                first_seen = old_asn_cidrs_dict[cidr].get("first_seen", current_time_str)
            else:
                first_seen = current_time_str

            newly_accepted_dict[cidr] = {
                "first_seen": first_seen,
                "last_added": current_time_str
            }
            added_count += 1

        updated_cidrs_dict = {}
        for cidr, meta in old_asn_cidrs_dict.items():
            if cidr in active_old_cidrs:
                updated_cidrs_dict[cidr] = meta
        for cidr, meta in newly_accepted_dict.items():
            updated_cidrs_dict[cidr] = meta

        history[asn] = {
            "last_scan": current_time_str,
            "total_count": len(updated_cidrs_dict),
            "new_added": added_count,
            "cidrs": updated_cidrs_dict
        }

        # 更新指针到下一条
        last_index = i + 1
        history["_progress"] = {"last_index": last_index}

        # 实时持久化历史与根目录下的 ip.txt
        save_history(history)
        IP_FILE.write_text("\n".join(sorted(existing_cidrs)), encoding="utf-8")
        if ASN_IP_FILE.parent.exists():
            ASN_IP_FILE.write_text("\n".join(sorted(existing_cidrs)), encoding="utf-8")

        if added_count > 0:
            print(f"    [+] 成功入库 {added_count} 个新网段")
        else:
            print(f"    [-] 无新资产更新")

    print(f"\n[*] 采集轮次结束")
    print(f"[*] 下次运行将从索引 {last_index} 继续")
    print(f"[*] 最终资产总数: {len(existing_cidrs)}")

if __name__ == "__main__":
    collect()
