import csv
import json
import ipaddress
from collections import defaultdict
from pathlib import Path
from datetime import datetime


# ============================================================
# 文件配置
# ============================================================

HISTORY_FILE = Path("seed_history.json")
IP_FILE = Path("ip.txt")
IP_COLD_FILE = Path("ip_cold.txt")          # 冷库：淘汰但未永久丢弃的 IP
TARGETS_FILE = Path("targets.txt")
RESULTS_FILE = Path("scan_results.csv")


# ============================================================
# 淘汰策略
# ============================================================

# 从未有过任何产出的 /24
# 连续多少次"实际扫描但没有新增结果"后淘汰
MAX_INACTIVE_NEW = 1


# 曾经有过产出的 /24
# 连续多少次"实际扫描但没有新增结果"后淘汰
MAX_INACTIVE_OLD = 15

# 热池 IP 数量低于此值时，从冷库补货
MIN_ACTIVE_IPS = 500

# 每次从冷库补入热池的 IP 数量
REFILL_SIZE = 3000


# ============================================================
# IP / CIDR 解析
# ============================================================

def get_cidr_key(target):
    """
    将以下格式统一转换为 /24：

        1.2.3.4
        1.2.3.4:80
        1.2.3.4:443
        1.2.3.0/24

    返回：

        1.2.3.0/24

    解析失败返回 None。
    """

    try:
        target = str(target).strip()

        if not target:
            return None

        # 已经是 CIDR
        if "/" in target:
            network = ipaddress.ip_network(
                target,
                strict=False
            )

            # 这里统一按 /24 作为种子判断单位
            if network.version == 4:
                ip = network.network_address
                network = ipaddress.ip_network(
                    f"{ip}/24",
                    strict=False
                )

            # [FIX 1] IPv6 CIDR 与单 IP 路径保持一致，统一返回 None
            if network.version != 4:
                return None

            return str(network)

        # IPv4:PORT
        # 例如：
        # 1.2.3.4:443
        if ":" in target:
            target = target.rsplit(":", 1)[0]

        ip = ipaddress.ip_address(target)

        # 当前逻辑针对 IPv4 /24
        if ip.version != 4:
            return None

        network = ipaddress.ip_network(
            f"{ip}/24",
            strict=False
        )

        return str(network)

    except Exception:
        return None


# ============================================================
# 历史记录
# ============================================================

def load_history():
    """
    读取历史状态。

    如果文件不存在或损坏，则使用空历史。
    """

    if not HISTORY_FILE.exists():
        return {}

    try:
        with open(
            HISTORY_FILE,
            "r",
            encoding="utf-8"
        ) as f:
            data = json.load(f)

        if isinstance(data, dict):
            return data

    except Exception as e:
        print(
            f"[WARN] 无法读取 {HISTORY_FILE}: {e}"
        )

    return {}


def save_history(history):
    """
    保存历史状态。
    """

    with open(
        HISTORY_FILE,
        "w",
        encoding="utf-8"
    ) as f:

        json.dump(
            history,
            f,
            indent=2,
            ensure_ascii=False
        )


# ============================================================
# 读取本轮实际扫描的网段
# ============================================================

def read_scanned_cidrs():
    """
    读取 targets.txt。
    """

    scanned_cidrs = set()

    if not TARGETS_FILE.exists():
        print(
            f"[WARN] {TARGETS_FILE} 不存在"
        )

        return scanned_cidrs

    try:

        with open(
            TARGETS_FILE,
            "r",
            encoding="utf-8"
        ) as f:

            for line in f:

                cidr = get_cidr_key(line)

                if cidr:
                    scanned_cidrs.add(cidr)

    except Exception as e:

        print(
            f"[WARN] 读取 {TARGETS_FILE} 失败: {e}"
        )

    return scanned_cidrs


# ============================================================
# 统计 scan_results.csv
# ============================================================

def read_result_counts():
    """
    统计 scan_results.csv 中每个 /24 当前累计拥有多少条结果。
    """

    result_counts = defaultdict(int)

    if not RESULTS_FILE.exists():

        print(
            f"[WARN] {RESULTS_FILE} 不存在"
        )

        return result_counts

    try:

        with open(
            RESULTS_FILE,
            "r",
            encoding="utf-8",
            newline=""
        ) as f:

            reader = csv.reader(f)

            # 跳过表头
            next(reader, None)

            for row in reader:

                if len(row) < 3:
                    continue

                cidr = get_cidr_key(row[2])

                if cidr:
                    result_counts[cidr] += 1

    except Exception as e:

        print(
            f"[WARN] 读取 {RESULTS_FILE} 失败: {e}"
        )

    return result_counts


# ============================================================
# 历史记录兼容与初始化
# ============================================================

def normalize_history_entry(entry):
    """
    兼容历史版本的 seed_history.json。
    """

    if not isinstance(entry, dict):
        entry = {}

    return {
        "last_total_hits": int(
            entry.get(
                "last_total_hits",
                0
            )
        ),

        "no_hit_rounds": int(
            entry.get(
                "no_hit_rounds",
                0
            )
        ),

        "has_historical_hit": bool(
            entry.get(
                "has_historical_hit",
                False
            )
        )
    }


# ============================================================
# 核心管理逻辑
# ============================================================

def manage_seeds():

    print("=" * 60)
    print("        manage_seeds.py")
    print("        IP 种子生命周期管理")
    print("=" * 60)

    # --------------------------------------------------------
    # 1. 读取历史
    # --------------------------------------------------------

    history = load_history()

    # 兼容历史格式
    for cidr in list(history.keys()):

        history[cidr] = normalize_history_entry(
            history[cidr]
        )

    # --------------------------------------------------------
    # 2. 读取本轮真正扫描过的 /24
    # --------------------------------------------------------

    scanned_cidrs = read_scanned_cidrs()

    if len(scanned_cidrs) == 0:
        print("没有实际扫描，本轮跳过清理")
        return

    print(
        f"[*] 本轮实际扫描网段: "
        f"{len(scanned_cidrs)}"
    )

    if len(history) == 0:
        print("首次运行，仅建立历史，不清理")

        current_results = read_result_counts()

        for cidr in scanned_cidrs:
            hits = current_results.get(cidr, 0)
            history[cidr] = {
                "last_total_hits": hits,
                "no_hit_rounds": 0,
                "has_historical_hit": hits > 0
            }

        save_history(history)
        return

    # --------------------------------------------------------
    # 3. 读取当前累计结果
    # --------------------------------------------------------

    current_results = read_result_counts()

    print(
        f"[*] 当前结果涉及网段: "
        f"{len(current_results)}"
    )

    # --------------------------------------------------------
    # 4. 更新本轮状态
    # --------------------------------------------------------

    new_result_cidrs = set()
    inactive_cidrs = set()

    for cidr in scanned_cidrs:

        if cidr not in history:

            history[cidr] = {
                "last_total_hits": 0,
                "no_hit_rounds": 0,
                "has_historical_hit": False
            }

        state = history[cidr]

        current_hits = current_results.get(
            cidr,
            0
        )

        last_hits = state.get(
            "last_total_hits",
            0
        )

        if current_hits > last_hits:

            state["no_hit_rounds"] = 0

            state["has_historical_hit"] = True

            new_result_cidrs.add(cidr)

            print(
                f"[+] 新增结果: "
                f"{cidr} "
                f"{last_hits} -> {current_hits}"
            )

        else:

            state["no_hit_rounds"] = (
                state.get(
                    "no_hit_rounds",
                    0
                ) + 1
            )

            inactive_cidrs.add(cidr)

        state["last_total_hits"] = current_hits

    # --------------------------------------------------------
    # 5. 判断哪些 /24 仍然保留
    # --------------------------------------------------------

    alive_cidrs = set()
    pruned_cidrs = set()

    for cidr, state in history.items():

        no_hit_rounds = state.get(
            "no_hit_rounds",
            0
        )

        has_historical_hit = state.get(
            "has_historical_hit",
            False
        )

        if has_historical_hit:

            if no_hit_rounds < MAX_INACTIVE_OLD:
                alive_cidrs.add(cidr)
            else:
                pruned_cidrs.add(cidr)

        else:

            if no_hit_rounds < MAX_INACTIVE_NEW:
                alive_cidrs.add(cidr)
            else:
                pruned_cidrs.add(cidr)

    # --------------------------------------------------------
    # 6. 清理 ip.txt
    # --------------------------------------------------------

    original_ips = []
    kept_ips = []
    removed_ips = []
    cold_added = 0
    refilled = 0

    if IP_FILE.exists():

        with open(
            IP_FILE,
            "r",
            encoding="utf-8"
        ) as f:

            original_ips = [
                line.strip()
                for line in f
                if line.strip()
            ]

        for ip in original_ips:

            cidr = get_cidr_key(ip)

            if cidr in alive_cidrs:
                kept_ips.append(ip)
            else:
                removed_ips.append(ip)

        # 安全检查 1：删除占比过大
        if len(original_ips) > 0 and (len(removed_ips) / len(original_ips) > 0.5):
            print(
                f"[!] 警告：删除 IP 数量占比超过 50% "
                f"({len(removed_ips)}/{len(original_ips)})，放弃清理操作。"
            )
            save_history(history)
            return

        # 安全检查 2：保留列表为空
        if len(kept_ips) == 0:
            print(f"[!] 警告：计算后的保留 IP 列表为空，放弃清理操作以防丢失种子。")
            # [FIX 2] 本轮计数更新已写入 history，必须持久化，否则下轮从旧值重算
            save_history(history)
            return

        # 去重，同时保持原始顺序
        kept_ips = list(dict.fromkeys(kept_ips))

        with open(
            IP_FILE,
            "w",
            encoding="utf-8"
        ) as f:

            if kept_ips:
                f.write("\n".join(kept_ips))
                f.write("\n")

        # 冷库：将淘汰的 IP 追加写入 ip_cold.txt，不永久丢弃
        if removed_ips:

            with open(
                IP_COLD_FILE,
                "a",
                encoding="utf-8"
            ) as f:

                f.write("\n".join(removed_ips))
                f.write("\n")

            cold_added = len(removed_ips)

            print(
                f"[*] 冷库新增: {cold_added} 条"
            )

        # 补货：热池不足时从冷库解冻一批
        if len(kept_ips) < MIN_ACTIVE_IPS and IP_COLD_FILE.exists():

            cold_lines = []

            with open(
                IP_COLD_FILE,
                "r",
                encoding="utf-8"
            ) as f:

                cold_lines = [
                    l.strip()
                    for l in f
                    if l.strip()
                ]

            # 去重并过滤掉已在热池中的
            hot_set = set(kept_ips)
            cold_unique = list(dict.fromkeys(
                ip for ip in cold_lines
                if ip not in hot_set
            ))

            refill = cold_unique[:REFILL_SIZE]
            remainder = cold_unique[REFILL_SIZE:]

            if refill:

                with open(
                    IP_FILE,
                    "a",
                    encoding="utf-8"
                ) as f:

                    f.write("\n".join(refill))
                    f.write("\n")

                with open(
                    IP_COLD_FILE,
                    "w",
                    encoding="utf-8"
                ) as f:

                    if remainder:
                        f.write("\n".join(remainder))
                        f.write("\n")

                refilled = len(refill)

                print(
                    f"[*] 冷库解冻: {refilled} 条补入热池，"
                    f"冷库剩余: {len(remainder)} 条"
                )

    else:
        print(f"[WARN] {IP_FILE} 不存在")

    # --------------------------------------------------------
    # 7. 保存历史
    # --------------------------------------------------------

    # [FIX 3] 已淘汰的网段从历史中删除，防止文件无限膨胀
    # 冷库中的网段历史同步清除，回来时当新网段重新计数
    for cidr in pruned_cidrs:
        history.pop(cidr, None)

    save_history(history)

    # --------------------------------------------------------
    # 8. 输出统计
    # --------------------------------------------------------

    print()
    print("=" * 60)
    print("                管理完成")
    print("=" * 60)

    print(f"[*] 本轮扫描网段: {len(scanned_cidrs)}")
    print(f"[+] 本轮有新增结果: {len(new_result_cidrs)}")
    print(f"[-] 本轮扫描但无新增: {len(inactive_cidrs)}")
    print(f"[+] 当前保留网段: {len(alive_cidrs)}")
    print(f"[-] 已淘汰网段: {len(pruned_cidrs)}")
    print(f"[+] 保留 IP 数量: {len(kept_ips)}")
    print(f"[-] 移入冷库 IP: {cold_added}")
    print(f"[+] 从冷库解冻 IP: {refilled}")
    print("=" * 60)


if __name__ == "__main__":
    manage_seeds()
