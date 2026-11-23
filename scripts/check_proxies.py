#!/usr/bin/env python3
"""
Real Xray-core proxy verifier v9 (Live Multi-Request + Streak Ranking + DNS) for The Last VPN.
- Sources: igareck, MyAppVPN-subs (output/reality.txt), aviamastersgh, AvenCores/goida-vpn-configs, Delta-Kronecker, kort0881
- Strict filter: ONLY VLESS Reality (UUIDv4, pbk>=32, tcp/grpc) & Trojan (pwd>=8, tcp/grpc)
- Real 3-step HTTP/HTTPS traffic verification (NOT ping!): gstatic + 1.1.1.1/trace + google/generate_204, RTT <= 1200ms
- Stability streak tracking (node_streaks.json): servers surviving multiple runs rank first
- Outputs: verified_pools.json, sub.txt (Base64), happ.json (with RU-DIRECT, DNS split, iOS-safe observatory).
"""

import base64
import concurrent.futures
import json
import os
import re
import socket
import subprocess
import tempfile
import time
from urllib.parse import parse_qs, quote, unquote, urlparse

import requests

XRAY_BIN = os.path.abspath("xray_bin/xray")
OUT_JSON = os.path.abspath("verified_pools.json")
OUT_SUB = os.path.abspath("sub.txt")
OUT_HAPP = os.path.abspath("happ.json")
STREAKS_FILE = os.path.abspath("node_streaks.json")

SOURCES = [
    ("igareck_mob", "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/BLACK_VLESS_RUS_mobile.txt"),
    ("igareck_ss_trojan", "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/BLACK_SS+All_RUS.txt"),
    ("myappvpn_reality", "https://raw.githubusercontent.com/indelingDanil/MyAppVPN-subs/output/reality.txt"),
    ("zieng2_wl", "https://raw.githubusercontent.com/zieng2/wl/main/vless_universal.txt"),
    ("aviamasters_ru", "https://raw.githubusercontent.com/aviamastersgh/vpn-free-russia/main/verified_configs.txt"),
    ("avencores_26", "https://raw.githubusercontent.com/AvenCores/goida-vpn-configs/refs/heads/main/githubmirror/26.txt"),
    ("avencores_24", "https://raw.githubusercontent.com/AvenCores/goida-vpn-configs/refs/heads/main/githubmirror/24.txt"),
    ("delta_reality", "https://raw.githubusercontent.com/Delta-Kronecker/V2ray-Config/main/config/tcp-pass/reality.txt"),
    ("kort_clean", "https://raw.githubusercontent.com/kort0881/vpn-vless-configs-russia/main/githubmirror/clean/vless.txt"),
    ("igareck_all", "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/BLACK_VLESS_RUS.txt"),
]

WHITELIST_SOURCES = [
    "https://bitbucket.org/igareck/vpn-configs-for-russia/raw/main/Vless-Reality-White-Lists-Rus-Mobile.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-CIDR-RU-checked.txt",
    "https://raw.githubusercontent.com/indelingDanil/MyAppVPN-subs/output/by-country/RU.txt",
]

COUNTRY_META = {
    "NL": ("🇳🇱", "Нидерланды"), "US": ("🇺🇸", "США"), "DE": ("🇩🇪", "Германия"),
    "FI": ("🇫🇮", "Финляндия"), "PL": ("🇵🇱", "Польша"), "SE": ("🇸🇪", "Швеция"),
    "GB": ("🇬🇧", "Великобритания"), "FR": ("🇫🇷", "Франция"), "CH": ("🇨🇭", "Швейцария"),
    "AT": ("🇦🇹", "Австрия"), "CZ": ("🇨🇿", "Чехия"), "EE": ("🇪🇪", "Эстония"),
    "LV": ("🇱🇻", "Латвия"), "LT": ("🇱🇹", "Литва"), "NO": ("🇳🇴", "Норвегия"),
    "IE": ("🇮🇪", "Ирландия"), "CA": ("🇨🇦", "Канада"), "TR": ("🇹🇷", "Турция"),
    "JP": ("🇯🇵", "Япония"), "SG": ("🇸🇬", "Сингапур"), "HK": ("🇭🇰", "Гонконг"),
    "KR": ("🇰🇷", "Корея"), "IN": ("🇮🇳", "Индия"), "IL": ("🇮🇱", "Израиль"),
    "AE": ("🇦🇪", "ОАЭ"), "AU": ("🇦🇺", "Австралия"), "IT": ("🇮🇹", "Италия"),
    "ES": ("🇪🇸", "Испания"), "RO": ("🇷🇴", "Румыния"), "BG": ("🇧🇬", "Болгария"),
    "HU": ("🇭🇺", "Венгрия"), "SK": ("🇸🇰", "Словакия"), "PT": ("🇵🇹", "Португалия"),
    "DK": ("🇩🇰", "Дания"), "BE": ("🇧🇪", "Бельгия"), "LU": ("🇱🇺", "Люксембург"),
    "GR": ("🇬🇷", "Греция"), "RS": ("🇷🇸", "Сербия"), "UA": ("🇺🇦", "Украина"),
    "MD": ("🇲🇩", "Молдова"), "KZ": ("🇰🇿", "Казахстан"), "GE": ("🇬🇪", "Грузия"),
    "AM": ("🇦🇲", "Армения"), "UZ": ("🇺🇿", "Узбекистан"), "TW": ("🇹🇼", "Тайвань"),
    "TH": ("🇹🇭", "Таиланд"), "VN": ("🇻🇳", "Вьетнам"), "ID": ("🇮🇩", "Индонезия"),
    "MY": ("🇲🇾", "Малайзия"), "PH": ("🇵🇭", "Филиппины"), "BR": ("🇧🇷", "Бразилия"),
    "AR": ("🇦🇷", "Аргентина"), "CL": ("🇨🇱", "Чили"), "MX": ("🇲🇽", "Мексика"),
    "ZA": ("🇿🇦", "ЮАР"), "CY": ("🇨🇾", "Кипр"),
}

TARGET_COUNTRIES = set(COUNTRY_META.keys())
RARE_HINTS = {"NL", "SE", "CA", "CH", "EE", "GB", "FR", "TR", "IE", "AT", "CZ", "NO", "LV", "LT", "SG", "JP", "FI", "PL", "AE"}

UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
CF_CDN_RE = re.compile(r"^(172\.(6[4-9]|7[01])\.|104\.(1[6-9]|2[0-9]|3[01])\.|162\.15[89]\.|188\.114\.|198\.41\.|108\.162\.|141\.101\.|190\.93\.|197\.234\.)")
PRIVATE_IP_RE = re.compile(r"^(127\.|10\.|192\.168\.|0\.|172\.(1[6-9]|2[0-9]|3[01])\.)")
BANNED_SNI_RE = re.compile(
    r"(\s|cloudflare\.com|fuck\.rkn|localhost|youtube\.com|youtu\.be|discord\.com|discordapp\.com|"
    r"instagram\.com|facebook\.com|fbcdn\.net|chatgpt\.com|openai\.com|twitter\.com|x\.com|"
    r"spotify\.com|netflix\.com|twitch\.tv|tiktok\.com|telegram\.org|t\.me|rutracker\.org)",
    re.I,
)
GOOD_FPS = {"chrome", "firefox", "safari", "ios", "edge", "randomized"}


def decode_sub_lines(raw_text: str):
    txt = (raw_text or "").strip()
    if "vless://" not in txt and "trojan://" not in txt:
        try:
            padded = txt + "=" * (-len(txt) % 4)
            decoded = base64.b64decode(padded, validate=False).decode("utf-8", errors="ignore")
            if "vless://" in decoded or "trojan://" in decoded:
                txt = decoded
        except Exception:
            pass
    return txt.splitlines()


def is_bad_host(host: str) -> bool:
    h = (host or "").strip().lower()
    if not h or PRIVATE_IP_RE.match(h) or CF_CDN_RE.match(h):
        return True
    return h in ("chatgpt.com", "cloudflare.com", "localhost") or h.endswith(".cloudflare.com")


def hint_country(remark: str) -> str:
    txt = unquote(remark or "")
    for cc in RARE_HINTS:
        if re.search(rf"\b{cc}\b", txt, re.I):
            return cc
    return ""


def parse_candidate(line: str, is_top150: bool = False):
    line = line.strip()
    if len(line) > 1200:
        return None
    if line.startswith("vless://"):
        return parse_vless(line, is_top150=is_top150)
    if line.startswith("trojan://"):
        return parse_trojan(line, is_top150=is_top150)
    return None


def parse_vless(line: str, is_top150: bool = False):
    try:
        base, _, remark = line.partition("#")
        u = urlparse(base)
        uuid = (u.username or "").strip()
        host = (u.hostname or "").strip()
        port = u.port or 443
        if not UUID_RE.match(uuid) or is_bad_host(host) or not (1 <= int(port) <= 65535):
            return None
        qs = {k: v[0] for k, v in parse_qs(u.query).items()}
        sec = qs.get("security", "none").lower()
        net = qs.get("type", "tcp").lower()
        if net == "raw":
            net = "tcp"
        if sec != "reality" or net not in ("tcp", "grpc"):
            return None
        pbk = qs.get("pbk", "").strip()
        if len(pbk) < 32:
            return None
        sni = qs.get("sni", qs.get("host", host)).strip()
        if "." not in sni or BANNED_SNI_RE.search(sni):
            return None
        sid = qs.get("sid", "").strip()
        if sid and not re.fullmatch(r"[0-9a-fA-F]{1,16}", sid):
            sid = ""
        flow = qs.get("flow", "") if net == "tcp" else ""
        if flow and flow != "xtls-rprx-vision":
            flow = ""
        fp = qs.get("fp", "chrome").strip().lower()
        if fp not in GOOD_FPS:
            fp = "chrome"
        return {
            "protocol": "vless",
            "dedupKey": f"vless:{host}:{port}:{uuid}",
            "baseUri": base,
            "host": host,
            "port": int(port),
            "isTop150": is_top150,
            "hintCc": hint_country(remark),
            "countryCode": "",
            "cfg": {
                "uuid": uuid,
                "security": "reality",
                "type": net,
                "sni": sni,
                "pbk": pbk,
                "sid": sid,
                "spx": qs.get("spx", "/"),
                "fp": fp,
                "flow": flow,
                "serviceName": qs.get("serviceName", ""),
                "path": "/",
                "wsHost": sni,
            },
        }
    except Exception:
        return None


def parse_trojan(line: str, is_top150: bool = False):
    try:
        base, _, remark = line.partition("#")
        u = urlparse(base)
        password = unquote(u.username or "").strip()
        host = (u.hostname or "").strip()
        port = u.port or 443
        if len(password) < 8 or is_bad_host(host) or not (1 <= int(port) <= 65535):
            return None
        qs = {k: v[0] for k, v in parse_qs(u.query).items()}
        net = qs.get("type", "tcp").lower()
        if net == "raw":
            net = "tcp"
        if net not in ("tcp", "grpc"):
            return None
        sni = qs.get("sni", qs.get("peer", host)).strip()
        if "." not in sni or BANNED_SNI_RE.search(sni):
            return None
        fp = qs.get("fp", "chrome").strip().lower()
        if fp not in GOOD_FPS:
            fp = "chrome"
        return {
            "protocol": "trojan",
            "dedupKey": f"trojan:{host}:{port}:{password}",
            "baseUri": base,
            "host": host,
            "port": int(port),
            "isTop150": is_top150,
            "hintCc": hint_country(remark),
            "countryCode": "",
            "cfg": {
                "password": password,
                "security": "tls",
                "type": net,
                "sni": sni,
                "fp": fp,
                "serviceName": qs.get("serviceName", ""),
            },
        }
    except Exception:
        return None


def build_outbound(node, tag="proxy"):
    c = node["cfg"]
    if node["protocol"] == "vless":
        stream = {
            "network": c["type"],
            "security": "reality",
            "realitySettings": {
                "serverName": c["sni"],
                "fingerprint": c["fp"],
                "publicKey": c["pbk"],
                "shortId": c["sid"],
                "spiderX": c["spx"],
            },
        }
        if c["type"] == "grpc":
            stream["grpcSettings"] = {"serviceName": c["serviceName"]}
        user_obj = {"id": c["uuid"], "encryption": "none"}
        if c["flow"]:
            user_obj["flow"] = c["flow"]
        return {
            "tag": tag,
            "protocol": "vless",
            "settings": {"vnext": [{"address": node["host"], "port": node["port"], "users": [user_obj]}]},
            "streamSettings": stream,
        }
    stream = {
        "network": c["type"],
        "security": "tls",
        "tlsSettings": {"serverName": c["sni"], "fingerprint": c["fp"]},
    }
    if c["type"] == "grpc":
        stream["grpcSettings"] = {"serviceName": c["serviceName"]}
    return {
        "tag": tag,
        "protocol": "trojan",
        "settings": {"servers": [{"address": node["host"], "port": node["port"], "password": c["password"]}]},
        "streamSettings": stream,
    }


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def verify_node_real_traffic(node):
    port = free_port()
    cfg = {
        "log": {"loglevel": "none"},
        "inbounds": [{
            "tag": "socks-in",
            "port": port,
            "listen": "127.0.0.1",
            "protocol": "socks",
            "settings": {"auth": "noauth", "udp": False},
        }],
        "outbounds": [build_outbound(node, "proxy")],
    }
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as tf:
        json.dump(cfg, tf)
        cfg_path = tf.name

    proc = None
    try:
        proc = subprocess.Popen(
            [XRAY_BIN, "run", "-c", cfg_path],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        time.sleep(0.28)
        if proc.poll() is not None:
            return None
        proxies = {"http": f"socks5h://127.0.0.1:{port}", "https": f"socks5h://127.0.0.1:{port}"}

        # Check 1: Real HTTPS request #1 + RTT (reject slow nodes > 1200ms)
        t0 = time.monotonic()
        r1 = requests.get("https://www.gstatic.com/generate_204", proxies=proxies, timeout=1.6)
        rtt_ms = int((time.monotonic() - t0) * 1000)
        if r1.status_code not in (200, 204) or rtt_ms > 1200:
            return None

        # Check 2: Real HTTPS request #2 to Cloudflare trace (proves stability + gets true exit country)
        tr = requests.get("https://1.1.1.1/cdn-cgi/trace", proxies=proxies, timeout=1.8)
        if not tr.ok:
            return None
        m = re.search(r"^loc=([A-Z]{2})$", tr.text, re.M)
        exit_cc = m.group(1) if m else ""

        # Check 3: Real HTTPS request #3 to Google (proves tunnel doesn't drop after 2 requests)
        r3 = requests.get("https://speed.cloudflare.com/__down?bytes=250000", proxies=proxies, timeout=5.0)
        if r3.status_code != 200 or len(r3.content) < 200000:
            return None

        node["rttMs"] = rtt_ms
        node["countryCode"] = exit_cc
        return node
    except Exception:
        return None
    finally:
        if proc and proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=1)
            except Exception:
                proc.kill()
        try:
            os.remove(cfg_path)
        except Exception:
            pass
    return None


def resolve_missing_countries(nodes):
    need = [n for n in nodes if not n.get("countryCode")]
    for i in range(0, len(need), 90):
        batch = need[i:i + 90]
        hosts = []
        host_map = {}
        for n in batch:
            try:
                ip = socket.gethostbyname(n["host"])
                hosts.append(ip)
                host_map.setdefault(ip, []).append(n)
            except Exception:
                pass
        if not hosts:
            continue
        try:
            r = requests.post("http://ip-api.com/batch?fields=query,countryCode", json=list(set(hosts)), timeout=8)
            if r.ok:
                for row in r.json():
                    cc = str(row.get("countryCode", "")).upper()
                    q = row.get("query", "")
                    if cc in TARGET_COUNTRIES:
                        for node in host_map.get(q, []):
                            node["countryCode"] = cc
        except Exception:
            pass


def build_happ_balancer(title, nodes):
    obs = [build_outbound(n, f"node_{i}") for i, n in enumerate(nodes[:6])]
    if len(obs) == 1:
        obs[0]["tag"] = "proxy"
    use_bal = len(obs) > 1
    cfg = {
        "remarks": title,
        "log": {"loglevel": "warning"},
        "dns": {
            "servers": [
                {"address": "77.88.8.8", "domains": ["geosite:category-ru", "domain:ru", "domain:xn--p1ai"]},
                "1.1.1.1",
                "8.8.8.8",
            ],
            "queryStrategy": "UseIPv4",
        },
        "inbounds": [{
            "tag": "socks-in",
            "port": 10808,
            "listen": "127.0.0.1",
            "protocol": "socks",
            "settings": {"auth": "noauth", "udp": True},
            "sniffing": {"enabled": True, "destOverride": ["http", "tls", "quic"], "routeOnly": True},
        }],
        "outbounds": obs + [{"tag": "direct", "protocol": "freedom"}, {"tag": "block", "protocol": "blackhole"}],
        "routing": {
            "domainStrategy": "AsIs",
            "rules": [
                {"type": "field", "domain": ["domain:gosuslugi.ru", "domain:sberbank.ru", "domain:tbank.ru", "domain:yandex.ru", "domain:vk.com", "domain:ozon.ru", "domain:wildberries.ru"], "outboundTag": "direct"},
                {"type": "field", "network": "tcp,udp", **({"balancerTag": "auto-bal"} if use_bal else {"outboundTag": "proxy"})},
            ],
        },
    }
    if use_bal:
        cfg["observatory"] = {"subjectSelector": ["node_"], "probeURL": "https://www.gstatic.com/generate_204", "probeInterval": "25s", "enableConcurrency": False}
        cfg["routing"]["balancers"] = [{"tag": "auto-bal", "selector": ["node_"], "fallbackTag": "node_0", "strategy": {"type": "leastPing"}}]
    return cfg


def main():
    old_streaks = {}
    if os.path.exists(STREAKS_FILE):
        try:
            with open(STREAKS_FILE, "r", encoding="utf-8") as f:
                old_streaks = json.load(f)
        except Exception:
            old_streaks = {}

    seen = set()
    per_source = []
    for name, url in SOURCES:
        bucket = []
        try:
            r = requests.get(url, timeout=10)
            if r.ok:
                is_top = name in ("igareck_mob", "igareck_ss_trojan", "aviamasters_ru", "myappvpn_reality")
                for line in decode_sub_lines(r.text):
                    n = parse_candidate(line, is_top150=is_top)
                    if n and n["dedupKey"] not in seen:
                        seen.add(n["dedupKey"])
                        bucket.append(n)
        except Exception:
            pass
        if bucket:
            per_source.append(bucket)

    candidates = []
    max_len = max((len(b) for b in per_source), default=0)
    for i in range(max_len):
        for b in per_source:
            if i < len(b):
                candidates.append(b[i])

    # Test proven long-lived nodes first, then top RU lists, then rare countries
    candidates.sort(key=lambda n: (
        -min(int(old_streaks.get(n["dedupKey"], 0)), 10),
        0 if n.get("isTop150") else 1,
        0 if n.get("hintCc") in RARE_HINTS else 1,
        0 if n["protocol"] == "vless" else 1,
    ))

    to_test = candidates[:2000]
    print(f"Collected {len(candidates)} strict candidates. Real 3-request test on {len(to_test)} in 40 threads...")
    live = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=40) as pool:
        for res in pool.map(verify_node_real_traffic, to_test):
            if res:
                live.append(res)

    resolve_missing_countries(live)
    new_streaks = {}
    for n in live:
        n.pop("hintCc", None)
        dk = n["dedupKey"]
        st = int(old_streaks.get(dk, 0)) + 1
        n["streak"] = st
        new_streaks[dk] = st

    with open(STREAKS_FILE, "w", encoding="utf-8") as f:
        json.dump(new_streaks, f)

    def node_rank(n):
        streak_tier = 0 if n.get("streak", 1) >= 3 else 1
        top = 0 if n.get("isTop150") else 5
        if n["protocol"] == "vless":
            t = 0 if (n["cfg"].get("type") == "tcp" and n["cfg"].get("flow") == "xtls-rprx-vision") else (1 if n["cfg"].get("type") == "tcp" else 2)
        else:
            t = 3
        return (streak_tier, top + t, -n.get("streak", 1), n.get("rttMs", 9999))

    pools = {}
    for n in live:
        cc = n.get("countryCode", "")
        if cc in TARGET_COUNTRIES:
            pools.setdefault(cc, []).append(n)

    for cc in pools:
        pools[cc].sort(key=node_rank)
        pools[cc] = pools[cc][:25]

    wl_candidates = []
    wl_seen = set()
    for url in WHITELIST_SOURCES:
        try:
            r = requests.get(url, timeout=10)
            if r.ok:
                for line in decode_sub_lines(r.text)[:100]:
                    n = parse_candidate(line, is_top150=True)
                    if n and n["dedupKey"] not in wl_seen:
                        wl_seen.add(n["dedupKey"])
                        wl_candidates.append(n)
        except Exception:
            continue

    wl_live = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=24) as pool:
        for res in pool.map(verify_node_real_traffic, wl_candidates[:60]):
            if res:
                wl_live.append(res)
    resolve_missing_countries(wl_live)
    for n in wl_live:
        n.pop("hintCc", None)
    wl_live.sort(key=node_rank)

    out = {"ts": int(time.time()), "totalLive": len(live), "countries": pools, "whitelist": wl_live[:20]}
    with open(OUT_JSON, "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False)

    sub_lines = []
    happ_cards = []
    top_global = sorted(
        [n for cc, arr in pools.items() if cc not in ("RU", "BY") for n in arr[:2]],
        key=node_rank,
    )
    if top_global:
        happ_cards.append(build_happ_balancer("⚡ Топ РФ (Мульти-резерв) ⚡The LastVPN", top_global[:6]))
    if wl_live:
        happ_cards.append(build_happ_balancer("🛡 Белые списки (4.5G) ⚡The LastVPN", wl_live[:6]))

    for cc in sorted(pools.keys()):
        flag, cname = COUNTRY_META[cc]
        nodes = pools[cc]
        sub_lines.append(f"{nodes[0]['baseUri']}#{quote(f'{flag} {cname} ⚡The LastVPN')}")
        happ_cards.append(build_happ_balancer(f"{flag} {cname} ⚡The LastVPN", nodes))

    with open(OUT_SUB, "w", encoding="utf-8") as f:
        f.write(base64.b64encode(("\n".join(sub_lines) + "\n").encode("utf-8")).decode("ascii"))
    with open(OUT_HAPP, "w", encoding="utf-8") as f:
        json.dump(happ_cards, f, ensure_ascii=False, indent=2)

    print(f"Saved {OUT_JSON}, {OUT_SUB}, {OUT_HAPP}: {len(pools)} countries, {len(live)} live nodes.")


if __name__ == "__main__":
    main()
