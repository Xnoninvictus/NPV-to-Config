#!/usr/bin/env python3
"""
npvs_converter_full.py

Scans a directory for *.npvs AND *.npvt files, converts every config
inside them to standard share URIs and writes all results to a single
.txt file, one URI per line.

Supported protocols (v2rayN EConfigType):
  1  = VMess        -> vmess://
  3  = Shadowsocks  -> ss://
  4  = SOCKS        -> socks://
  5  = VLESS        -> vless://
  6  = Trojan       -> trojan://
  7  = Hysteria2    -> hysteria2://
  8  = TUIC         -> tuic://
  9  = WireGuard    -> wireguard://
  10 = HTTP         -> http://
  11 = AnyTLS       -> anytls://
  12 = Naive        -> naive+https://
"""

import base64
import json
import sys
from pathlib import Path
from urllib.parse import quote, urlencode


NPX_EXTENSIONS = ("*.npvs", "*.npvt")


# ----------------------------------------------------------------------
# Base64 helpers
# ----------------------------------------------------------------------
def b64_pad(s: str) -> str:
    return s + "=" * (-len(s) % 4)


def npvs_decode(value):
    """Decode values like: npvs1:YmFzZTY0"""
    if isinstance(value, str) and value.startswith("npvs1:"):
        raw = value[6:]
        try:
            return base64.b64decode(b64_pad(raw)).decode("utf-8")
        except Exception:
            return value
    return value


def decode_profile(profile: dict) -> dict:
    return {k: npvs_decode(v) for k, v in profile.items()}


def fix_mojibake(s):
    if not isinstance(s, str):
        return s
    try:
        return s.encode("latin1").decode("utf-8")
    except Exception:
        return s


# ----------------------------------------------------------------------
# Common helpers
# ----------------------------------------------------------------------
def get_host_port(item: dict, p: dict):
    if p.get("server") and p.get("serverPort"):
        return str(p["server"]), str(p["serverPort"])

    addr = item.get("address", "")
    if ":" in addr:
        host, port = addr.rsplit(":", 1)
    else:
        host, port = addr, ""
    return host, str(port)


def qs(params: dict) -> str:
    cleaned = {k: v for k, v in params.items() if v not in (None, "", False, 0)}
    return urlencode(cleaned, quote_via=quote)


def get_remark(item: dict) -> str:
    return quote(fix_mojibake(item.get("name", "")), safe="")


# ----------------------------------------------------------------------
# URI builders
# ----------------------------------------------------------------------

# --- configType 1: VMess ---
def to_vmess(item: dict, p: dict) -> str:
    host, port = get_host_port(item, p)

    vmess_obj = {
        "v": "2",
        "ps": fix_mojibake(item.get("name", "")),
        "add": host,
        "port": str(port),
        "id": p.get("password") or p.get("id") or p.get("uuid", ""),
        "aid": str(p.get("alterId", p.get("aid", 0))),
        "scy": p.get("security", "auto"),
        "net": p.get("network", "tcp"),
        "type": p.get("headerType", "none"),
        "host": p.get("host", ""),
        "path": p.get("path", ""),
        "tls": p.get("security", ""),
        "sni": p.get("sni", ""),
    }
    vmess_obj = {k: v for k, v in vmess_obj.items() if v not in ("", None)}

    raw = json.dumps(vmess_obj, separators=(",", ":"), ensure_ascii=False)
    encoded = base64.b64encode(raw.encode("utf-8")).decode("ascii").rstrip("=")
    return f"vmess://{encoded}"


# --- configType 3: Shadowsocks ---
def to_ss(item: dict, p: dict) -> str:
    host, port = get_host_port(item, p)
    method = p.get("method", "")
    password = p.get("password", "")

    userinfo = base64.urlsafe_b64encode(
        f"{method}:{password}".encode()
    ).decode().rstrip("=")

    return f"ss://{userinfo}@{host}:{port}#{get_remark(item)}"


# --- configType 4: SOCKS ---
def to_socks(item: dict, p: dict) -> str:
    host, port = get_host_port(item, p)
    user = p.get("username", p.get("user", ""))
    password = p.get("password", "")

    if user and password:
        userinfo = f"{quote(user, safe='')}:{quote(password, safe='')}@"
    elif user:
        userinfo = f"{quote(user, safe='')}@"
    else:
        userinfo = ""

    return f"socks://{userinfo}{host}:{port}#{get_remark(item)}"


# --- configType 5: VLESS ---
def to_vless(item: dict, p: dict) -> str:
    host, port = get_host_port(item, p)
    uuid = p.get("password") or p.get("id") or p.get("uuid")
    net = p.get("network", "tcp")
    sec = p.get("security", "none")

    params = {
        "encryption": "none",
        "type": net,
        "security": sec,
    }

    if p.get("flow"):
        params["flow"] = p["flow"]
    if p.get("sni"):
        params["sni"] = p["sni"]
    if p.get("fingerPrint"):
        params["fp"] = p["fingerPrint"]

    if sec == "reality":
        if p.get("publicKey"):
            params["pbk"] = p["publicKey"]
        if p.get("shortId"):
            params["sid"] = p["shortId"]
        if p.get("spiderX"):
            params["spx"] = p["spiderX"]

    if net in ("ws", "h2", "http", "grpc"):
        if p.get("path"):
            params["path"] = p["path"]
        if p.get("host"):
            params["host"] = p["host"]

    if p.get("headerType") and p["headerType"] != "none":
        params["headerType"] = p["headerType"]

    return f"vless://{uuid}@{host}:{port}?{qs(params)}#{get_remark(item)}"


# --- configType 6: Trojan ---
def to_trojan(item: dict, p: dict) -> str:
    host, port = get_host_port(item, p)
    password = p.get("password", "")
    net = p.get("network", "tcp")
    sec = p.get("security", "tls")

    params = {
        "security": sec,
        "type": net,
    }

    if p.get("sni"):
        params["sni"] = p["sni"]
    if p.get("fingerPrint"):
        params["fp"] = p["fingerPrint"]
    if p.get("allowInsecure") or p.get("tlsAllowInsecure") or p.get("insecure"):
        params["allowInsecure"] = "1"

    if net in ("ws", "h2", "http", "grpc"):
        if p.get("path"):
            params["path"] = p["path"]
        if p.get("host"):
            params["host"] = p["host"]

    if p.get("headerType") and p["headerType"] != "none":
        params["headerType"] = p["headerType"]
    if p.get("flow"):
        params["flow"] = p["flow"]

    return f"trojan://{quote(str(password), safe='')}@{host}:{port}?{qs(params)}#{get_remark(item)}"


# --- configType 7: Hysteria2 ---
def to_hy2(item: dict, p: dict) -> str:
    host, port = get_host_port(item, p)
    password = p.get("password", "")

    params = {}
    if p.get("sni"):
        params["sni"] = p["sni"]
    if p.get("insecure") or p.get("tlsAllowInsecure") or p.get("allowInsecure"):
        params["insecure"] = "1"
    if p.get("obfsPassword"):
        params["obfs"] = p.get("obfs", "salamander")
        params["obfs-password"] = p["obfsPassword"]
    if p.get("pinSHA256"):
        params["pinSHA256"] = p["pinSHA256"]
    if p.get("uploadMbps"):
        params["upmbps"] = p["uploadMbps"]
    if p.get("downloadMbps"):
        params["downmbps"] = p["downloadMbps"]

    user = quote(str(password), safe="")
    return f"hysteria2://{user}@{host}:{port}/?{qs(params)}#{get_remark(item)}"


# --- configType 8: TUIC ---
def to_tuic(item: dict, p: dict) -> str:
    host, port = get_host_port(item, p)

    uuid = p.get("uuid", "")
    password = p.get("password", "")
    token = p.get("token", "")

    params = {}
    if p.get("sni"):
        params["sni"] = p["sni"]
    if p.get("alpn"):
        params["alpn"] = p["alpn"]
    if p.get("congestion_control"):
        params["congestion_control"] = p["congestion_control"]
    if p.get("udp_relay_mode"):
        params["udp_relay_mode"] = p["udp_relay_mode"]
    if p.get("allowInsecure") or p.get("insecure") or p.get("tlsAllowInsecure"):
        params["allow_insecure"] = "1"
    if p.get("disable_sni"):
        params["disable_sni"] = "1"

    if uuid and password:
        userinfo = f"{quote(uuid, safe='')}:{quote(password, safe='')}@"
    elif token:
        userinfo = f"{quote(token, safe='')}@"
    else:
        userinfo = ""

    return f"tuic://{userinfo}{host}:{port}?{qs(params)}#{get_remark(item)}"


# --- configType 9: WireGuard ---
def to_wireguard(item: dict, p: dict) -> str:
    host, port = get_host_port(item, p)

    private_key = p.get("password") or p.get("privateKey", "")
    public_key = p.get("publicKey", "")
    address = p.get("address", p.get("localAddress", ""))
    mtu = p.get("mtu", "")

    params = {}
    if public_key:
        params["publickey"] = public_key
    if address:
        params["address"] = address
    if mtu:
        params["mtu"] = mtu
    if p.get("reserved"):
        params["reserved"] = p["reserved"]

    userinfo = quote(str(private_key), safe="")
    return f"wireguard://{userinfo}@{host}:{port}/?{qs(params)}#{get_remark(item)}"


# --- configType 10: HTTP ---
def to_http(item: dict, p: dict) -> str:
    host, port = get_host_port(item, p)
    user = p.get("username", p.get("user", ""))
    password = p.get("password", "")

    if user and password:
        userinfo = f"{quote(user, safe='')}:{quote(password, safe='')}@"
    elif user:
        userinfo = f"{quote(user, safe='')}@"
    else:
        userinfo = ""

    return f"http://{userinfo}{host}:{port}#{get_remark(item)}"


# --- configType 11: AnyTLS ---
def to_anytls(item: dict, p: dict) -> str:
    host, port = get_host_port(item, p)
    password = p.get("password", "")

    params = {}
    if p.get("sni"):
        params["sni"] = p["sni"]
    if p.get("insecure") or p.get("allowInsecure") or p.get("tlsAllowInsecure"):
        params["insecure"] = "1"

    user = quote(str(password), safe="")
    return f"anytls://{user}@{host}:{port}/?{qs(params)}#{get_remark(item)}"


# --- configType 12: Naive ---
def to_naive(item: dict, p: dict) -> str:
    host, port = get_host_port(item, p)
    user = p.get("username", p.get("user", ""))
    password = p.get("password", "")

    params = {}
    if p.get("padding"):
        params["padding"] = "1"

    userinfo = f"{quote(user, safe='')}:{quote(password, safe='')}@"
    return f"naive+https://{userinfo}{host}:{port}?{qs(params)}#{get_remark(item)}"


# ----------------------------------------------------------------------
# Dispatcher
# ----------------------------------------------------------------------
def convert_item(item: dict):
    p = decode_profile(item.get("v2rayProfile", {}))
    ct = p.get("configType")

    converters = {
        1: to_vmess,
        3: to_ss,
        4: to_socks,
        5: to_vless,
        6: to_trojan,
        7: to_hy2,
        8: to_tuic,
        9: to_wireguard,
        10: to_http,
        11: to_anytls,
        12: to_naive,
    }

    if ct in converters:
        result = converters[ct](item, p)
        if isinstance(result, str):
            return result
        return f"# converter returned non-str for configType={ct} name={item.get('name','unknown')}"

    # Fallback inference
    if p.get("flow") and p.get("publicKey"):
        return to_vless(item, p)
    if p.get("method") and p.get("method") != "none":
        return to_ss(item, p)
    if p.get("obfsPassword") or (
        p.get("security") == "tls" and p.get("password") and not p.get("method")
    ):
        return to_hy2(item, p)
    if p.get("uuid") and p.get("password"):
        return to_tuic(item, p)
    if p.get("publicKey") and p.get("privateKey"):
        return to_wireguard(item, p)

    return f"# unsupported configType={ct} name={item.get('name', 'unknown')}"


# ----------------------------------------------------------------------
# Loaders
# ----------------------------------------------------------------------
def load_npvs(path: Path) -> dict:
    with open(path, "r", encoding="utf-8-sig") as f:
        text = f.read().strip()

    lines = text.splitlines()
    if lines and lines[0].strip().upper().startswith("NPV"):
        text = "\n".join(lines[1:]).strip()

    return json.loads(text)


def load_npvt(path: Path):
    """
    Best-effort parser for .npvt files. Their real format is not JSON,
    so this attempts to decode each comma-separated line as a base64
    JSON payload. Returns a list of config dicts (possibly empty).
    """
    with open(path, "r", encoding="utf-8-sig") as f:
        text = f.read().strip()

    lines = text.splitlines()
    if not lines:
        return []

    if lines[0].strip().upper().startswith("NPVT"):
        lines = lines[1:]

    configs = []
    for line in lines:
        line = line.strip()
        if not line or "," not in line:
            continue

        name_b64, payload_b64 = line.split(",", 1)

        # Decode the name (base64) — it may or may not be valid UTF-8.
        try:
            name = base64.b64decode(b64_pad(name_b64)).decode("utf-8", errors="replace")
        except Exception:
            name = name_b64

        # Decode the payload — try JSON, skip if it isn't.
        try:
            payload_bytes = base64.b64decode(b64_pad(payload_b64))
            payload_text = payload_bytes.decode("utf-8")
            data = json.loads(payload_text)
        except Exception:
            continue

        configs.append({
            "name": name,
            "v2rayProfile": data,
        })

    return configs


def load_configs(path: Path):
    suffix = path.suffix.lower()
    if suffix == ".npvs":
        return load_npvs(path).get("configs", [])
    if suffix == ".npvt":
        return load_npvt(path)
    return []


# ----------------------------------------------------------------------
# Directory scan / main
# ----------------------------------------------------------------------
def find_npvs_files(directory: Path):
    files = []
    for pattern in NPX_EXTENSIONS:
        files.extend(directory.glob(pattern))
    return sorted(set(files))


def main():
    target_dir = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(".")
    output_file = Path(sys.argv[2]) if len(sys.argv) > 2 else Path("converted_configs.txt")

    if not target_dir.is_dir():
        print(f"Error: {target_dir} is not a directory", file=sys.stderr)
        sys.exit(1)

    npvs_files = find_npvs_files(target_dir)
    if not npvs_files:
        print(f"No .npvs or .npvt files found in {target_dir.resolve()}", file=sys.stderr)
        sys.exit(1)

    all_uris = []
    total_configs = 0
    errors = []

    for npvs_path in npvs_files:
        try:
            configs = load_configs(npvs_path)
        except Exception as e:
            errors.append(f"{npvs_path.name}: failed to load — {e}")
            continue

        for item in configs:
            try:
                uri = convert_item(item)
                if isinstance(uri, str) and uri:
                    all_uris.append(uri)
                    total_configs += 1
                else:
                    errors.append(
                        f"{npvs_path.name}: converter returned no URI for "
                        f"{item.get('name', 'unknown')}"
                    )
            except Exception as e:
                errors.append(
                    f"{npvs_path.name}: error converting "
                    f"{item.get('name', 'unknown')} — {e}"
                )

    with open(output_file, "w", encoding="utf-8") as f:
        f.write("\n".join(all_uris))
        if all_uris:
            f.write("\n")

    print(f"Scanned {len(npvs_files)} file(s) in {target_dir.resolve()}")
    print(f"  (.npvs: {sum(1 for p in npvs_files if p.suffix.lower() == '.npvs')}, "
          f".npvt: {sum(1 for p in npvs_files if p.suffix.lower() == '.npvt')})")
    print(f"Converted {total_configs} config(s)")
    print(f"Output written to: {output_file.resolve()}")

    if errors:
        print("\nWarnings/Errors:")
        for err in errors:
            print(f"  - {err}")


if __name__ == "__main__":
    main()
