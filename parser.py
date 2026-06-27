"""
Парсинг подписки и отдельных ссылок узлов в готовые outbound-объекты Xray.

Поддерживаются: vless, vmess, trojan, ss (shadowsocks).
Каждый узел превращается в словарь:

    {
        "name":     "человекочитаемое имя (#remark)",
        "protocol": "vless" | "vmess" | "trojan" | "shadowsocks",
        "address":  "host",
        "port":     443,
        "outbound": { ... готовый объект outbounds[0] для Xray ... },
    }

Узлы с неподдерживаемым протоколом пропускаются.
"""

import base64
import json
import re
from urllib.parse import urlsplit, parse_qs, unquote


# ----------------------------------------------------------------- загрузка

def fetch_subscription(url: str, timeout: int = 20) -> str:
    """Скачивает тело подписки. Многие панели требуют «браузерный» User-Agent."""
    import requests  # ленивый импорт: парсинг работает и без сетевой зависимости

    headers = {"User-Agent": "Mozilla/5.0 (vpn-checker)"}
    resp = requests.get(url, headers=headers, timeout=timeout)
    resp.raise_for_status()
    return resp.text


def _b64decode(data: str) -> bytes:
    """Декодирует base64, терпимо относясь к отсутствию паддинга и url-safe варианту."""
    data = data.strip().replace("\n", "").replace("\r", "")
    data = data.replace("-", "+").replace("_", "/")
    data += "=" * (-len(data) % 4)
    return base64.b64decode(data)


def extract_links(body: str) -> list[str]:
    """
    Из тела подписки достаёт список ссылок вида proto://...
    Подписка бывает либо base64-блоком, либо уже готовым списком строк.
    """
    body = body.strip()

    # Если в теле сразу видны схемы — это plain-список.
    if "://" in body:
        candidate = body
    else:
        # Иначе пробуем base64.
        try:
            candidate = _b64decode(body).decode("utf-8", "replace")
        except Exception:
            candidate = body

    links = []
    for line in candidate.splitlines():
        line = line.strip()
        if "://" in line:
            links.append(line)
    return links


# ----------------------------------------------------------------- парсеры

def _stream_settings(network: str, security: str, q: dict, defaults: dict) -> dict:
    """Собирает streamSettings из query-параметров (общая логика для vless/trojan)."""
    network = network or "tcp"
    ss = {"network": network, "security": security or "none"}

    host = q.get("host", [""])[0]
    path = q.get("path", [""])[0]
    service = q.get("serviceName", [""])[0]
    header_type = q.get("headerType", [""])[0]

    if network == "ws":
        ws = {"path": unquote(path) or "/"}
        if host:
            ws["headers"] = {"Host": host}
        ss["wsSettings"] = ws
    elif network in ("grpc", "gun"):
        ss["network"] = "grpc"
        ss["grpcSettings"] = {"serviceName": unquote(service)}
    elif network in ("h2", "http"):
        ss["network"] = "http"
        h = {"path": unquote(path) or "/"}
        if host:
            h["host"] = [host]
        ss["httpSettings"] = h
    elif network == "tcp" and header_type == "http":
        tcp = {"header": {"type": "http"}}
        if host or path:
            tcp["header"]["request"] = {
                "path": [unquote(path) or "/"],
                "headers": {"Host": [host] if host else []},
            }
        ss["tcpSettings"] = tcp

    sni = q.get("sni", [q.get("peer", [defaults.get("sni", "")])[0]])[0] or defaults.get("sni", "")
    fp = q.get("fp", ["chrome"])[0]
    alpn = q.get("alpn", [""])[0]

    if security == "reality":
        ss["realitySettings"] = {
            "serverName": sni,
            "fingerprint": fp or "chrome",
            "publicKey": q.get("pbk", [""])[0],
            "shortId": q.get("sid", [""])[0],
            "spiderX": unquote(q.get("spx", ["/"])[0]) or "/",
        }
    elif security == "tls":
        tls = {"serverName": sni, "fingerprint": fp or "chrome"}
        if alpn:
            tls["alpn"] = alpn.split(",")
        if q.get("allowInsecure", ["0"])[0] in ("1", "true"):
            tls["allowInsecure"] = True
        ss["tlsSettings"] = tls

    return ss


def parse_vless(link: str) -> dict:
    u = urlsplit(link)
    q = parse_qs(u.query)
    uuid = u.username or ""
    host = u.hostname or ""
    port = u.port or 443
    name = unquote(u.fragment) or host

    network = q.get("type", ["tcp"])[0]
    security = q.get("security", ["none"])[0]
    flow = q.get("flow", [""])[0]

    user = {"id": uuid, "encryption": "none"}
    if flow:
        user["flow"] = flow

    outbound = {
        "protocol": "vless",
        "tag": "proxy",
        "settings": {"vnext": [{"address": host, "port": port, "users": [user]}]},
        "streamSettings": _stream_settings(network, security, q, {"sni": host}),
    }
    return {"name": name, "protocol": "vless", "address": host, "port": port, "outbound": outbound}


def parse_trojan(link: str) -> dict:
    u = urlsplit(link)
    q = parse_qs(u.query)
    password = unquote(u.username or "")
    host = u.hostname or ""
    port = u.port or 443
    name = unquote(u.fragment) or host

    network = q.get("type", ["tcp"])[0]
    security = q.get("security", ["tls"])[0]

    outbound = {
        "protocol": "trojan",
        "tag": "proxy",
        "settings": {"servers": [{"address": host, "port": port, "password": password}]},
        "streamSettings": _stream_settings(network, security, q, {"sni": host}),
    }
    return {"name": name, "protocol": "trojan", "address": host, "port": port, "outbound": outbound}


def parse_vmess(link: str) -> dict:
    raw = link[len("vmess://"):]
    cfg = json.loads(_b64decode(raw).decode("utf-8", "replace"))
    host = cfg.get("add", "")
    port = int(cfg.get("port", 443))
    name = cfg.get("ps") or host

    network = cfg.get("net", "tcp")
    security = "tls" if cfg.get("tls") in ("tls", "reality", True) else "none"

    # Переиспользуем общий сборщик через эмуляцию query-параметров.
    q = {
        "host": [cfg.get("host", "")],
        "path": [cfg.get("path", "")],
        "serviceName": [cfg.get("path", "")],
        "sni": [cfg.get("sni", cfg.get("host", "")) or host],
        "headerType": [cfg.get("type", "")],
        "alpn": [cfg.get("alpn", "")],
    }
    ss = _stream_settings(network, security, q, {"sni": host})

    outbound = {
        "protocol": "vmess",
        "tag": "proxy",
        "settings": {"vnext": [{
            "address": host, "port": port,
            "users": [{"id": cfg.get("id", ""), "alterId": int(cfg.get("aid", 0)),
                       "security": cfg.get("scy", "auto")}],
        }]},
        "streamSettings": ss,
    }
    return {"name": name, "protocol": "vmess", "address": host, "port": port, "outbound": outbound}


def parse_ss(link: str) -> dict:
    body = link[len("ss://"):]
    name = ""
    if "#" in body:
        body, frag = body.split("#", 1)
        name = unquote(frag)
    body = body.split("?", 1)[0]

    # Два формата: base64(method:pass)@host:port  или  base64(method:pass@host:port)
    if "@" in body:
        userinfo, hostport = body.rsplit("@", 1)
        try:
            method, password = _b64decode(userinfo).decode().split(":", 1)
        except Exception:
            method, password = unquote(userinfo).split(":", 1)
    else:
        decoded = _b64decode(body).decode("utf-8", "replace")
        userinfo, hostport = decoded.rsplit("@", 1)
        method, password = userinfo.split(":", 1)

    host, port = hostport.rsplit(":", 1)
    port = int(re.sub(r"[^0-9]", "", port))
    name = name or host

    outbound = {
        "protocol": "shadowsocks",
        "tag": "proxy",
        "settings": {"servers": [{
            "address": host, "port": port, "method": method, "password": password,
        }]},
    }
    return {"name": name, "protocol": "shadowsocks", "address": host, "port": port, "outbound": outbound}


_PARSERS = {
    "vless": parse_vless,
    "vmess": parse_vmess,
    "trojan": parse_trojan,
    "ss": parse_ss,
}


def parse_link(link: str) -> dict | None:
    scheme = link.split("://", 1)[0].lower()
    parser = _PARSERS.get(scheme)
    if not parser:
        return None
    try:
        node = parser(link)
        node["link"] = link  # сохраняем исходную ссылку для копирования
        return node
    except Exception:
        return None


def parse_subscription(url_or_body: str) -> list[dict]:
    """
    Принимает либо URL подписки, либо уже скачанное тело.
    Возвращает список распарсенных узлов.
    """
    if url_or_body.strip().startswith(("http://", "https://")):
        body = fetch_subscription(url_or_body.strip())
    else:
        body = url_or_body

    nodes = []
    for link in extract_links(body):
        node = parse_link(link)
        if node:
            nodes.append(node)
    return nodes
