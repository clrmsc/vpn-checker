"""
Тестирование узлов: поднимаем Xray с локальным SOCKS-входом, через него
проверяем доступность google.com, затем меряем скорость скачивания.

Узлы проверяются последовательно — это важно для честного замера скорости
(параллельные загрузки делят канал и искажают результат).
"""

import json
import os
import shutil
import socket
import subprocess
import tempfile
import time

# --- настройки (можно переопределить через переменные окружения) ---------

XRAY_BIN = os.environ.get("XRAY_BIN") or shutil.which("xray") or "/usr/local/bin/xray"
SOCKS_PORT = int(os.environ.get("VC_SOCKS_PORT", "10810"))

# Чем проверяем «загрузился ли google»: 204 без тела, быстро и однозначно.
CONNECT_URL = os.environ.get("VC_CONNECT_URL", "https://www.google.com/generate_204")
CONNECT_TIMEOUT = int(os.environ.get("VC_CONNECT_TIMEOUT", "8"))

# Чем меряем скорость. Cloudflare отдаёт ровно запрошенное число байт.
SPEED_URL = os.environ.get("VC_SPEED_URL", "https://speed.cloudflare.com/__down?bytes=20000000")
SPEED_TIMEOUT = int(os.environ.get("VC_SPEED_TIMEOUT", "15"))


def xray_available() -> bool:
    return bool(shutil.which(XRAY_BIN) or os.path.exists(XRAY_BIN))


def _wait_port(port: str, host: str = "127.0.0.1", timeout: float = 4.0) -> bool:
    """Ждём, пока Xray откроет SOCKS-порт."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.3)
            if s.connect_ex((host, port)) == 0:
                return True
        time.sleep(0.1)
    return False


def _build_config(outbound: dict, port: int) -> dict:
    return {
        "log": {"loglevel": "none"},
        "inbounds": [{
            "tag": "socks-in",
            "listen": "127.0.0.1",
            "port": port,
            "protocol": "socks",
            "settings": {"udp": True},
        }],
        "outbounds": [outbound],
    }


def _curl(url: str, write_out: str, timeout: int, port: int) -> str:
    """Запрос через SOCKS-прокси Xray. --socks5-hostname резолвит DNS на той стороне."""
    cmd = [
        "curl", "-s", "-o", "/dev/null",
        "--socks5-hostname", f"127.0.0.1:{port}",
        "--max-time", str(timeout),
        "-w", write_out,
        url,
    ]
    out = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 3)
    return out.stdout.strip()


def test_node(node: dict, port: int = SOCKS_PORT) -> dict:
    """
    Возвращает результат: status ok|dead|error, latency_ms, speed_mbps.
    """
    result = {
        "name": node["name"],
        "protocol": node["protocol"],
        "address": f'{node["address"]}:{node["port"]}',
        "link": node.get("link", ""),
        "status": "dead",
        "latency_ms": None,
        "speed_mbps": None,
        "error": None,
    }

    cfg = _build_config(node["outbound"], port)
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
        json.dump(cfg, f)
        cfg_path = f.name

    proc = None
    try:
        proc = subprocess.Popen(
            [XRAY_BIN, "run", "-c", cfg_path],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        if not _wait_port(port):
            result["status"] = "error"
            result["error"] = "xray не запустился"
            return result

        # 1) Проверка доступности google.
        try:
            out = _curl(CONNECT_URL, "%{http_code} %{time_total}", CONNECT_TIMEOUT, port)
            code, t_total = out.split()
            if code in ("200", "204"):
                result["status"] = "ok"
                result["latency_ms"] = round(float(t_total) * 1000)
            else:
                result["error"] = f"http {code}"
                return result
        except Exception as e:
            result["error"] = f"нет связи ({e.__class__.__name__})"
            return result

        # 2) Скорость — только если узел жив.
        try:
            bps = _curl(SPEED_URL, "%{speed_download}", SPEED_TIMEOUT, port)
            speed = float(bps) * 8 / 1_000_000  # байт/с -> Мбит/с
            result["speed_mbps"] = round(speed, 1)
        except Exception:
            result["speed_mbps"] = 0.0

        return result

    except Exception as e:
        result["status"] = "error"
        result["error"] = str(e)
        return result
    finally:
        if proc:
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()
        try:
            os.unlink(cfg_path)
        except OSError:
            pass


def test_all(nodes: list[dict]):
    """Генератор: тестирует узлы по очереди, отдавая результат сразу."""
    for node in nodes:
        yield test_node(node)
