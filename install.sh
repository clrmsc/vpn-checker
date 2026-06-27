#!/usr/bin/env bash
#
# Установка vpn-checker на Raspberry Pi OS (Bookworm).
# Ставит Xray-core, Python-зависимости в venv и (опционально) systemd-сервис.
#
set -euo pipefail

APP_DIR="$(cd "$(dirname "$0")" && pwd)"
XRAY_BIN="/usr/local/bin/xray"

echo "==> Каталог приложения: $APP_DIR"

# --- системные пакеты ---------------------------------------------------
echo "==> Проверяю системные пакеты…"
need=()
command -v python3 >/dev/null 2>&1            || need+=(python3)
python3 -m venv --help >/dev/null 2>&1         || need+=(python3-venv)
command -v pip3 >/dev/null 2>&1                || need+=(python3-pip)
command -v curl >/dev/null 2>&1                || need+=(curl)
command -v unzip >/dev/null 2>&1               || need+=(unzip)

if [ ${#need[@]} -gt 0 ]; then
  echo "==> Ставлю недостающие пакеты: ${need[*]}"
  # update может ругаться на сторонние репозитории (plex и т.п.) — это не критично.
  sudo apt-get update -qq || true
  sudo apt-get install -y "${need[@]}"
else
  echo "==> Все нужные пакеты уже установлены — apt не трогаю."
fi

# --- Xray-core ----------------------------------------------------------
if command -v xray >/dev/null 2>&1; then
  echo "==> Xray уже установлен: $(command -v xray)"
else
  echo "==> Определяю архитектуру для Xray…"
  case "$(uname -m)" in
    aarch64|arm64) ZIP="Xray-linux-arm64-v8a.zip" ;;
    armv7l|armhf)  ZIP="Xray-linux-arm32-v7a.zip" ;;
    x86_64|amd64)  ZIP="Xray-linux-64.zip" ;;
    *) echo "Неизвестная архитектура $(uname -m), поставьте Xray вручную" >&2; exit 1 ;;
  esac
  URL="https://github.com/XTLS/Xray-core/releases/latest/download/$ZIP"
  echo "==> Скачиваю $ZIP…"
  TMP="$(mktemp -d)"
  curl -fsSL "$URL" -o "$TMP/xray.zip"
  unzip -o "$TMP/xray.zip" -d "$TMP" >/dev/null
  sudo install -m 0755 "$TMP/xray" "$XRAY_BIN"
  rm -rf "$TMP"
  echo "==> Xray установлен: $XRAY_BIN"
fi

# --- Python venv --------------------------------------------------------
echo "==> Создаю виртуальное окружение…"
python3 -m venv "$APP_DIR/.venv"
"$APP_DIR/.venv/bin/pip" install --quiet --upgrade pip
"$APP_DIR/.venv/bin/pip" install --quiet -r "$APP_DIR/requirements.txt"

echo
echo "==> Готово. Запуск вручную:"
echo "    $APP_DIR/.venv/bin/python $APP_DIR/app.py"
echo "    затем откройте  http://<ip-малинки>:3333"
echo

# --- systemd (опционально) ---------------------------------------------
read -rp "Установить автозапуск через systemd? [y/N] " ans
if [[ "${ans,,}" == "y" ]]; then
  SERVICE="/etc/systemd/system/vpn-checker.service"
  sudo tee "$SERVICE" >/dev/null <<EOF
[Unit]
Description=VPN Checker web UI
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$USER
WorkingDirectory=$APP_DIR
ExecStart=$APP_DIR/.venv/bin/python $APP_DIR/app.py
Restart=on-failure
Environment=XRAY_BIN=$XRAY_BIN

[Install]
WantedBy=multi-user.target
EOF
  sudo systemctl daemon-reload
  sudo systemctl enable --now vpn-checker
  echo "==> Сервис запущен. Статус:  sudo systemctl status vpn-checker"
fi
