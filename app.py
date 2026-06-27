"""
Flask-приложение: веб-интерфейс для проверки VPN-узлов из подписки.

Маршруты:
  GET  /                  — страница с полем ввода и таблицей результатов
  GET  /api/parse?url=    — распарсить подписку, вернуть количество узлов
  GET  /api/check?url=    — SSE-поток: по событию на каждый проверенный узел
"""

import json

from flask import Flask, Response, render_template, request, stream_with_context

import checker
import parser as sub_parser

app = Flask(__name__)


@app.route("/")
def index():
    return render_template("index.html", xray_ok=checker.xray_available())


@app.route("/api/parse")
def api_parse():
    url = request.args.get("url", "").strip()
    if not url:
        return {"error": "пустая ссылка"}, 400
    try:
        nodes = sub_parser.parse_subscription(url)
    except Exception as e:
        return {"error": f"не удалось загрузить подписку: {e}"}, 502
    return {"count": len(nodes)}


@app.route("/api/check")
def api_check():
    url = request.args.get("url", "").strip()

    def event(obj):
        return f"data: {json.dumps(obj, ensure_ascii=False)}\n\n"

    @stream_with_context
    def gen():
        if not checker.xray_available():
            yield event({"type": "error", "message": "Xray не установлен (см. install.sh)"})
            return
        try:
            nodes = sub_parser.parse_subscription(url)
        except Exception as e:
            yield event({"type": "error", "message": f"Подписка не загрузилась: {e}"})
            return

        if not nodes:
            yield event({"type": "error", "message": "В подписке не найдено поддерживаемых узлов"})
            return

        yield event({"type": "start", "total": len(nodes)})
        for i, res in enumerate(checker.test_all(nodes)):
            res["type"] = "result"
            res["index"] = i
            yield event(res)
        yield event({"type": "done"})

    return Response(gen(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=3333, threaded=True)
