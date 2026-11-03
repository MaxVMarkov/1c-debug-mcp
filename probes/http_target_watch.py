"""Появляется ли предмет отладки у сеанса, запущенного БЕЗ /DEBUG.

Вопрос №1 всей затеи: если цель заводится только от клиента с ключом /DEBUG, то
безлюдного триггера не существует — агент обязан иметь GUI-сеанс. Если же rphost
регистрирует в dbgs ЛЮБОЙ сеанс базы (веб-клиент, OData, HTTP-сервис, фоновое
задание), то агент может вызвать серверный код сам, из curl, и отлаживать его.

Замер: UI висит на базе, GUI-сеанс с /DEBUG уже даёт цель `Server`. Параллельно
дергаем OData и HTTP-сервис — и смотрим, добавится ли в снимке вторая цель
(типа `OData`/`HTTPService`) или нет.

usage: python probes/http_target_watch.py [alias] [секунд]
"""
import io
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", "qoder-1c-debug", "server"))
from rdbg_client import RdbgClient  # noqa: E402

ALIAS = sys.argv[1] if len(sys.argv) > 1 else "demo-base"
SECONDS = float(sys.argv[2]) if len(sys.argv) > 2 else 50.0
WEB = "http://localhost:8090/%s" % ALIAS
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..",
                   "evidence", "http_target_watch.txt")


def opener():
    """OData и HTTP-сервисы УТ требуют аутентификации сеанса (401 без неё сессия
    даже не начинается, и цели в снимке не появляется). Учётные данные — только из
    окружения (V8_DB_USER/V8_DB_PASS), в вывод не попадают."""
    user = os.environ.get("V8_DB_USER")
    password = os.environ.get("V8_DB_PASS")
    if not user or not password:
        sys.stderr.write("V8_DB_USER/V8_DB_PASS в окружении нет — без аутентификации, жди 401\n")
        return urllib.request.build_opener()
    mgr = urllib.request.HTTPPasswordMgrWithDefaultRealm()
    mgr.add_password(None, WEB, user, password)
    auth = urllib.request.HTTPBasicAuthHandler(mgr)
    digest = urllib.request.HTTPDigestAuthHandler(mgr)
    return urllib.request.build_opener(auth, digest)


OPENER = None


def get(url, timeout=90):
    try:
        with OPENER.open(url, timeout=timeout) as r:
            body = r.read(400)
            return r.status, body.decode("utf-8", "replace")[:200].replace("\n", " ")
    except urllib.error.HTTPError as e:
        return e.code, (e.read(200).decode("utf-8", "replace") if e.fp else "")
    except Exception as e:
        return "ERR", repr(e)[:160]


def main():
    global OPENER
    OPENER = opener()
    log = io.open(OUT, "w", encoding="utf-8")

    def note(text):
        print(text)
        log.write(text + "\n")
        log.flush()

    client = RdbgClient(timeout=60)
    ui_id, result = client.attach(ALIAS)
    note("attach -> %s ui=%s" % (result, ui_id))
    if result != "registered":
        return 1
    try:
        note("веб-доступ: %s -> %s" % (WEB + "/webroot.txt", get(WEB + "/webroot.txt")))
        odata = "%s/odata/standard.odata/%s?%s" % (
            WEB, urllib.parse.quote("Catalog_Номенклатура"), "$top=400&$format=json")
        note("odata url: %s" % odata)
        seen = set()
        deadline = time.time() + SECONDS
        fired = False
        while time.time() < deadline:
            status, payload = client.post("getDbgTargets", client.envelope(ALIAS, ui_id))
            text = payload.decode("utf-8", "replace")
            kinds = sorted(set(t for t in ("Server", "JOB", "OData", "HTTPService", "WEBClient",
                                           "ManagedClient", "WebSocket") if "<targetType>%s<" % t in text))
            count = text.count("<debugRDBGRequestResponse:id>")
            if (count, tuple(kinds)) not in seen:
                seen.add((count, tuple(kinds)))
                note("%s: целей=%d типы=%s" % (time.strftime("%H:%M:%S"), count, kinds))
                if not fired:
                    fired = True
                    note("  > firing odata: %s" % (get(odata),))
            time.sleep(2)
        note("уникальных снимков: %d" % len(seen))
        note("\n=== последний полный снимок ===\n%s" % text)
        log.flush()
        return 0
    finally:
        note("detach -> HTTP %s" % client.detach(ALIAS, ui_id))
        log.close()


if __name__ == "__main__":
    sys.exit(main())
