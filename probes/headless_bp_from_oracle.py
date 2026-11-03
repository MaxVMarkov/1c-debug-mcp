"""Точка останова в модуле, версию которого агент снял с кадра останова.

Длинная стена этого проекта: `bpWorkspace` требует `version` модуля, а взять его было
неоткуда — в XML-исходниках его нет (docs §4), хешем текста он не является
(probes/module_version_hash.py: 48 комбинаций, 0 совпадений), configVersion из
ConfigDumpInfo не совпадает, а `correctedBP` платформа не присылает
(probes/bp_corrected_oracle.py: 90 с пустого long-poll).

Обход, который это проверяет: version приезжает САМ в кадре `callStackFormed` (баг
парсинга — `objectID/propertyID/version` лежат внутри `<moduleID>` — исправлен 2026-10-17).
Значит достаточно один раз попасть в модуль на останове по ран-тайм ошибке, считать
идентификатор модуля, и дальше ставить в него обычную точку.

Сценарий на живом триггере (веб-сервис EnterpriseDataExchange с планом обмена, которого
нет — код падает на строке 40 модуля):

  1. auto-attach + stopOnErrors -> SOAP -> останов -> снять objectID/propertyID/version;
  2. stopOnErrors выключить, поставить точку на строку 37 той же копии модуля;
  3. повторить SOAP -> останов ДОМЕННО точкой (RTE уже не вооружён) -> eval -> Continue.

usage: python probes/headless_bp_from_oracle.py [alias]
"""
import io
import os
import sys
import threading
import time
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "qoder-1c-debug", "server"))
import mcp_core  # noqa: E402

ALIAS = sys.argv[1] if len(sys.argv) > 1 else "demo-base"
WEB = "http://localhost:8090/%s" % ALIAS
NS_EDX = "http://www.1c.ru/SSL/EnterpriseDataExchange_1_0_1_1"
BP_LINE = 37
OUT = os.path.join(HERE, "..", "evidence", "headless_bp_from_oracle.txt")


def call(tool, args):
    out = mcp_core.call(tool, args)
    print("-- %s(%s)\n%s" % (tool, args, out))
    return out


def fire_soap():
    """Веб-сервис падает на строке 40: {WebСервис…Модуль(40)} Поле объекта не обнаружено."""
    mgr = urllib.request.HTTPPasswordMgrWithDefaultRealm()
    mgr.add_password(None, WEB, os.environ.get("V8_DB_USER", ""), os.environ.get("V8_DB_PASS", ""))
    op = urllib.request.build_opener(urllib.request.HTTPBasicAuthHandler(mgr))
    body = ('<ns:TestConnection xmlns:ns="%s"><ns:ExchangePlanName>ПланаТакогоНет</ns:ExchangePlanName>'
            '<ns:PeerCode>probe</ns:PeerCode></ns:TestConnection>' % NS_EDX)
    envelope = ('<?xml version="1.0" encoding="utf-8"?><soap:Envelope '
                'xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body>%s</soap:Body>'
                '</soap:Envelope>' % body)
    req = urllib.request.Request("%s/ws/EnterpriseDataExchange_1_0_1_1" % WEB,
                                 data=envelope.encode("utf-8"))
    req.add_header("Content-Type", "text/xml; charset=utf-8")
    req.add_header("SOAPAction", '""')
    try:
        with op.open(req, timeout=240) as r:
            return r.status, r.read(300).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, (e.read(300).decode("utf-8", "replace") if e.fp else "")
    except Exception as e:
        return "ERR", repr(e)[:200]


def fire_and_wait(label, timeout=45):
    box = {}
    t = threading.Thread(target=lambda: box.update({"r": fire_soap()}))
    t.daemon = True
    t.start()
    print("%s: SOAP отправлен" % label)
    stopped = call("wait_stop", {"base": ALIAS, "timeout": timeout})
    t.join(timeout=5)
    return stopped, box.get("r")


def main():
    log = io.open(OUT, "w", encoding="utf-8")
    real_stdout = sys.stdout

    class Tee:
        def write(self, data):
            log.write(data)
            real_stdout.write(data)

        def flush(self):
            log.flush()
            real_stdout.flush()

    sys.stdout = Tee()
    try:
        call("session_start", {"base": ALIAS, "wait": 20})
        call("auto_attach_targets", {"base": ALIAS, "types": ["Server", "JOB", "WEBService", "HTTPService"]})

        # фаза 1: останов по RTE и съём идентификаторов модуля
        call("stop_on_error", {"base": ALIAS, "on": True})
        stopped, answer = fire_and_wait("фаза 1 (RTE)")
        frames = (stopped or {}).get("frames") or []
        if not frames:
            print("фаза 1 не удалась: останова нет; SOAP=%s" % (answer,))
            return 1
        oracle = frames[0]
        print("оракул: module=%s property=%s version=%s line=%s"
              % (oracle["module"], oracle["property"], oracle["version"], oracle["line"]))
        call("step", {"base": ALIAS, "action": "Continue"})
        call("stop_on_error", {"base": ALIAS, "on": False})

        # фаза 2: обычная точка со снятыми идентификаторами, RTE больше не вооружён
        call("breakpoints_set", {"base": ALIAS, "modules": [{
            "objectID": oracle["module"], "propertyID": oracle["property"],
            "version": oracle["version"], "lines": [BP_LINE]}]})
        stopped, answer = fire_and_wait("фаза 2 (точка %d)" % BP_LINE)
        frames = (stopped or {}).get("frames") or []
        hit = frames and frames[0].get("line") == str(BP_LINE)
        print("фаза 2: останов на строке %s, ожидалась %d -> %s"
              % (frames and frames[0].get("line"), BP_LINE, "ТОЧКА РАБОТАЕТ" if hit else "НЕ ТА СТРОКА"))
        if frames:
            call("eval", {"base": ALIAS, "expression": "ИмяПланаОбмена"})
            call("locals", {"base": ALIAS})
        call("step", {"base": ALIAS, "action": "Continue"})
        call("breakpoints_clear", {"base": ALIAS})
        call("auto_attach_targets", {"base": ALIAS, "types": []})
        print("SOAP-ответ фазы 2: %s" % (answer,))
        call("session_stop", {"base": ALIAS})
        return 0 if hit else 1
    finally:
        sys.stdout = real_stdout
        log.close()


if __name__ == "__main__":
    sys.exit(main())
