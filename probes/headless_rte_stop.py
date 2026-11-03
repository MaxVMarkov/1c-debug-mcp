"""Цельный безголовый останов: auto-attach + stopOnErrors + один HTTP-вызов.

Собрано из трёх уже подтверждённых сегодня вещей:

* сеанс без `/DEBUG` появляется в getDbgTargets (замер 00:28, evidence/job_target_watch_raw.txt);
* `/ws/` базы опубликован и отвечает, WSDL снят (evidence/wsdl_*.xml);
* `setBreakOnRTE` принимается и читается обратно (evidence/rte_stop_probe.txt).

Не хватало успеть присоединиться к цели, которая живёт секунды, — для этого
`setAutoAttachSettings` (debugAutoAttach.xsd: список targetType, на которые UI цепляется
сам). Ставим auto-attach на Server/JOB/HTTPService/WEBService + останов по RTE, затем
одним POST вызываем веб-сервис `GetCustomers` с незарегистрированным устройством:
обмен в УТ на это отвечает исключением уровня BSL.

Если приезжает `stop` — в кадре есть moduleID с objectID/propertyID/version: это и есть
оракул версий, которого не хватало для точек в произвольных модулях.

usage: python probes/headless_rte_stop.py [alias]
"""
import io
import os
import sys
import threading
import time
import urllib.error
import urllib.request

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", "qoder-1c-debug", "server"))
from rdbg_client import RdbgClient  # noqa: E402

ALIAS = sys.argv[1] if len(sys.argv) > 1 else "demo-base"
WEB = "http://localhost:8090/%s" % ALIAS
NS_COE = "http://www.1c.ru/CustomerOrders/Exchange"
NS_EDX = "http://www.1c.ru/SSL/EnterpriseDataExchange_1_0_1_1"
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "evidence",
                   "headless_rte_stop.txt")
PUMP_SEC = 60.0
TYPES = ("Server", "JOB", "HTTPService", "WEBService", "ManagedClient", "WEBClient")


def note(log, text):
    print(text)
    log.write(text + "\n")
    log.flush()


def soap_call(opener, service, body_inner):
    envelope = ('<?xml version="1.0" encoding="utf-8"?>'
                '<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"'
                ' xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'
                '<soap:Body>%s</soap:Body></soap:Envelope>' % body_inner)
    req = urllib.request.Request("%s/ws/%s" % (WEB, service), data=envelope.encode("utf-8"))
    req.add_header("Content-Type", "text/xml; charset=utf-8")
    req.add_header("SOAPAction", '""')
    try:
        with opener.open(req, timeout=150) as r:
            return r.status, r.read(4000).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, (e.read(4000).decode("utf-8", "replace") if e.fp else "")
    except Exception as e:
        return "ERR", repr(e)[:300]


def main():
    log = io.open(OUT, "w", encoding="utf-8")
    mgr = urllib.request.HTTPPasswordMgrWithDefaultRealm()
    mgr.add_password(None, WEB, os.environ.get("V8_DB_USER", ""), os.environ.get("V8_DB_PASS", ""))
    opener = urllib.request.build_opener(urllib.request.HTTPBasicAuthHandler(mgr))
    client = RdbgClient(timeout=60)
    ui_id, result = client.attach(ALIAS)
    note(log, "attach -> %s ui=%s" % (result, ui_id))
    if result != "registered":
        return 1

    events, stops = [], []
    pump_stop = threading.Event()

    def pump():
        while not pump_stop.is_set():
            try:
                status, payload = client.post("pingDebugUIParams", client.envelope(ALIAS, ui_id),
                                              extra_query="&dbgui=%s&str" % ui_id)
            except Exception as exc:
                note(log, "ping исключение: %r" % exc)
                return
            if payload:
                text = payload.decode("utf-8", "replace")
                events.append(text)
                note(log, "=== событие %s\n%s" % (time.strftime("%H:%M:%S"), text[:5000]))
                if "errorInfo" in text or "<stop>" in text or "stopByBP" in text:
                    stops.append(text)

    def targets():
        status, payload = client.post("getDbgTargets", client.envelope(ALIAS, ui_id))
        return payload.decode("utf-8", "replace")

    try:
        note(log, "setAutoAttachSettings -> %s" % (client.set_auto_attach(ALIAS, ui_id, TYPES)[0],))
        note(log, "getAutoAttachSettings -> %s" % (client.get_auto_attach(ALIAS, ui_id),))
        note(log, "setBreakOnRTE -> %s" % (client.set_break_on_rte(ALIAS, ui_id, True)[0],))
        t = threading.Thread(target=pump)
        t.daemon = True
        t.start()

        bodies = [
            # план обмена с несуществующим именем: получить его в БСП — исключение языка
            ("EnterpriseDataExchange_1_0_1_1",
             '<ns:TestConnection xmlns:ns="%s"><ns:ExchangePlanName>ПланаТакогоНет</ns:ExchangePlanName>'
             '<ns:PeerCode>probe</ns:PeerCode></ns:TestConnection>' % NS_EDX),
            ("EnterpriseDataExchange_1_0_1_1",
             '<ns:Ping xmlns:ns="%s"><ns:ExchangePlanName>ПланаТакогоНет</ns:ExchangePlanName>'
             '<ns:PeerCode>probe</ns:PeerCode></ns:Ping>' % NS_EDX),
            ("EnterpriseDataExchange_1_0_1_1",
             '<ns:PrepareDataForGetting xmlns:ns="%s">'
             '<ns:ExchangePlanName>ПланаТакогоНет</ns:ExchangePlanName>'
             '<ns:PeerCode>probe</ns:PeerCode></ns:PrepareDataForGetting>' % NS_EDX),
        ]
        for service, body in bodies:
            code, text = soap_call(opener, service, body)
            note(log, "SOAP %s -> %s\n%s" % (service, code, text[:900]))
            if stops:
                break
            time.sleep(2)
        note(log, "цели сразу после: %s" % [ln for ln in targets().split("<seanceNo>")][1:])
        deadline = time.time() + PUMP_SEC
        while time.time() < deadline and not stops:
            time.sleep(2)
        note(log, "ИТОГО: событий %d, остановов %d" % (len(events), len(stops)))
        return 0
    finally:
        pump_stop.set()
        time.sleep(1)
        try:
            client.set_break_on_rte(ALIAS, ui_id, stop_on_errors=False)
            client.set_auto_attach(ALIAS, ui_id, ())
        except Exception as exc:
            note(log, "сброс настроек не удался: %r" % exc)
        note(log, "detach -> HTTP %s" % client.detach(ALIAS, ui_id))
        log.close()


if __name__ == "__main__":
    sys.exit(main())
