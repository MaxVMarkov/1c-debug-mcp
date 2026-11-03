"""Останов по ран-тайм ошибке (setBreakOnRTE) на безголовом триггере.

Два вопроса, на которые отвечает один прогон:

1. `version` модуля. Точку останова в произвольном модуле агент поставить не может:
   version не хеш текста (probes/module_version_hash.py) и не configVersion из
   ConfigDumpInfo, а correctedBP платформа не присылает (probes/bp_corrected_oracle.py:
   90 с пустого long-poll). Останов по RTE версии не требует вообще.
2. Безголовый триггер. Сеанс без /DEBUG появляется в getDbgTargets (замер 00:28),
   веб-сервисы базы отвечают по SOAP (evidence/wsdl_*.xml) — значит серверный BSL-код
   можно вызвать одним HTTP-запросом, без окна и без клиента на этой машине.

Прогон: поднять UI -> setBreakOnRTE(stopOnErrors=true) -> качать события фоном ->
пакет SOAP-вызовов (валидный Ping и заведомо битые тела) -> смотреть, приедет ли
`stop` и что в нём (в кадре останова есть идентификатор модуля — заодно и version).

usage: python probes/rte_stop_probe.py [alias]
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
NS_DMIL = "http://www.1c.ru/dmil"
NS_COE = "http://www.1c.ru/CustomerOrders/Exchange"
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "evidence",
                   "rte_stop_probe.txt")
PUMP_SEC = 75.0


def note(log, text):
    print(text)
    log.write(text + "\n")
    log.flush()


def soap(opener, service, ns, body_inner, timeout=120):
    envelope = ('<?xml version="1.0" encoding="utf-8"?>'
                '<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">'
                '<soap:Body>%s</soap:Body></soap:Envelope>' % body_inner)
    req = urllib.request.Request("%s/ws/%s" % (WEB, service),
                                 data=envelope.encode("utf-8"))
    req.add_header("Content-Type", "text/xml; charset=utf-8")
    req.add_header("SOAPAction", '""')
    try:
        with opener.open(req, timeout=timeout) as r:
            return r.status, r.read(3000).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, (e.read(3000).decode("utf-8", "replace") if e.fp else "")
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

    stop_seen = []
    raw_events = []
    pump_stop = threading.Event()

    def pump():
        while not pump_stop.is_set():
            try:
                status, payload = client.post("pingDebugUIParams", client.envelope(ALIAS, ui_id),
                                              extra_query="&dbgui=%s&str" % ui_id)
            except Exception as exc:
                note(log, "ping исключение: %r" % exc)
                break
            if payload:
                text = payload.decode("utf-8", "replace")
                raw_events.append(text)
                note(log, "=== событие %s (%d байт)\n%s" % (time.strftime("%H:%M:%S"), len(payload),
                                                            text[:4000]))
                if "<stop>" in text or "errorInfo" in text:
                    stop_seen.append(text)

    def targets_snapshot():
        status, payload = client.post("getDbgTargets", client.envelope(ALIAS, ui_id))
        text = payload.decode("utf-8", "replace")
        rows = []
        for block in text.split("<debugRDBGRequestResponse:id>")[1:]:
            def field(name):
                i = block.find("<%s>" % name)
                return block[i + len(name) + 2:block.find("</%s>" % name, i)] if i >= 0 else "-"
            rows.append((field("seanceNo"), field("targetType"), field("id")))
        return rows

    try:
        status, payload = client.set_break_on_rte(ALIAS, ui_id, stop_on_errors=True)
        note(log, "setBreakOnRTE(stop) -> HTTP %s, тело %r" % (status, payload[:300]))
        note(log, "getBreakOnRTE -> %s" % (client.get_break_on_rte(ALIAS, ui_id),))
        note(log, "цели до: %s" % targets_snapshot())

        t = threading.Thread(target=pump)
        t.daemon = True
        t.start()

        calls = [
            ("DMILService", NS_DMIL, '<ns:execute xmlns:ns="%s"><ns:arg1>ping</ns:arg1></ns:execute>' % NS_DMIL),
            ("CustomerOrdersExchange", NS_COE,
             '<ns:Ping xmlns:ns="%s"><ns:deviceID>probe</ns:deviceID></ns:Ping>' % NS_COE),
            ("CustomerOrdersExchange", NS_COE,
             '<ns:Ping xmlns:ns="%s"></ns:Ping>' % NS_COE),
            ("CustomerOrdersExchange", NS_COE,
             '<ns:GetCustomers xmlns:ns="%s"><ns:bogus>1</ns:bogus><ns:bogus>2</ns:bogus>'
             '</ns:GetCustomers>' % NS_COE),
            ("CustomerOrdersExchange", NS_COE,
             '<ns:NoSuchOperation xmlns:ns="%s"><ns:a>1</ns:a></ns:NoSuchOperation>' % NS_COE),
        ]
        for service, ns, body in calls:
            code, text = soap(opener, service, ns, body)
            note(log, "SOAP %s <- %s\n%s" % (service, code, text[:900]))
            if stop_seen:
                break
            time.sleep(2)

        note(log, "жду события ещё 10 с...")
        time.sleep(10)
        pump_stop.set()
        t.join(timeout=15)
        note(log, "цели после: %s" % targets_snapshot())
        note(log, "ИТОГО: событий %d, останов %d" % (len(raw_events), len(stop_seen)))
        if stop_seen:
            note(log, "первый останов:\n%s" % stop_seen[0][:6000])
        return 0
    finally:
        try:
            client.set_break_on_rte(ALIAS, ui_id, stop_on_errors=False)
        except Exception as exc:
            note(log, "снять RTE не удалось: %r" % exc)
        note(log, "detach -> HTTP %s" % client.detach(ALIAS, ui_id))
        pump_stop.set()
        log.close()


if __name__ == "__main__":
    sys.exit(main())
