"""Приёмка безголового цикла: цель появляется от HTTP-вызова, останов, eval, continue.

Повторяет probes/headless_rte_stop.py, но идёт через инструменты ядра (mcp_core), то есть
ровно через тот код, который стоит в плагине: session_start -> auto_attach_targets ->
stop_on_error -> SOAP-вызов веб-сервиса -> wait_stop -> eval -> locals -> step(Continue) ->
stop_on_error(off). Тригмер —enterprise-обмен с планом обмена, которого нет: БСП на этом
падает исключением уровня языка, а не «вежливым» сообщением (замер 2026-10-17 00:5x:
вежливый ответ на GetCustomers останова не даёт).

usage: python probes/headless_acceptance.py [alias]
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
BODY = ('<ns:TestConnection xmlns:ns="%s" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'
        '<ns:ExchangePlanName>ПланаТакогоНет</ns:ExchangePlanName>'
        '<ns:PeerCode>probe</ns:PeerCode></ns:TestConnection>' % NS_EDX)
OUT = os.path.join(HERE, "..", "evidence", "headless_acceptance_0_0_8.txt")


def call(tool, args):
    out = mcp_core.call(tool, args)
    print("-- %s(%s)\n%s" % (tool, args, out))
    return out


def fire_soap():
    mgr = urllib.request.HTTPPasswordMgrWithDefaultRealm()
    mgr.add_password(None, WEB, os.environ.get("V8_DB_USER", ""), os.environ.get("V8_DB_PASS", ""))
    op = urllib.request.build_opener(urllib.request.HTTPBasicAuthHandler(mgr))
    envelope = ('<?xml version="1.0" encoding="utf-8"?><soap:Envelope '
                'xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body>%s</soap:Body>'
                '</soap:Envelope>' % BODY)
    req = urllib.request.Request("%s/ws/EnterpriseDataExchange_1_0_1_1" % WEB,
                                 data=envelope.encode("utf-8"))
    req.add_header("Content-Type", "text/xml; charset=utf-8")
    req.add_header("SOAPAction", '""')
    try:
        with op.open(req, timeout=180) as r:
            return r.status, r.read(500).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, (e.read(500).decode("utf-8", "replace") if e.fp else "")
    except Exception as e:
        return "ERR", repr(e)[:200]


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
        call("auto_attach_targets", {"base": ALIAS,
                                     "types": ["Server", "JOB", "HTTPService", "WEBService"]})
        call("stop_on_error", {"base": ALIAS, "on": True})
        box = {}
        t = threading.Thread(target=lambda: box.update({"r": fire_soap()}))
        t.daemon = True
        t.start()
        print("SOAP отправлен, жду останов...")
        stopped = call("wait_stop", {"base": ALIAS, "timeout": 45})
        if not stopped or stopped.get("timeout"):
            print("останова нет")
            return 1
        frame = (stopped.get("frames") or [{}])[0]
        print("кадр: %s" % frame)
        session = mcp_core._sessions.get(ALIAS)
        for ev in list(session.events)[-14:]:
            print("СОБЫТИЕ %r" % (mcp_core._shape(ev),))
        print("снимок целей после останова:")
        for row in session.client.targets(ALIAS, session.ui_id):
            print("   %r" % (row,))
        call("eval", {"base": ALIAS, "expression": "ИмяПланаОбмена"})
        call("eval", {"base": ALIAS, "expression": "Длина(ИмяПланаОбмена) + '-A'"})
        call("locals", {"base": ALIAS})
        call("step", {"base": ALIAS, "action": "Continue"})
        call("stop_on_error", {"base": ALIAS, "on": False})
        call("auto_attach_targets", {"base": ALIAS, "types": []})
        t.join(timeout=20)
        print("SOAP-ответ: %s" % (box.get("r"),))
        call("session_stop", {"base": ALIAS})
        return 0
    finally:
        sys.stdout = real_stdout
        log.close()


if __name__ == "__main__":
    sys.exit(main())
