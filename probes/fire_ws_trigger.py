"""Выстрел по веб-сервису опубликованной базы — безголовый триггер серверного BSL-кода.

По умолчанию — план обмена `ПланаТакогоНет`: его не существует, и код веб-сервиса падает на
строке 40 своего модуля (`Поле объекта не обнаружено`). Это ран-тайм ошибка языка, её ловит
останов по RTE. Вежливый ответ (как у `GetCustomers` с незарегистрированным устройством) для
останова по ошибке не годится: исключения нет.

Номером/файлом тела можно вызвать ЛЮБУЮ операцию — так проверяется останов по точке в модуле,
который агент выбрал только по XML-исходникам (objectID из ConfigDumpInfo + константа propertyID),
не имея ни профиля конфигуратора, ни предыдущего останова.

Запускать фоном: когда цель встанет, сервер держит запрос открытым, и скрипт закончится
только после Continue.

usage: python probes/fire_ws_trigger.py [alias] [timeout_sec] [service] [body-file]
"""
import io
import os
import sys
import urllib.error
import urllib.request

ALIAS = sys.argv[1] if len(sys.argv) > 1 else "demo-base"
TIMEOUT = float(sys.argv[2]) if len(sys.argv) > 2 else 600.0
SERVICE = sys.argv[3] if len(sys.argv) > 3 else "EnterpriseDataExchange_1_0_1_1"
WEB = "http://localhost:8090/%s" % ALIAS
NS_EDX = "http://www.1c.ru/SSL/EnterpriseDataExchange_1_0_1_1"
if len(sys.argv) > 4:
    BODY = io.open(sys.argv[4], encoding="utf-8").read().strip()
else:
    BODY = ('<ns:TestConnection xmlns:ns="%s"><ns:ExchangePlanName>ПланаТакогоНет</ns:ExchangePlanName>'
            '<ns:PeerCode>probe</ns:PeerCode></ns:TestConnection>' % NS_EDX)


def main():
    mgr = urllib.request.HTTPPasswordMgrWithDefaultRealm()
    mgr.add_password(None, WEB, os.environ.get("V8_DB_USER", ""), os.environ.get("V8_DB_PASS", ""))
    op = urllib.request.build_opener(urllib.request.HTTPBasicAuthHandler(mgr))
    envelope = ('<?xml version="1.0" encoding="utf-8"?><soap:Envelope '
                'xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"'
                ' xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'
                '<soap:Body>%s</soap:Body></soap:Envelope>' % BODY)
    req = urllib.request.Request("%s/ws/%s" % (WEB, SERVICE), data=envelope.encode("utf-8"))
    req.add_header("Content-Type", "text/xml; charset=utf-8")
    req.add_header("SOAPAction", '""')
    print("POST %s/ws/%s" % (WEB, SERVICE))
    try:
        with op.open(req, timeout=TIMEOUT) as r:
            print("HTTP %s\n%s" % (r.status, r.read(2000).decode("utf-8", "replace")))
    except urllib.error.HTTPError as e:
        print("HTTP %s\n%s" % (e.code, (e.read(2000).decode("utf-8", "replace") if e.fp else "")))
    except Exception as e:
        print("ERR %r" % (e,))
    return 0


if __name__ == "__main__":
    sys.exit(main())
