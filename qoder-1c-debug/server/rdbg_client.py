"""RDBG client — управление режимом отладки 1С:Предприятие 8.5 через dbgs.exe.

Формат запросов/ответов воспроизведён по живому захвату трафика конфигуратора
(docs/rdbg-protocol-2026-10-09.md), а не по
догадкам: маршрут `POST /e1crdbg/rdbg?cmd=<команда>`, конверт `<request>` в пространстве
debugBaseData, параметры в префиксе схемы команды, полиморфный `<result>` ответа через
xsi:type, значения в base64.

Transport-особенности, без которых клиент ломается:

* dbgs не закрывает соединение даже при `Connection: close` — читать ровно
  `Content-Length`, иначе чтение виснет;
* пустой heartbeat — это `204 No Content`, тела нет вовсе;
* события приходят ответом на уже отправленный `pingDebugUIParams` (период 5 с, одно
  событие за ответ), поэтому long-poll надо держать постоянно, а не опрашивать состояние
  после каждой команды.

Зависимости — только стандартная библиотека.
"""
import base64
import http.client
import uuid
import xml.etree.ElementTree as ET

NS_BASE = "http://v8.1c.ru/8.3/debugger/debugBaseData"
NS_RDBG = "http://v8.1c.ru/8.3/debugger/debugRDBGRequestResponse"
NS_BP = "http://v8.1c.ru/8.3/debugger/debugBreakpoints"
NS_CALC = "http://v8.1c.ru/8.3/debugger/debugCalculations"
NS_DBGUI = "http://v8.1c.ru/8.3/debugger/debugDBGUICommands"
NS_RTE = "http://v8.1c.ru/8.3/debugger/debugRTEFilter"
NS_AUTO = "http://v8.1c.ru/8.3/debugger/debugAutoAttach"
XSI = "http://www.w3.org/2001/XMLSchema-instance"

BOM = b"\xef\xbb\xbf"
TYPE_BOOLEAN, TYPE_NUMBER, TYPE_STRING, TYPE_CONTEXT = 2, 3, 4, 100


def local(tag):
    return tag.split("}")[-1] if "}" in tag else tag


def text(elem, name):
    if elem is None:
        return None
    for child in elem:
        if local(child.tag) == name:
            return (child.text or "").strip()
    return None


def kids(elem, name):
    return [c for c in elem if local(c.tag) == name] if elem is not None else []


def b64(value):
    return base64.b64decode(value).decode("utf-8", "replace") if value else None


def esc(value):
    return str(value).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


class DebugTarget:
    def __init__(self, elem):
        self.id = text(elem, "id")
        self.seance_id = text(elem, "seanceId")
        self.seance_no = text(elem, "seanceNo")
        self.info_base_alias = text(elem, "infoBaseAlias")
        self.info_base_instance_id = text(elem, "infoBaseInstanceID")
        self.user_name = text(elem, "userName")
        self.config_version = text(elem, "configVersion")
        self.target_type = text(elem, "targetType") or "Server"
        self.state = text(elem, "state")
        self.state_num = text(elem, "stateNum")

    def __repr__(self):
        return ("DebugTarget(id=%s base=%s seance=%s type=%s state=%s)"
                % (self.id, self.info_base_alias, self.seance_no, self.target_type, self.state))


class EvalResult:
    """evalExpr / evalLocalVariables / modifyValue: результат в <result> или <newValueState>."""

    def __init__(self, elem):
        self.state = text(elem, "evalResultState")
        self.expression_result_id = text(elem, "expressionResultID")
        self.error = b64(text(elem, "exceptionStr"))
        info = (kids(elem, "resultValueInfo") or [None])[0]
        self.type_name = text(info, "typeName")
        self.type_code = text(info, "typeCode")
        self.value = self._decode(info)
        self.presentation = b64(text(info, "pres"))

    @staticmethod
    def _decode(info):
        # Ключом служит typeCode: одно и то же значение лежит в разных элементах
        # (valueBoolean / valueDecimal / value), а «Неопределено» приходит без значения.
        if info is None:
            return None
        boolean = text(info, "valueBoolean")
        if boolean is not None:
            return boolean == "true"
        number = text(info, "valueDecimal")
        if number is not None:
            return number
        # строки приходят в valueString: отдельного элемента `value` в протоколе нет
        for name in ("valueString", "value"):
            raw = text(info, name)
            if raw is not None:
                return b64(raw)
        return None

    @property
    def ok(self):
        return self.state == "correctly"

    def __repr__(self):
        return "EvalResult(%s %s=%r err=%r)" % (self.state, self.type_name, self.value, self.error)


class ContextValue:
    def __init__(self, elem):
        prop = (kids(elem, "propInfo") or [None])[0]
        # propName приходит открытым текстом, а presentation — base64; путать их нельзя.
        self.name = text(prop, "propName")
        self.read = text(prop, "isReaded") == "true"
        info = (kids(elem, "valueInfo") or [None])[0]
        self.type_name = text(info, "typeName")
        self.value = EvalResult._decode(info)
        self.presentation = b64(text(info, "pres"))

    def __repr__(self):
        return "ContextValue(%s: %s = %r)" % (self.name, self.type_name, self.value)


class StackFrame:
    def __init__(self, elem):
        # objectID/propertyID/version лежат ВНУТРИ <moduleID>, а не рядом с lineNo. Без
        # спуска в него кадр приезжает без версии модуля — а version из кадра останова и
        # есть единственный источник версии для точки в модуле, которого нет в
        # XML-исходниках (замер 2026-10-17, docs §17).
        source = (kids(elem, "moduleID") or [elem])[0]
        self.module_id = text(source, "objectID")
        self.property_id = text(source, "propertyID")
        self.version = text(source, "version")
        self.module_type = text(source, "type")
        self.extension_name = text(source, "extensionName")
        self.line_no = text(elem, "lineNo")
        self.presentation = b64(text(elem, "presentation"))
        self.is_fantom = text(elem, "isFantom")

    def __repr__(self):
        return "StackFrame(line=%s %s)" % (self.line_no, (self.presentation or "")[:70])


class Event:
    """Сообщение из <result xsi:type="...DBGUIExtCmdInfo*"> — ответ на ping."""

    def __init__(self, result):
        self.kind = (result.get("{%s}type" % XSI) or "").split(":")[-1]
        self.cmd_id = text(result, "cmdID")
        self.cmd_num = text(result, "cmdIDNum")
        self.target_id_str = text(result, "targetIDStr")
        self.stop_by_bp = text(result, "stopByBP")
        self.frames = [StackFrame(f) for f in kids(result, "callStack")]
        payload = ((kids(result, "evalExprResBaseData") + kids(result, "newValueState") + [None])[0]
                   # синхронный ответ evalExpr кладёт поля вычисления прямо в <result>
                   if (kids(result, "evalExprResBaseData") + kids(result, "newValueState"))
                   else (result if text(result, "evalResultState") is not None else None))
        self.eval = EvalResult(payload) if payload is not None else None
        self.expression_result_id = (self.eval.expression_result_id if self.eval else None)
        # calculationResult встречается на двух уровнях: внутри evalExprResBaseData
        # (событие exprEvaluated от evalLocalVariables) и прямо в <result>.
        calc = ((kids(payload, "calculationResult") if payload is not None else [])
                + kids(result, "calculationResult") + [None])[0]
        self.context = ([ContextValue(v) for v in kids(calc, "valueOfContextPropInfo")]
                        if calc is not None else [])

    def __repr__(self):
        return ("Event(%s frames=%d context=%d eval=%r)"
                % (self.cmd_id or self.kind, len(self.frames), len(self.context), self.eval))


class ModuleBreakpoints:
    """Один модуль в bpWorkspace. propertyID/version вывести из исходников нельзя —
    их надо брать из перехваченного bpWorkspace (docs §4)."""

    def __init__(self, object_id, property_id, version, lines, module_type=None, extension_name=None):
        self.object_id, self.property_id, self.version = object_id, property_id, version
        self.lines, self.module_type, self.extension_name = lines, module_type, extension_name

    def to_xml(self):
        idn = "<debugBreakpoints:id>"
        if self.module_type:
            idn += "<type>%s</type>" % esc(self.module_type)
        if self.extension_name:
            idn += "<extensionName>%s</extensionName>" % esc(self.extension_name)
        idn += ("<objectID>%s</objectID><propertyID>%s</propertyID>"
                "<version>%s</version></debugBreakpoints:id>"
                % (self.object_id, self.property_id, self.version))
        bps = "".join("<debugBreakpoints:bpInfo><debugBreakpoints:line>%d</debugBreakpoints:line>"
                      "<debugBreakpoints:hitCount>1</debugBreakpoints:hitCount>"
                      "</debugBreakpoints:bpInfo>" % line for line in self.lines)
        return "<debugBreakpoints:moduleBPInfo>%s%s</debugBreakpoints:moduleBPInfo>" % (idn, bps)


class RdbgError(Exception):
    pass


class RdbgClient:
    def __init__(self, host="127.0.0.1", port=1550, timeout=30):
        self.host, self.port, self.timeout = host, port, timeout

    # ---------------- транспорт ----------------

    def post(self, cmd, inner_xml, endpoint="rdbg", extra_ns="", extra_query=""):
        namespaces = ' xmlns:debugRDBGRequestResponse="%s"%s' % (NS_RDBG, extra_ns)
        body = BOM + ('<?xml version="1.0" encoding="UTF-8"?><request xmlns="%s"%s'
                      ' xmlns:v8="http://v8.1c.ru/8.1/data/core"'
                      ' xmlns:xs="http://www.w3.org/2001/XMLSchema"'
                      ' xmlns:xsi="%s">%s</request>'
                      % (NS_BASE, namespaces, XSI, inner_xml)).encode("utf-8")
        conn = http.client.HTTPConnection(self.host, self.port, timeout=self.timeout)
        try:
            conn.putrequest("POST", "/e1crdbg/%s?cmd=%s%s" % (endpoint, cmd, extra_query),
                            skip_accept_encoding=True)
            conn.putheader("Accept", "application/xml")
            conn.putheader("Accept-Charset", "utf-8")
            conn.putheader("Content-Type", "application/xml; charset=utf-8")
            conn.putheader("Content-Length", str(len(body)))
            conn.putheader("Connection", "close")
            conn.endheaders(body)
            resp = conn.getresponse()
            return resp.status, (b"" if resp.status == 204 else resp.read())
        finally:
            conn.close()

    @staticmethod
    def parse(payload):
        return ET.fromstring(payload.decode("utf-8-sig")) if payload else None

    @staticmethod
    def unwrap(root):
        for name in ("result", "newValueState", "item", "id"):
            found = kids(root, name)
            if found:
                return found[0]
        return root

    @staticmethod
    def envelope(alias, ui_id, inner=""):
        P = NS_RDBG
        return ('<debugRDBGRequestResponse:infoBaseAlias>%s</debugRDBGRequestResponse:infoBaseAlias>'
                '<debugRDBGRequestResponse:idOfDebuggerUI>%s</debugRDBGRequestResponse:idOfDebuggerUI>%s'
                % (esc(alias), ui_id, inner))

    # ---------------- команды ----------------

    def test(self):
        status, _ = self.post("test", "", endpoint="rdbgTest")
        return status == 200

    def attach(self, alias, ui_id=None, foreground_ability=False, user=None, password=None):
        """attachDebugUI. Если на сервере задан `--password`, без `credentials` ответ —
        `credentialsRequired` (снято 2026-10-16 на отдельном dbgs:1551).

        Упаковка проверена эмпирически: `credentials` = base64 от UTF-8 пароля; UTF-16LE
        сервер отвергает тем же `credentialsRequired`. `userName` без `--debugServerUsers`
        игнорируется (с ним и без него при верном пароле — `registered`), так что формат
        `userName` остаётся непроверенным; base64 от UTF-8 — то же, что делает клиент с
        паролем, и иных данных у нас нет.
        """
        ui_id = ui_id or str(uuid.uuid1())
        creds = ""
        if user:
            creds += ('<debugRDBGRequestResponse:userName>%s</debugRDBGRequestResponse:userName>'
                      % base64.b64encode(user.encode("utf-8")).decode())
        if password:
            creds += ('<debugRDBGRequestResponse:credentials>%s</debugRDBGRequestResponse:credentials>'
                      % base64.b64encode(password.encode("utf-8")).decode())
        inner = self.envelope(alias, ui_id, creds +
                              '<debugRDBGRequestResponse:options>'
                              '<debugRDBGRequestResponse:foregroundAbility>%s</debugRDBGRequestResponse:foregroundAbility>'
                              '</debugRDBGRequestResponse:options>' % ("true" if foreground_ability else "false"))
        status, payload = self.post("attachDebugUI", inner)
        return ui_id, text(self.parse(payload), "result")

    def detach(self, alias, ui_id):
        return self.post("detachDebugUI", self.envelope(alias, ui_id))[0]

    def targets(self, alias, ui_id):
        status, payload = self.post("getDbgTargets", self.envelope(alias, ui_id))
        root = self.parse(payload)
        return [DebugTarget(e) for e in kids(root, "id") + kids(root, "item")] if root is not None else []

    def attach_target(self, alias, ui_id, target_id, attach=True):
        inner = self.envelope(alias, ui_id,
                              '<debugRDBGRequestResponse:attach>%s</debugRDBGRequestResponse:attach>'
                              '<debugRDBGRequestResponse:id><id>%s</id></debugRDBGRequestResponse:id>'
                              % ("true" if attach else "false", target_id))
        return self.post("attachDetachDbgTargets", inner)[0]

    def set_breakpoints(self, alias, ui_id, modules):
        """bpWorkspace передаётся целиком: сервер не принимает диффы."""
        inner = self.envelope(alias, ui_id,
                              '<debugRDBGRequestResponse:bpWorkspace>%s</debugRDBGRequestResponse:bpWorkspace>'
                              % "".join(m.to_xml() for m in modules))
        # возвращаем и тело: при отказе сервера именно в нём единственный разбор
        return self.post("setBreakpoints", inner, extra_ns=' xmlns:debugBreakpoints="%s"' % NS_BP)

    def set_break_on_rte(self, alias, ui_id, stop_on_errors=True, analyze=False, patterns=()):
        """setBreakOnRTE — «останавливаться по ран-тайм ошибке», без конфигуратора.

        Тело — `state` типа RteFilterStorage (debugRTEFilter.xsd, elementFormDefault=qualified):
        признак останова, признак анализа текста ошибки и подстроки-фильтры. Нужно там, где
        версию модуля для точки останова взять негде: останов приходит на любом исключении,
        а не только на заранее отмеченной строке.
        """
        items = "".join(
            '<debugRTEFilter:strTemplate><debugRTEFilter:include>%s</debugRTEFilter:include>'
            '<debugRTEFilter:str>%s</debugRTEFilter:str></debugRTEFilter:strTemplate>'
            % ("true" if inc else "false", esc(text)) for text, inc in patterns)
        inner = self.envelope(
            alias, ui_id,
            '<debugRDBGRequestResponse:state>'
            '<debugRTEFilter:stopOnErrors>%s</debugRTEFilter:stopOnErrors>'
            '<debugRTEFilter:analyzeErrorStr>%s</debugRTEFilter:analyzeErrorStr>'
            '%s</debugRDBGRequestResponse:state>'
            % ("true" if stop_on_errors else "false", "true" if analyze else "false", items))
        return self.post("setBreakOnRTE", inner,
                         extra_ns=' xmlns:debugRTEFilter="%s"' % NS_RTE)

    def get_break_on_rte(self, alias, ui_id):
        status, payload = self.post("getBreakOnRTE", self.envelope(alias, ui_id),
                                    extra_ns=' xmlns:debugRTEFilter="%s"' % NS_RTE)
        return status, payload.decode("utf-8", "replace")

    def set_auto_attach(self, alias, ui_id, target_types=("Server", "JOB")):
        """setAutoAttachSettings — сервер сам присоединяет к этому UI цели указанных типов.

        Для безголовых сценариев это единственный способ успеть: цель от HTTP-вызова или
        фонового задания живёт секунды, и вручную (attachDetachDbgTargets) к ней не
        прицепиться — код уже выполнен.
        """
        body = "".join('<debugAutoAttach:targetType>%s</debugAutoAttach:targetType>' % t
                       for t in target_types)
        inner = self.envelope(alias, ui_id,
                              '<debugRDBGRequestResponse:autoAttachSettings>%s'
                              '</debugRDBGRequestResponse:autoAttachSettings>' % body)
        return self.post("setAutoAttachSettings", inner,
                         extra_ns=' xmlns:debugAutoAttach="%s"' % NS_AUTO)

    def get_auto_attach(self, alias, ui_id):
        status, payload = self.post("getAutoAttachSettings", self.envelope(alias, ui_id),
                                    extra_ns=' xmlns:debugAutoAttach="%s"' % NS_AUTO)
        return status, payload.decode("utf-8", "replace")

    def step(self, alias, ui_id, target_id, action="Step"):
        inner = self.envelope(alias, ui_id,
                              '<debugRDBGRequestResponse:targetID><id>%s</id></debugRDBGRequestResponse:targetID>'
                              '<debugRDBGRequestResponse:action>%s</debugRDBGRequestResponse:action>'
                              % (target_id, action))
        status, payload = self.post("step", inner)
        root = self.parse(payload)
        item = (kids(root, "item") or [None])[0]
        return text(item, "state"), text(item, "stateNum")

    # ---------------- вычисления ----------------

    def _calc_body(self, alias, ui_id, target_id, src_inner, max_text=10240, path_element="expr"):
        result_id = str(uuid.uuid4())
        inner = self.envelope(alias, ui_id,
                              '<debugRDBGRequestResponse:calcWaitingTime>100</debugRDBGRequestResponse:calcWaitingTime>'
                              '<debugRDBGRequestResponse:targetID><id>%s</id></debugRDBGRequestResponse:targetID>'
                              '<debugRDBGRequestResponse:%s>'
                              '<debugCalculations:srcCalcInfo>'
                              '<debugCalculations:expressionID>%s</debugCalculations:expressionID>'
                              '<debugCalculations:expressionResultID>%s</debugCalculations:expressionResultID>'
                              '%s</debugCalculations:srcCalcInfo>'
                              '<debugCalculations:presOptions>'
                              '<debugCalculations:maxTextSize>%d</debugCalculations:maxTextSize>'
                              '</debugCalculations:presOptions>'
                              '</debugRDBGRequestResponse:%s>'
                              % (target_id, path_element, uuid.uuid4(), result_id, src_inner, max_text, path_element))
        return result_id, inner

    @staticmethod
    def _expression_src(expression):
        return ('<debugCalculations:calcItem><debugCalculations:itemType>expression</debugCalculations:itemType>'
                '<debugCalculations:expression>%s</debugCalculations:expression></debugCalculations:calcItem>'
                % esc(expression))

    def eval_expr(self, alias, ui_id, target_id, expression):
        result_id, inner = self._calc_body(alias, ui_id, target_id, self._expression_src(expression))
        status, payload = self.post("evalExpr", inner, extra_ns=_NS_CALC)
        return _as_eval(self.parse(payload)), result_id

    def eval_locals(self, alias, ui_id, target_id):
        src = '<debugCalculations:interfaces>context</debugCalculations:interfaces>'
        result_id, inner = self._calc_body(alias, ui_id, target_id, src, max_text=307200)
        status, payload = self.post("evalLocalVariables", inner, extra_ns=_NS_CALC)
        return _as_eval(self.parse(payload)), result_id

    def modify_value(self, alias, ui_id, target_id, path_expression, value_expression):
        src = (self._expression_src(path_expression)
               + '<debugCalculations:interfaces>context</debugCalculations:interfaces>')
        result_id, inner = self._calc_body(alias, ui_id, target_id, src, max_text=307200,
                                           path_element="modifyDataPath")
        inner += ('<debugRDBGRequestResponse:newValueInfo>'
                  '<debugCalculations:variant>expr</debugCalculations:variant>'
                  '<debugCalculations:valueExpression>%s</debugCalculations:valueExpression>'
                  '</debugRDBGRequestResponse:newValueInfo>' % esc(value_expression))
        status, payload = self.post("modifyValue", inner, extra_ns=_NS_CALC)
        return _as_eval(self.parse(payload)), result_id

    # ---------------- события ----------------

    def ping(self, alias, ui_id):
        status, payload = self.post("pingDebugUIParams", self.envelope(alias, ui_id),
                                    extra_query="&dbgui=%s&str" % ui_id)
        if status == 204 or not payload:
            return None
        root = self.parse(payload)
        result = self.unwrap(root)
        return Event(result) if result is not None else None


_NS_CALC = ' xmlns:debugCalculations="%s"' % NS_CALC


def _as_eval(root):
    if root is None:
        return None
    return EvalResult(RdbgClient.unwrap(root))
