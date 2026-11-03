"""Ядро MCP-сервера отладки 1С: список инструментов и их вызов.

Транспорт подключается сверху: `debug_mcp.py` (stdio, для отладки вслепую) и
`debug_mcp_http.py` (HTTP, тот, что объявлен в плагине). Разделение нужно затем, чтобы
инструменты можно было гонять по stdin без Qoder.

Сеанс держится в процессе: `pingDebugUIParams` — это long-poll с ответом 204 за ~5 с,
и событие остановки приходит ровно один раз. Если не читать его фоном, агент увидит
паузу только после следующей команды, а `step` без приостановленной цели сервер
принимает, но ничего не происходит. Поэтому на сеанс заводится поток-сборщик событий.

UI отладчика обязан сниматься всегда: незакрытый `attachDebugUI` блокирует базу состоянием
`ibInDebug` (см. docs/rdbg-protocol-2026-10-09.md §11).
"""
import base64
import os
import threading
import time
import uuid
from collections import deque

import bp_store
import md_index
import rdbg_client as rc

PROTOCOL_VERSION = "2024-11-05"
SERVER_INFO = {"name": "1c-debug", "version": "0.0.12"}

# ibInDebug — это не «занято навсегда»: незакрытый attachDebugUI держит базу 90…150 с и
# отпускает сам (три замера 2026-10-16, docs/rdbg-protocol-2026-10-09.md §14). Ждать внутри
# вызова бессмысленно дальше минутного окна: транспорт обрывает длинный tools/call раньше.
DEFAULT_UI_WAIT = 30.0
UI_RETRY_STEP = 5.0
UI_BLOCK_SEC = 120

# Обоим отвечают за учётные данные сервера отладки; в отличие от ibInDebug это НЕ преходящее
# состояние — повторять бессмысленно. Формулировка исправлена по замеру 2026-10-16
# (docs/rdbg-protocol-2026-10-09.md §15): сервер БЕЗ --password точно так же отвечает
# credentialsRequired, если UI пароль ПРИСЛАЛ. То есть код значит «учётные данные не совпали»,
# а не «сервер требует пароль».
CREDENTIAL_HINTS = {
    "credentialsRequired": "учётные данные не совпали: либо на dbgs задан --password, а мы его "
                           "не прислали (тогда password в аргументах или DBGSRV_PASSWORD в "
                           "окружении сервера), либо пароль на dbgs НЕ задан, а мы его прислали "
                           "зря (тогда убери password/DBGSRV_PASSWORD). credentials = base64 от "
                           "UTF-8; сервер без --password принимает attach только без учётных "
                           "данных",
    "fullCredentialsRequired": "сервер отладки запущен со списком пользователей "
                               "(dbgs --debugServerUsers, который перекрывает --password): нужны "
                               "user И password (DBGSRV_USER + DBGSRV_PASSWORD); формат файла "
                               "списка в документации отсутствует",
}

_sessions = {}
_lock = threading.Lock()

TOOLS = [
    {"name": "debug_status",
     "description": "Жив ли сервер отладки (dbgs.exe) и какие сеансы открыты.",
     "inputSchema": {"type": "object", "properties": {
         "host": {"type": "string"}, "port": {"type": "integer"}}}},
    {"name": "session_start",
     "description": "Подключить отладчик к базе: attachDebugUI + фоновый сбор событий. "
                    "Если база занята висячим UI, ответ — {'attached': false, 'reason': "
                    "'ibInDebug', 'retryAfterSec': 120}: состояние преходящее (держится 90…150 с "
                    "и снимается само, docs §14), поэтому спи и повторяй вызов, а не жди внутри "
                    "него. wait — сколько секунд инструмент сам повторяет attach (0…60, "
                    "по умолчанию 30). Отказ {'attached': false, 'reason': "
                    "'credentialsRequired'} означает НЕСОВПАДЕНИЕ учётных данных в обе стороны: "
                    "сервер с --password не принимает UI без пароля, а сервер без пароля не "
                    "принимает UI, который пароль прислал (замер 2026-10-16, docs §15) — сверь "
                    "password/DBGSRV_PASSWORD с тем, как запущен dbgs. При списке пользователей "
                    "(--debugServerUsers, он перекрывает --password) нужен ещё user / "
                    "DBGSRV_USER. Пароль в ответе не появляется.",
     "inputSchema": {"type": "object", "properties": {
         "base": {"type": "string", "description": "имя информационной базы (infoBaseAlias)"},
         "host": {"type": "string"}, "port": {"type": "integer"},
         "foreground": {"type": "boolean", "description": "foregroundAbility, по умолчанию false"},
         "wait": {"type": "number", "description": "секунд повторять attach внутри вызова, 0…60 (по умолчанию 30)"},
         "user": {"type": "string", "description": "имя пользователя отладки (если dbgs запущен с --debugServerUsers)"},
         "password": {"type": "string", "description": "пароль сервера отладки; предпочтительнее задавать "
                                                       "DBGSRV_PASSWORD в окружении, а не в разговоре"}},
         "required": ["base"]}},
    {"name": "session_stop",
     "description": "Отключить отладчик (detachDebugUI) и остановить сбор событий.",
     "inputSchema": {"type": "object", "properties":
         {"base": {"type": "string"}}, "required": ["base"]}},
    {"name": "targets",
     "description": "СНИМОК dbgs, а не список живых сеансов: после смерти клиента его цель "
                    "висит здесь 30…90 с (docs §13). Поле attachedByThisUI — присоединяли ли мы "
                    "её сами. Состояний тут нет: getDbgTargets отвечает без <state>, состояние "
                    "приезжает только событием dbgTargetStateChanged в long-poll.",
     "inputSchema": {"type": "object", "properties":
         {"base": {"type": "string"}}, "required": ["base"]}},
    {"name": "target_attach",
     "description": "Присоединить предмет отладки к нашему UI (то, что делает двойной клик в "
                    "конфигураторе). Без него setBreakpoints копится, но цели не останавливаются, "
                    "а eval/locals приходят пустыми. target_id по умолчанию — единственная цель.",
     "inputSchema": {"type": "object", "properties": {
         "base": {"type": "string"},
         "target_id": {"type": "string"},
         "attach": {"type": "boolean", "description": "false = отсоединить, по умолчанию true"}},
         "required": ["base"]}},
    {"name": "wait_stop",
     "description": "Дождаться паузы на строке кода и вернуть стек кадров со строками и "
                    "представлением вызова с фактическими аргументами.",
     "inputSchema": {"type": "object", "properties": {
         "base": {"type": "string"}, "timeout": {"type": "number", "description": "секунды, по умолчанию 30"}},
         "required": ["base"]}},
    {"name": "stop_on_error",
     "description": "Включить или снять останов на ран-тайм ошибке языка (setBreakOnRTE). "
                    "В отличие от точки останова не требует ни версии модуля, ни самой точки: ловит "
                    "любое исключение, в том числе в коде, куда точку поставить нечем. Ответ содержит "
                    "то, что сервер отдал на getBreakOnRTE. Снимать обязательно (on=false), иначе база "
                    "будет висеть в паузе на каждой ошибке.",
     "inputSchema": {"type": "object", "properties": {
         "base": {"type": "string"},
         "on": {"type": "boolean", "description": "по умолчанию true"},
         "patterns": {"type": "array", "items": {"type": "string"},
                      "description": "подстроки текста ошибки; с ними включается analyzeErrorStr"},
         "exclude": {"type": "boolean",
                     "description": "true = подстроки работают как запреты (include=false)"}},
         "required": ["base"]}},
    {"name": "auto_attach_targets",
     "description": "Приказать серверу отладки самому присоединять к этому UI цели указанных типов "
                    "(setAutoAttachSettings). Нужно для целей, живущих секунды: сеанс от HTTP-вызова "
                    "или фоновое задание заканчивается раньше, чем агент успеет увидеть его в targets "
                    "и вызвать target_attach. types — список DebugTargetType ('Server', 'JOB', "
                    "'HTTPService', 'WEBService', ...); пустой список выключает режим.",
     "inputSchema": {"type": "object", "properties": {
         "base": {"type": "string"},
         "types": {"type": "array", "items": {"type": "string"}}},
         "required": ["base"]}},
    {"name": "breakpoints_list",
     "description": "Точки останова из рабочего листа конфигуратора (его профиль) — там есть "
                    "objectID/propertyID/version, которых нет в XML-исходниках.",
     "inputSchema": {"type": "object", "properties": {}}},
    {"name": "breakpoints_set",
     "description": "Установить точки. Без modules берёт всё из профиля конфигуратора. "
                    "modules — элементы либо {name, lines, extensionName?}, либо явные "
                    "{objectID, propertyID, version, lines, type?, extensionName?}. Именная форма "
                    "разрешает модуль по ConfigDumpInfo.xml выгрузки (нужен configPath): "
                    "CommonModule.Х, WebService.Х, HttpService.Х, Document.Х.ObjectModule, "
                    "Document.Х.ManagerModule, Document.Х.Form.ФормаДокумента. Версия платформой "
                    "не сверяется (docs §17.7), поэтому для именованных модулей версия пишется нулями. "
                    "После push сам присоединяет цель (attach) и пишет в поле attach, что для этого "
                    "произошло — без присоединения точки принимаются, но не останавливают.",
     "inputSchema": {"type": "object", "properties": {
         "base": {"type": "string"},
         "configPath": {"type": "string",
                        "description": "каталог выгрузки конфигурации (или расширения) либо путь к "
                                       "ConfigDumpInfo.xml; по умолчанию V8_CONFIG_SRC из окружения"},
         "modules": {"type": "array", "items": {"type": "object"}}}, "required": ["base"]}},
    {"name": "breakpoints_clear",
     "description": "Снять все точки базы (пустой bpWorkspace).",
     "inputSchema": {"type": "object", "properties":
         {"base": {"type": "string"}}, "required": ["base"]}},
    {"name": "step",
     "description": "Шаг отладки: Step (F10), StepIn (F11), StepOut (Shift+F11), Continue (F9).",
     "inputSchema": {"type": "object", "properties": {
         "base": {"type": "string"},
         "action": {"type": "string", "enum": ["Step", "StepIn", "StepOut", "Continue"]},
         "target_id": {"type": "string", "description": "id цели; по умолчанию единственная"}},
         "required": ["base", "action"]}},
    {"name": "eval",
     "description": "Вычислить выражение в контексте приостановленного кадра. Цель выбирает и "
                    "присоединяет сам (как и locals/set_variable/step).",
     "inputSchema": {"type": "object", "properties": {
         "base": {"type": "string"}, "expression": {"type": "string"}},
         "required": ["base", "expression"]}},
    {"name": "locals",
     "description": "Локальные переменные и параметры текущего кадра (evalLocalVariables).",
     "inputSchema": {"type": "object", "properties":
         {"base": {"type": "string"}}, "required": ["base"]}},
    {"name": "set_variable",
     "description": "Присвоить значение переменной (modifyValue); подтверждение — перечитанное "
                    "значение, а не флаг успеха.",
     "inputSchema": {"type": "object", "properties": {
         "base": {"type": "string"}, "path": {"type": "string"},
         "value_expression": {"type": "string"}}, "required": ["base", "path", "value_expression"]}},
]


class Session:
    def __init__(self, client, alias, ui_id, foreground):
        self.client, self.alias, self.ui_id = client, alias, ui_id
        self.foreground = foreground
        self.events = deque(maxlen=200)
        # evalExpr/evalLocalVariables/modifyValue чаще всего отвечают пустым <result>, а
        # значение приезжает СЛЕДУЮЩИМ событием exprEvaluated с тем же expressionResultID.
        # Пинг принадлежит этому потоку, поэтому инструмент сам не пингует — он ждёт здесь.
        self.results = {}
        self.calc_lock = threading.Lock()
        self.stop = None
        # цели, которые мы уже присоединили к своему UI: attachDetachDbgTargets идемпотентен
        # по сути, но каждый лишний запрос — это лишний кадр в дампе и лишний HTTP 200 без ответа
        self.attached = set()
        self.alive = True
        self.thread = threading.Thread(target=self._pump, daemon=True)
        self.thread.start()

    def _pump(self):
        while self.alive:
            try:
                event = self.client.ping(self.alias, self.ui_id)
            except Exception as exc:
                self.events.append({"error": repr(exc)})
                time.sleep(1.0)
                continue
            if event is None:
                continue
            self.events.append(event)
            if event.frames:
                self.stop = event
            rid = getattr(event, "expression_result_id", None)
            if rid:
                self.results[rid] = event

    def await_result(self, rid, fallback, timeout=6.0):
        """Дождаться события с этим expressionResultID; fallback — синхронный ответ."""
        if fallback is not None and getattr(fallback, "state", None):
            return fallback
        deadline = time.time() + timeout
        while time.time() < deadline:
            got = self.results.pop(rid, None)
            if got is not None:
                return got
            time.sleep(0.1)
        return fallback

    def dispose(self):
        self.alive = False


def _need(alias):
    session = _sessions.get(alias)
    if session is None:
        raise ValueError("сеанс по базе %r не открыт — вызови session_start" % alias)
    return session


def _stop_target(session, targets):
    """Цель, на которой пришёл последний останов, если её удалось опознать в снимке.

    Событие несёт `targetIDStr` — непрозрачный base64 от 1C, но строковые формы id цели и
    id сеанса внутри угадываются (замер 2026-10-17: останов WEBService-цели seance 31,
    а `_pick_target` без этой проверки выбирал висевшую в снимке мёртвую цель seance 10,
    из-за чего eval/locals отвечали пустым). Не совпало — возвращаем None, выбираем по
    состоянию/свежести.
    """
    event = session.stop
    blob = None
    if event is not None and getattr(event, "target_id_str", None):
        try:
            blob = base64.b64decode(event.target_id_str + "=" * 3)
        except Exception:
            blob = None
    if blob is None:
        return None
    for target in targets:
        for key in (target.id, target.seance_id):
            if key and (key.encode("utf-8") in blob or key.replace("-", "").encode() in blob):
                return target
    return None


def _named_module(module, default_dump):
    """Элемент {name, lines} -> элемент с objectID/propertyID из выгрузки конфигурации.

    Явная форма с objectID/propertyID проходит нетронутой: резолвер — удобство, а не единственный
    путь (виды модулей вне таблицы PROPERTY по-прежнему задаются руками).
    """
    if "name" not in module:
        return module
    dump = module.get("configPath") or default_dump
    if not dump:
        raise ValueError("для модуля %r нужен configPath (каталог выгрузки или ConfigDumpInfo.xml) "
                         "или переменная окружения V8_CONFIG_SRC" % module["name"])
    got = md_index.resolve(dump, module["name"])
    out = dict(module)
    out.update({"objectID": got["objectID"], "propertyID": got["propertyID"],
                "version": module.get("version") or got["version"]})
    out.setdefault("type", "ExtensionModule" if module.get("extensionName") else None)
    return out


def _pick_target(session, targets):
    """Приостановленная цель важнее работающей: с ней осмысленны eval/step.

    Порядок: та, на которой пришёл останов > приостановленная > самая свежая по seanceNo.
    Последняя нужна для безголовых сценариев (docs §17): цель от HTTP-вызова появляется в
    снимке с пустым state, и без этого правила агент уедетeval'ом в старую цель-призрак.
    """
    stopped = _stop_target(session, targets)
    if stopped is not None:
        return stopped
    suspended = [t for t in targets if t.state and t.state != "Worked"]
    if suspended:
        return suspended[0]
    return max(targets, key=lambda t: int(t.seance_no or 0))


def _ensure_attached(session, target_id=None):
    """Выбрать цель и присоединить её к нашему UI, если ещё не присоединена.

    Это то, что в конфигураторе делает двойной клик по цели. Без него setBreakpoints
    уходит на сервер с HTTP 200, но цель не останавливается, а eval/locals отвечают
    пустым телом (docs/rdbg-protocol-2026-10-09.md §7).

    Возвращает (id, attached_now, цель). Цель возвращается затем, чтобы вызывающий
    мог доложить ЕЁ seanceNo/targetType: снимок dbgs включает мёртвые сеансы ещё
    30…90 с после смерти клиента (§13), и attach такого трупа отвечает HTTP 200.
    """
    targets = session.client.targets(session.alias, session.ui_id)
    if not targets:
        raise ValueError("предметов отладки нет: нужен живой сеанс базы — клиент, "
                         "веб-вызов или фоновое задание; /DEBUG для появления цели не "
                         "обязателен (замер 2026-10-17, docs §17)")
    session.attached &= {t.id for t in targets}   # цель пропала из снимка — attach забыт
    if target_id:
        chosen = next((t for t in targets if t.id == target_id), None)
        if chosen is None:
            raise ValueError("цели %s нет в снимке dbgs; есть %s"
                             % (target_id, ", ".join(t.id[:8] for t in targets)))
    else:
        chosen = _pick_target(session, targets)
    if chosen.id in session.attached:
        return chosen.id, False, chosen
    status = session.client.attach_target(session.alias, session.ui_id, chosen.id, attach=True)
    if status != 200:
        raise ValueError("attachDetachDbgTargets -> HTTP %s" % status)
    session.attached.add(chosen.id)
    return chosen.id, True, chosen


def _attach_report(session, target, attached_now, chosen):
    """Что attach реально оставил после себя: та же цель всё ещё в снимке или уже нет."""
    still = {t.id for t in session.client.targets(session.alias, session.ui_id)}
    return {"target": target, "targetType": chosen.target_type, "seanceNo": chosen.seance_no,
            "attachedNow": attached_now, "stillInSnapshot": target in still}


def _shape(value):
    if isinstance(value, rc.Event):
        return {"kind": value.cmd_id or value.kind, "stopByBP": value.stop_by_bp,
                "expressionResultID": value.expression_result_id,
                "frames": [_shape(f) for f in value.frames],
                "context": [_shape(v) for v in value.context] if value.context else None,
                "eval": _shape(value.eval) if value.eval else None}
    if isinstance(value, rc.StackFrame):
        return {"module": value.module_id, "property": value.property_id, "version": value.version,
                "type": value.module_type, "extension": value.extension_name,
                "line": value.line_no, "presentation": value.presentation}
    if isinstance(value, rc.EvalResult):
        return {"state": value.state, "type": value.type_name, "value": value.value,
                "presentation": value.presentation, "error": value.error}
    if isinstance(value, rc.ContextValue):
        return {"name": value.name, "type": value.type_name, "value": value.value,
                "presentation": value.presentation}
    if isinstance(value, list):
        return [_shape(v) for v in value]
    return value


def _unwrap_eval(got):
    """await_result возвращает либо синхронный EvalResult, либо Event exprEvaluated."""
    if isinstance(got, rc.Event):
        return got.eval if got.eval is not None else got.context
    return got


def call(name, args):
    host = args.get("host", "127.0.0.1")
    port = int(args.get("port", 1550))

    if name == "debug_status":
        client = rc.RdbgClient(host, port)
        return {"dbgs_alive": client.test(), "endpoint": "%s:%d" % (host, port),
                "sessions": sorted(_sessions)}
    if name == "session_start":
        alias = args["base"]
        if alias in _sessions:
            return {"already": True, "ui": _sessions[alias].ui_id}
        client = rc.RdbgClient(host, port)
        # потолок 60 с: транспорт MCP обрывает длинный вызов раньше, чем он окупается
        # (замер 2026-10-16: wait=110 → «MCP error -32603», а база освободилась бы сама)
        wait = min(60.0, max(0.0, float(args.get("wait", DEFAULT_UI_WAIT))))
        started = time.time()
        deadline = started + wait
        user = args.get("user") or os.environ.get("DBGSRV_USER") or None
        password = args.get("password") or os.environ.get("DBGSRV_PASSWORD") or None
        attempts, ui_id, result = 0, None, None
        while True:
            attempts += 1
            ui_id, result = client.attach(alias, foreground_ability=bool(args.get("foreground")),
                                          user=user, password=password)
            if result == "registered" or result in CREDENTIAL_HINTS or time.time() >= deadline:
                break
            time.sleep(min(UI_RETRY_STEP, max(0.0, deadline - time.time())))
        if result in CREDENTIAL_HINTS:
            # пароль — не тайна, которую надо напечатать: в ответе только факт и способ задать
            return {"attached": False, "reason": result, "attempts": attempts,
                    "passwordProvided": bool(password), "userProvided": bool(user),
                    "hint": CREDENTIAL_HINTS[result]}
        if result == "ibInDebug":
            # штатное преходящее состояние, а не сбой: висячий UI держит базу 90…150 с и
            # отпускает сам (§14). Возвращаем данные, чтобы агент спал и повторял вызов,
            # вместо того чтобы ловить таймаут длинного ожидания внутри инструмента.
            return {"attached": False, "reason": result, "attempts": attempts,
                    "waitedSec": round(time.time() - started, 1), "retryAfterSec": UI_BLOCK_SEC,
                    "hint": "база занята незакрытым или убитым отладочным UI; подожди "
                            "≈%d с и повтори session_start" % UI_BLOCK_SEC}
        if result != "registered":
            raise ValueError("attachDebugUI -> %s после %d попыток; unknown — база не найдена "
                             "или сервер отладки о ней не знает, notRegistered — прочий отказ "
                             "регистрации" % (result, attempts))
        _sessions[alias] = Session(client, alias, ui_id, bool(args.get("foreground")))
        out = {"attached": True, "ui": ui_id, "attempts": attempts}
        if attempts > 1:
            out["waitedSec"] = round(time.time() - started, 1)
        return out
    if name == "session_stop":
        alias = args["base"]
        session = _sessions.pop(alias, None)
        if session is None:
            return {"was_open": False}
        try:
            status = session.client.detach(alias, session.ui_id)
        finally:
            session.dispose()
        return {"detached_http": status}

    if name == "breakpoints_list":
        # рабочий лист конфигуратора читается и без открытого сеанса: это источник
        # objectID/propertyID/version, а не запрос к серверу отладки
        return {"files": [{"path": path.replace("\\", "/"), "modules": entries}
                          for path, entries in bp_store.find_workspaces()]}

    session = _need(args["base"])
    if name == "targets":
        out = []
        for t in session.client.targets(session.alias, session.ui_id):
            shaped = _shape(t.__dict__)
            shaped["attachedByThisUI"] = t.id in session.attached
            out.append(shaped)
        return out
    if name == "target_attach":
        target = args.get("target_id")
        attach = args.get("attach", True)
        if attach:
            target, attached_now, _chosen = _ensure_attached(session, target)
            status = 200
        else:
            if not target:
                available = session.client.targets(session.alias, session.ui_id)
                if len(available) != 1:
                    raise ValueError("целей %d — укажи target_id явно" % len(available))
                target = available[0].id
            status = session.client.attach_target(session.alias, session.ui_id, target,
                                                  attach=False)
            session.attached.discard(target)
            attached_now = False
        after = session.client.targets(session.alias, session.ui_id)
        return {"http": status, "attach": bool(attach), "target": target,
                "attachedNow": attached_now,
                "targets_after": len(after),
                "states": [(t.id[:8], t.state, t.state_num) for t in after]}
    if name == "wait_stop":
        deadline = time.time() + float(args.get("timeout", 30))
        while time.time() < deadline:
            if session.stop is not None:
                found, session.stop = session.stop, None
                return _shape(found)
            time.sleep(0.2)
        return {"timeout": True, "events": [_shape(e) for e in list(session.events)[-5:]]}
    if name == "breakpoints_set":
        modules = args.get("modules")
        default_dump = args.get("configPath") or os.environ.get("V8_CONFIG_SRC")
        if modules is not None:
            modules = [_named_module(m, default_dump) for m in modules]
        if modules is None:
            modules = [m for _p, entries in bp_store.find_workspaces() for m in entries]
            if not modules:
                raise ValueError("в профиле конфигуратора точек нет — передай modules явно")
            modules = [{"objectID": m["objectID"], "propertyID": m["propertyID"],
                        "version": m["version"], "lines": m["lines"],
                        "type": "ExtensionModule" if m.get("extension_name") else None,
                        "extensionName": m.get("extension_name")} for m in modules]
        built = [rc.ModuleBreakpoints(m["objectID"], m["propertyID"], m["version"],
                                      m.get("lines") or [], m.get("type"),
                                      m.get("extensionName") or m.get("extension_name"))
                 for m in modules]
        status, payload = session.client.set_breakpoints(session.alias, session.ui_id, built)
        out = {"http": status, "modules": len(built),
               "response": payload.decode("utf-8", "replace")[:400]}
        try:
            target, attached_now, chosen = _ensure_attached(session)
            out["attach"] = _attach_report(session, target, attached_now, chosen)
        except ValueError as exc:
            # точки приняты сервером, но останавливать их нечему и не кем — это тот самый
            # молчаливый случай «HTTP 200, а ничего не происходит»
            out["attach"] = {"error": str(exc)}
        return out
    if name == "breakpoints_clear":
        status, payload = session.client.set_breakpoints(session.alias, session.ui_id, [])
        return {"http": status}
    if name == "stop_on_error":
        on = bool(args.get("on", True))
        patterns = args.get("patterns") or []
        exclude = bool(args.get("exclude"))
        status, _ = session.client.set_break_on_rte(
            session.alias, session.ui_id, stop_on_errors=on, analyze=bool(patterns),
            patterns=[(p, not exclude) for p in patterns])
        readback_status, readback = session.client.get_break_on_rte(session.alias, session.ui_id)
        return {"http": status, "on": on, "filters": len(patterns),
                "readback_http": readback_status, "readback": readback[:300]}
    if name == "auto_attach_targets":
        types = args.get("types") or []
        status, _ = session.client.set_auto_attach(session.alias, session.ui_id, tuple(types))
        return {"http": status, "types": list(types)}
    if name == "step":
        target, _, _chosen = _ensure_attached(session, args.get("target_id"))
        action = args.get("action", "Step")
        state, state_num = session.client.step(session.alias, session.ui_id, target, action)
        if action == "Continue":
            # останов забыт: пока не приедет новый, цель выбираем по состоянию/свежести,
            # а не по тому, на чём стояли пять минут назад
            session.stop = None
        return {"target": target, "state": state, "stateNum": state_num, "action": action}
    if name == "eval":
        target, _, _chosen = _ensure_attached(session)
        # Два вычисления на одном UI одновременно путаются: второе утаскивает чужой
        # exprEvaluated и отвечает «correctly» с пустотой (замер 2026-10-17 через плагин).
        with session.calc_lock:
            res, rid = session.client.eval_expr(session.alias, session.ui_id,
                                                target, args["expression"])
            got = session.await_result(rid, res)
        return _shape(_unwrap_eval(got))
    if name == "locals":
        target, _, _chosen = _ensure_attached(session)
        with session.calc_lock:
            context = None
            # Первый запрос иногда отвечает пустотой: синхронный <result> приходит до
            # exprEvaluated, а ожидание его не досидело (замер 2026-10-17 02:0x: пустой
            # ответ, повтор — все четыре параметра). Повтор — не стоимость, а смысл.
            for attempt in range(3):
                if attempt:
                    # пауза обязательна: пустым бывает ПЕРВЫЙ ответ после останова, а
                    # моментальный повтор внутри лога той же проблемы (замер 0.0.10)
                    time.sleep(1.0)
                res, rid = session.client.eval_locals(session.alias, session.ui_id, target)
                ev = session.await_result(rid, res, timeout=8.0)
                context = getattr(ev, "context", None)
                if context:
                    break
        return _shape(context if context else _unwrap_eval(ev))
    if name == "set_variable":
        target, _, _chosen = _ensure_attached(session)
        with session.calc_lock:
            res, rid = session.client.modify_value(session.alias, session.ui_id,
                                                   target, args["path"],
                                                   args["value_expression"])
            got = session.await_result(rid, res)
        return _shape(_unwrap_eval(got))
    raise ValueError("неизвестный инструмент: %s" % name)
