"""Имя модуля -> objectID + propertyID для bpWorkspace.

Зачем: агент ставит точку строкой `CommonModule.ОбщегоНазначения` + номер строки и не должен
охотиться за GUID'ами. `objectID` берётся из `ConfigDumpInfo.xml` живой выгрузки конфигурации
(или расширения — у расширения свой дамп), `propertyID` — константа платформы для вида модуля,
снятая с кадров останова (docs/rdbg-protocol-2026-10-09.md §17.5). `version` платформа не
сверяет (§17.7), поэтому для именованных модулей он пишется нулями.

Что видно в дампе (по дампу конфигурации):

    CommonModule.CRMЛокализация.Module            id=4e1749be-….0
    Document.АвансовыйОтчет.ObjectModule          id=9de71b46-….0
    Document.АвансовыйОтчет.ManagerModule         id=9de71b46-….2
    Catalog.Х.ManagerModule                       id=….-….3     (индекс != у документов)
    Document.Х.Form.ФормаДокумента.Form           id=36863726-….0
    WebService.CustomerOrdersExchange.Module      id=c0aa0d5d-…

Поэтому ключ — имя узла, а не номер после точки: индекс вида модуля у разных типов не совпадает.
"""
import difflib
import io
import os
import re

# Вид модуля -> propertyID. Единственный модуль объекта (общий модуль, веб-сервис, HTTP-сервис) —
# одна и та же константа: замер 2026-10-17 показал d5963243… и в кадре WebСервис.CustomerOrdersExchange,
# и в кадре ОбщийМодуль.МобильноеПриложениеЗаказыКлиентов.
PROPERTY = {
    "ObjectModule": "a637f77f-3840-441d-a1c3-699c8c5cb7e0",
    "ManagerModule": "d1b64a2c-8078-4982-8190-8f81aefda192",
    "Form": "32e087ab-1491-49b6-aba7-43571b41ac2b",
    "Module": "d5963243-262e-4398-b4d7-fb16d06484f6",
}
# Виды модулей, чью константу ещё не снимали: objectID выдадим, propertyID потребуем руками.
UNKNOWN_KINDS = ("RecordSetModule", "ValueManagerModule", "TableModule", "CommandModule")

ZERO_VERSION = "0" * 40

_NODE = re.compile(r'<Metadata name="([^"]+)" id="([0-9a-f\-]{36})(?:\.(\d+))?"')

_CACHE = {}


def dump_file(config_path):
    """ConfigDumpInfo.xml по пути к выгрузке (или сам файл — тогда вернём его)."""
    if os.path.isfile(config_path):
        return config_path
    candidate = os.path.join(config_path, "ConfigDumpInfo.xml")
    if os.path.isfile(candidate):
        return candidate
    raise ValueError("нет ConfigDumpInfo.xml в %r" % config_path)


def index(config_path):
    """имя узла -> guid объекта (первая часть id). Кэш по (файл, mtime)."""
    path = dump_file(config_path)
    key = (path, os.path.getmtime(path), os.path.getsize(path))
    cached = _CACHE.get(path)
    if cached and cached[0] == key:
        return cached[1]
    found = {}
    with io.open(path, encoding="utf-8", errors="replace") as handle:
        for line in handle:
            for match in _NODE.finditer(line):
                name, guid = match.group(1), match.group(2)
                found.setdefault(name, guid)
    _CACHE[path] = (key, found)
    return found


def _node_names(name):
    """Варианты имени узла для пользовательского имени модуля."""
    parts = name.split(".")
    if len(parts) < 2:
        raise ValueError("имя модуля должно быть вида CommonModule.Х или Document.Х.ObjectModule")
    kind = parts[-1]
    if kind in PROPERTY:
        if kind == "Module":
            return [name, ".".join(parts[:-1]) + ".Module"]
        return [name]
    if kind in UNKNOWN_KINDS:
        return [name]
    # CommonModule.Х / WebService.Х / HttpService.Х -> узел <имя>.Module
    if parts[0] in ("CommonModule", "WebService", "HttpService"):
        return [name + ".Module", name]
    # Document.Х.Form.ФормаДокумента -> узел <имя>.Form
    if len(parts) >= 4 and "Form" in parts:
        return [name + ".Form", name]
    return [name, name + ".Module", name + ".ObjectModule"]


def resolve(config_path, name):
    """-> (objectID, propertyID, version, узел, вид модуля).

    version — нули: платформа его не сверяет (§17.7). Возвращаем поле, чтобы вызывающий
    не додумывал его сам и ответ был похож на прежний, «сырой».
    """
    nodes = index(config_path)
    tried = []
    for candidate in _node_names(name):
        tried.append(candidate)
        guid = nodes.get(candidate)
        if not guid:
            continue
        kind = candidate.rsplit(".", 1)[-1]
        if kind not in PROPERTY:
            raise ValueError("узел %r найден, но его вид модуля %r не в таблице констант — "
                             "передай objectID/propertyID явно" % (candidate, kind))
        return {"objectID": guid, "propertyID": PROPERTY[kind], "version": ZERO_VERSION,
                "node": candidate, "kind": kind}
    near = difflib.get_close_matches(name, list(nodes), n=5, cutoff=0.55)
    raise ValueError("модуля %r нет в %s (пробовали %s). Ближайшие: %s"
                     % (name, dump_file(config_path), ", ".join(tried), ", ".join(near) or "нет"))
