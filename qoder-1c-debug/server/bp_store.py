"""Чтение рабочего листа точек остановки конфигуратора из его профиля.

Раньше считалось, что `propertyID` и `version` для `setBreakpoints` агенту взять
неоткуда: в XML-исходниках конфигурации их нет (docs/rdbg-protocol-2026-10-09.md §4).
Найдено хранилище: конфигуратор пишет список точек в свой профиль, ключ `Breakpoints`
файла `%APPDATA%\\1C\\1cv8\\<профиль>\\<GUID>\\1cv8.pfl`, и там лежит ровно то, что
уходит по проводу.

Запись модуля (проверено на 5 модулях, совпало байт в байт с setBreakpoints из захвата
2026-10-09 — docs/rdbg-protocol-2026-10-09.md, §4):

    {"",0},<objectID>,<propertyID>,0,<version как GUID>,<n>,base64(20 байт),"<extensionName>"

Поле `version` — 20 байт в base64; стоящий рядом «GUID» есть не что иное, как те же
первые 16 байт в смешанном порядке (little-endian в первых трёх группах).
"""
import base64
import glob
import io
import os
import re

_GUID = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"

RECORD = re.compile(
    r'\{"",0\},'
    r'(' + _GUID + r'),'          # 1: objectID модуля
    r'(' + _GUID + r'),'          # 2: propertyID (вид модуля)
    r'\d+,'
    + _GUID + r','                # version в виде GUID — дублирует base64 ниже
    r'\d+,'
    r'([A-Za-z0-9+/=]+),'         # 3: version, 20 байт в base64
    r'"([^"]*)"'                  # 4: имя расширения, пустое для базовой конфигурации
)

LINE = re.compile(r'\{1,(\d+),')


def profile_files(appdata=None):
    """Все профили баз, где конфигуратор мог оставить точки."""
    root = appdata or os.path.join(os.environ.get("APPDATA", ""), "1C", "1cv8")
    return sorted(glob.glob(os.path.join(root, "*", "*", "1cv8.pfl")))


def read_workspace(path):
    """-> список словарей objectID/propertyID/version/extension_name/lines."""
    text = io.open(path, encoding="utf-8", errors="replace").read()
    head = text.find('"Breakpoints"')
    if head < 0:
        return []
    body = text[head:]
    stop = body.find('"Bookmarks"')
    region = body[:stop] if stop > 0 else body

    found = list(RECORD.finditer(region))
    out = []
    for index, match in enumerate(found):
        object_id, property_id, version_b64, extension = match.groups()
        # Границу блока строк берём по началу следующей записи (или концу списка):
        # terminator последней записи отличается, и ловить его паттерном — способ
        # потерять модуль.
        block_end = found[index + 1].start() if index + 1 < len(found) else len(region)
        lines = [int(n) for n in LINE.findall(region[match.end():block_end])]
        try:
            version = base64.b64decode(version_b64).hex()
        except Exception:
            version = None
        out.append({"objectID": object_id, "propertyID": property_id, "version": version,
                    "extension_name": extension or None, "lines": lines})
    return out


def find_workspaces(appdata=None):
    for path in profile_files(appdata):
        entries = read_workspace(path)
        if entries:
            yield path, entries


if __name__ == "__main__":
    found_any = False
    for path, entries in find_workspaces():
        found_any = True
        print(path)
        for entry in entries:
            print("   %s %s v=%s ext=%s lines=%s" % (
                entry["objectID"][:8], entry["propertyID"][:8],
                (entry["version"] or "?")[:20], entry["extension_name"], entry["lines"]))
    if not found_any:
        print("точек в профилях конфигуратора не найдено")
