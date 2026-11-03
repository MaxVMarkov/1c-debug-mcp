"""Извлечение констант propertyID видов модулей из поставки платформы.

Снимок с живого кадра останова даёт константу только для того вида модуля, где уже случался
останов. Таблица дескрипторов свойств лежит в `backbas.dll` открыто: запись имеет вид
[16 байт GUID в mixed-endian][имя свойства UTF-16], поэтому константу можно взять, ничего не
отлаживая (замер 2026-10-17: перед именем `ObjectModule` лежит ровно a637f77f-… — та же, что
приехала в кадрах останова).

Как работает: ищет в DLL/EXE поставки UTF-16-имена свойств модулей, восстанавливает ВЕСЬ строковый
узел (а не подстроку), читает 16 байт непосредственно перед его началом и печатает пары
имя -> GUID. Мусор отсекается требованием границы строки (перед именем два нулевых байта) и
фильтром «в чанке слишком много печатных байтов — это текст, а не GUID».

usage: python probes/extract_property_table.py [каталог bin]
"""
import io
import os
import sys
import uuid

NAMES = ["ObjectModule", "ManagerModule", "RecordSetModule", "ValueManagerModule",
         "CommandModule", "SessionModule", "ManagedApplicationModule", "PipelineSettingsModule",
         "Form", "ManagedForm", "Module", "HttpService", "WebService"]
KNOWN = {
    "a637f77f-3840-441d-a1c3-699c8c5cb7e0": "ObjectModule",
    "d1b64a2c-8078-4982-8190-8f81aefda192": "ManagerModule",
    "32e087ab-1491-49b6-aba7-43571b41ac2b": "Form module",
    "d5963243-262e-4398-b4d7-fb16d06484f6": "Module одно-модульных объектов",
    "9b7bbbae-9771-46f2-9e4d-2489e0ffc702": "МодульСеанса",
}
WORD = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.")
TERMINATOR = bytes([0, 0])          # конец UTF-16-строки: 0x0000


def utf16_at(raw, pos):
    """Строка UTF-16, начинающаяся в pos (до 0x0000 или символа вне имён свойств)."""
    out = []
    while pos + 1 < len(raw):
        code = int.from_bytes(raw[pos:pos + 2], "little")
        if code == 0:
            break
        ch = chr(code)
        if ch not in WORD:
            break
        out.append(ch)
        pos += 2
    return "".join(out)


def string_start(raw, pos):
    """Начало UTF-16-строки, внутри которой на pos лежит найденная подстрока."""
    if pos % 2:
        return None
    scan = pos
    while scan >= 2 and raw[scan - 2:scan] != TERMINATOR:
        scan -= 2
    if scan < 2 or raw[scan - 2:scan] != TERMINATOR:
        return None
    return scan


def guid_at(raw, pos):
    """mixed-endian GUID перед началом имени; нулевые и текстовые чанки отбрасываются."""
    chunk = raw[max(0, pos - 16):pos]
    if len(chunk) < 16 or chunk == TERMINATOR * 8:
        return None
    if sum(1 for b in chunk if 32 <= b < 127) > 10:
        return None
    return str(uuid.UUID(bytes_le=chunk))


def main():
    root = sys.argv[1] if len(sys.argv) > 1 else r"C:\Program Files\1cv8\8.5.1.1529\bin"
    log = io.open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "evidence",
                               "property_table_extract.txt"), "w", encoding="utf-8")
    tally = {}
    for dirpath, _dirs, files in os.walk(root):
        for name in sorted(files):
            if not name.lower().endswith((".dll", ".exe")):
                continue
            path = os.path.join(dirpath, name)
            if os.path.getsize(path) > 200 * 1024 * 1024:
                continue
            raw = io.open(path, "rb").read()
            for prop in NAMES:
                needle = prop.encode("utf-16-le")
                start = 0
                while True:
                    pos = raw.find(needle, start)
                    if pos < 0:
                        break
                    start = pos + len(needle)
                    begin = string_start(raw, pos)
                    if begin is None or begin > pos:
                        continue
                    full = utf16_at(raw, begin)
                    if not full or prop not in full:
                        continue
                    guid = guid_at(raw, begin)
                    if not guid:
                        continue
                    tally.setdefault((full, guid), []).append(name)
    for (full, guid), where in sorted(tally.items()):
        log.write("%-30s %s  x%-3d %s%s\n" % (full[:30], guid, len(where),
                                              ",".join(sorted(set(where)))[:70],
                                              "   <== известная" if guid in KNOWN else ""))
    log.close()
    print("пар имя->guid: %d" % len(tally))
    for (full, guid), where in sorted(tally.items()):
        if guid in KNOWN or full.endswith(("RecordSetModule", "ValueManagerModule",
                                           "CommandModule", "SessionModule")):
            print("  %-30s %s x%d %s" % (full, guid, len(where), KNOWN.get(guid, "")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
