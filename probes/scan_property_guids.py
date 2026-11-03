"""Где в поставке платформы живут константы propertyID видов модулей.

Резолвер имён модулей (`qoder-1c-debug/server/md_index.py`) пока знает четыре константы, снятые с
кадров останова. Если эти GUID'ы лежат в файле поставки (схема классов метаданных, реестр свойств),
таблица закрывается целиком сразу — для `RecordSetModule`, `ValueManagerModule`, `CommandModule` и
прочего, где кадр ещё не снимали.

Ищем в бинарных файлах обе формы: обычный ASCII-GUID и UTF-16LE (1C хранит строки широко), в
обоих регистрах, а также форму `{...}`.

usage: python probes/scan_property_guids.py [файл…|каталог]
"""
import io
import os
import sys
import uuid

WANTED = {
    "a637f77f-3840-441d-a1c3-699c8c5cb7e0": "ObjectModule",
    "d1b64a2c-8078-4982-8190-8f81aefda192": "ManagerModule",
    "32e087ab-1491-49b6-aba7-43571b41ac2b": "Form module",
    "d5963243-262e-4398-b4d7-fb16d06484f6": "Module (single-module objects)",
    "9b7bbbae-9771-46f2-9e4d-2489e0ffc702": "МодульСеанса",
    "a7f21201-b234-4b3b-b676-9ad813e3d816": "(не константа: objectID общего модуля — контроль)",
}
EXTS = (".dll", ".exe", ".xsd", ".xml", ".res", ".hbk", ".bin", ".dat", ".mof", ".ini")


def needles(guid):
    """Текстовые формы GUID + сырые 16 байт в обоих порядках (в бинарных таблицах 1C
    строковых GUID'ов нет — проверено этим же прогоном)."""
    out = []
    for form in (guid, guid.upper(), "{%s}" % guid, "{%s}" % guid.upper()):
        out.append(("text", form.encode("utf-8")))
        out.append(("utf16", form.encode("utf-16-le")))
    u = uuid.UUID(guid)
    out.append(("bytes", u.bytes))
    out.append(("bytes_le", u.bytes_le))
    return out


def scan(path, report):
    try:
        raw = io.open(path, "rb").read()
    except Exception as exc:
        report("  %s: не прочитан (%r)" % (os.path.basename(path), exc))
        return 0
    hits = 0
    for guid, label in WANTED.items():
        for kind, needle in needles(guid):
            start = 0
            while True:
                pos = raw.find(needle, start)
                if pos < 0:
                    break
                hits += 1
                decode = "utf-16-le" if kind == "utf16" else "latin-1"
                text = " ".join(ch for ch in raw[max(0, pos - 48):pos + 72].decode(decode, errors="replace")
                                if 32 <= ord(ch) < 127)
                report("  %-30s %-28s %s +0x%x [%s] %s" %
                       (os.path.basename(path), label, kind, pos, guid[:8], text[:70]))
                start = pos + 1
    return hits


def main():
    root = sys.argv[1] if len(sys.argv) > 1 else r"C:\Program Files\1cv8\8.5.1.1529"
    log = io.open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "evidence",
                               "property_guid_scan.txt"), "w", encoding="utf-8")

    def report(line):
        log.write(line + "\n")
        log.flush()

    paths = []
    if os.path.isfile(root):
        paths = [root]
    else:
        for dirpath, _dirs, files in os.walk(root):
            for name in files:
                if name.lower().endswith(EXTS):
                    paths.append(os.path.join(dirpath, name))
    total = 0
    report("файлов к поиску: %d" % len(paths))
    for path in paths:
        if os.path.getsize(path) > 200 * 1024 * 1024:
            continue
        found = scan(path, report)
        total += found
    report("ИТОГО вхождений: %d" % total)
    log.close()
    print("вхождений: %d, след в evidence/property_guid_scan.txt" % total)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
