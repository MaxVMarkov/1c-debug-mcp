"""Эмпирическая таблица propertyID видов модулей для bpWorkspace.

`objectID` в записи точки — GUID объекта метаданных, `propertyID` — GUID вида модуля
(модуль объекта / менеджера / формы / ...). Второе — константа платформы, но в схемах
перечисления нет. Источник констант: профили конфигуратора (bp_store) + имена объектов
из ConfigDumpInfo.xml выгрузок конфигурации и расширений.

Запускается без подключения к dbgs: только чтение диска.

usage: python probes/property_id_table.py <dump-dir> [<dump-dir> ...]
       (без аргументов — каталоги из V8_CONFIG_SRC через os.pathsep)
"""
import glob
import io
import os
import re
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                 "..", "qoder-1c-debug", "server"))
import bp_store  # noqa: E402


def dump_roots():
    roots = sys.argv[1:]
    if not roots:
        roots = [p for p in os.environ.get("V8_CONFIG_SRC", "").split(os.pathsep) if p]
    out = []
    for root in roots:
        out.append(root)
        out.extend(glob.glob(os.path.join(root, "*")))
    return [p for p in out if os.path.isdir(p)]


DUMPS = dump_roots()

RE_META = re.compile(r'<Metadata name="([^"]+)" id="([0-9a-f\-]{36})(\.\d+)?"')


def index():
    """GUID объекта -> имя из ConfigDumpInfo (первое попадание)."""
    out = {}
    for root in DUMPS:
        cdi = os.path.join(root, "ConfigDumpInfo.xml")
        if not os.path.exists(cdi):
            continue
        text = io.open(cdi, encoding="utf-8", errors="replace").read()
        for name, guid, child in RE_META.findall(text):
            if child:
                continue  # дочерние id (.0/.1) — это сами модули/справки, не объект
            out.setdefault(guid.lower(), (name, os.path.basename(root)))
    return out


def main():
    by_guid = index()
    print("известных объектов из выгрузок: %d" % len(by_guid))
    table = {}
    for path, entries in bp_store.find_workspaces():
        for e in entries:
            key = (e["objectID"].lower(), e["propertyID"].lower())
            name, dump = by_guid.get(key[0], ("?", ""))
            table.setdefault(key, {"name": name, "dump": dump, "lines": set(), "ext": set()})
            table[key]["lines"].update(e["lines"])
            table[key]["ext"].add(e.get("extension_name") or "")
    print("\nobjectID -> имя объекта, и при этом какой propertyID у какого вида модуля")
    for (obj, prop), info in sorted(table.items(), key=lambda kv: kv[1]["name"]):
        lines = ",".join(str(n) for n in sorted(info["lines"]))
        ext = ",".join(sorted(x for x in info["ext"] if x)) or "-"
        print("  %-38s %-36s obj=%s prop=%s lines=%s" %
              (info["name"][:38], "%s/%s" % (info["dump"], ext), obj, prop, lines))
    print("\nсводно: propertyID -> вид модуля (по имени объекта и тому, где точка)")
    kinds = {}
    for (_obj, prop), info in table.items():
        kinds.setdefault(prop, []).append(info["name"])
    for prop, names in sorted(kinds.items()):
        print("  %s : %s" % (prop, "; ".join(sorted(set(names))[:6])))
    return 0


if __name__ == "__main__":
    sys.exit(main())
