"""Собрать ZIP плагина для Upload Plugin в Qoder.

Правило упаковки: архив раскладывается манифестом в корне (без папки-обёртки), поэтому
в zip кладётся содержимое каталога плагина, а не сам каталог. Имя берётся из version
в манифесте, чтобы архив и декларация не разъезжались.
"""
import json
import os
import sys
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PLUGIN = os.path.join(ROOT, "qoder-1c-debug")
SKIP_DIRS = {"__pycache__"}


def skip(name):
    return name in SKIP_DIRS or name.endswith(".pyc")


def main():
    with open(os.path.join(PLUGIN, ".qoder-plugin", "plugin.json"), encoding="utf-8") as fh:
        version = json.load(fh)["version"]

    out_dir = os.path.join(ROOT, "dist")
    os.makedirs(out_dir, exist_ok=True)
    out = os.path.join(out_dir, "1c-debug-%s.zip" % version)

    written = []
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zf:
        for dirpath, dirnames, filenames in os.walk(PLUGIN):
            dirnames[:] = sorted(d for d in dirnames if not skip(d))
            for fname in sorted(filenames):
                if skip(fname):
                    continue
                full = os.path.join(dirpath, fname)
                rel = os.path.relpath(full, PLUGIN).replace(os.sep, "/")
                zf.write(full, rel)
                written.append(rel)

    print(out)
    for rel in written:
        print("  " + rel)
    if ".qoder-plugin/plugin.json" not in written:
        print("ОШИБКА: манифест не в корне архива", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
