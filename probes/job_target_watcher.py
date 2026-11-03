"""Пассивный наблюдатель целей JOB: когда они появляются сами и под каким именем.

Дорога A задачи #33: регламентные задания кластера запускаются без человека, но ловить их надо
заранее — цель живёт секунды-минуты. Скрипт поднимает свой отладочный UI, включает
авто-присоединение целей `JOB`/`Server`/`WEBService` и с интервалом опрашивает `getDbgTargets`,
записывая каждую новую/ушедшую цель со всеми полями снимка. По времени появления потом
сопоставим с регистром сведений о фоновых заданиях (таблица в MSSQL читается db-sql-read) —
там лежит имя метода, а значит и модуль, куда надо ставить точку.

Сам скрипт НИЧЕГО не останавливает: `stopOnErrors` не вооружает и точек не шлёт, чтобы не
подвесить живую базу на то время, пока наблюдатель висит.

usage: python probes/job_target_watcher.py [alias] [минут]
"""
import io
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", "qoder-1c-debug", "server"))
from rdbg_client import RdbgClient  # noqa: E402

ALIAS = sys.argv[1] if len(sys.argv) > 1 else "demo-base"
MINUTES = float(sys.argv[2]) if len(sys.argv) > 2 else 15.0
STEP = 5.0
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "evidence",
                   "job_target_watch_long.txt")


def main():
    log = io.open(OUT, "a", encoding="utf-8")

    def note(text):
        line = "%s %s" % (time.strftime("%H:%M:%S"), text)
        log.write(line + "\n")
        log.flush()

    client = RdbgClient(timeout=60)
    ui_id = None
    for attempt in range(8):
        ui_id, result = client.attach(ALIAS)
        if result == "registered":
            break
        note("attachDebugUI -> %s (попытка %d), жду" % (result, attempt + 1))
        time.sleep(10)
    if ui_id is None or result != "registered":
        note("UI не подключён, наблюдение срывается")
        log.close()
        return 1
    note("наблюдение началось, ui=%s, минут=%.1f" % (ui_id, MINUTES))
    try:
        client.set_auto_attach(ALIAS, ui_id, ("JOB", "Server", "WEBService", "HTTPService"))
        known = {}
        started = {}
        deadline = time.time() + MINUTES * 60
        polls = 0
        while time.time() < deadline:
            polls += 1
            try:
                targets = client.targets(ALIAS, ui_id)
            except Exception as exc:
                note("getDbgTargets исключение: %r" % (exc,))
                time.sleep(STEP)
                continue
            now = {t.id: t for t in targets}
            for tid, t in now.items():
                if tid not in known:
                    started[tid] = time.time()
                    note("НОВАЯ  seance=%s type=%s user=%s id=%s cfg=%s" %
                         (t.seance_no, t.target_type, t.user_name, tid[:8],
                          (t.config_version or "")[:12]))
            for tid in set(known) - set(now):
                note("УШЛА    seance=%s type=%s жила ~%ds" %
                     (known[tid].seance_no, known[tid].target_type,
                      int(time.time() - started.get(tid, time.time()))))
            known = now
            time.sleep(STEP)
        note("наблюдение закончено, опросов %d, целей в конце %d" % (polls, len(known)))
        return 0
    finally:
        try:
            client.set_auto_attach(ALIAS, ui_id, ())
            note("detach -> HTTP %s" % client.detach(ALIAS, ui_id))
        except Exception as exc:
            note("снятие UI не удалось: %r" % (exc,))
        log.close()


if __name__ == "__main__":
    raise SystemExit(main())
