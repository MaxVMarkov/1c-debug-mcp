# 1c-debug-mcp

MCP-сервер, который даёт агенту управление **режимом отладки 1С:Предприятие 8.5**:
точки останова, шаги, стек вызовов, вычисление выражений и изменение значений — через
штатный сервер отладки кластера `dbgs.exe` (RDBG поверх HTTP), **без EDT и без кликов
в конфигураторе**. Идёт в комплекте с плагином Qoder.

> MCP server that drives the 1C:Enterprise 8.5 cluster debug server (`dbgs.exe`, RDBG over
> HTTP): breakpoints, stepping, call stack, `eval`, locals. No EDT, no UI automation.

## Что умеет

- **Точки останова по имени модуля.** `CommonModule.Х`, `Document.Х.ObjectModule`,
  `Document.Х.Form.ФормаДокумента`, `WebService.Х.Модуль` — `objectID` берётся из
  `ConfigDumpInfo.xml` выгрузки конфигурации, `propertyID` — из таблицы констант платформы.
  `version` платформа не сверяет, поэтому для именованных модулей он пишется нулями.
- **Безголовая цель отладки.** Любой живой сеанс базы регистрируется в `dbgs` как цель:
  HTTP/SOAP-вызов опубликованного сервиса, HTTP-сервис, фоновое задание. Клиент с `/DEBUG`
  и открытое окно не нужны.
- **Останов на ран-тайм ошибке** (`setBreakOnRTE`) — ловит исключение в модуле, куда точку
  поставить нечем, и не требует версии модуля.
- **Авто-присоединение** короткоживущих целей (`setAutoAttachSettings`): сеанс от HTTP-вызова
  живёт секунды и исчезает раньше, чем агент увидит его в списке.
- **Рабочий лист конфигуратора** как источник точек (`1cv8.pfl`, ключ `Breakpoints`).
- **Вычисления в остановленном кадре:** `eval`, `locals`, `set_variable` — с подтверждением
  перечитанным значением.

Всего 15 инструментов; таблица — в [`qoder-1c-debug/README.md`](qoder-1c-debug/README.md).

## Требования

- Windows, 1С:Предприятие **8.5.1.x**, кластер запущен с `ragent -debug` — тогда рядом
  поднимается `dbgs.exe` (по умолчанию порт 1550).
- Python 3.9+ (стандартная библиотека, внешних зависимостей нет).
- Для безголового режима база должна быть опубликована (веб-сервисы `/ws/`, HTTP-сервисы
  `/hs/` или OData) — иначе серверный код нечем вызвать.

## Установка

### Плагин Qoder

```bash
python scripts/pack_plugin.py          # -> dist/1c-debug-<version>.zip
```

Панель плагинов → **Upload Plugin** → ZIP (манифест должен лежать в корне архива, без
папки-обёртки — упаковщик это соблюдает). Плагин объявляет HTTP-MCP
`http://127.0.0.1:8123/mcp`, но процесс не запускает: поднимите сервер сами *до* старта
Qoder.

```powershell
powershell.exe -NoProfile -File qoder-1c-debug/scripts/start-server.ps1
```

После установки — полный перезапуск Qoder: набор MCP-инструментов фиксируется на старте
приложения.

### Вручную, без плагина

```bash
python qoder-1c-debug/server/debug_mcp_http.py --port 8123
```

и зарегистрируйте в клиенте MCP-сервер типа `http` с URL `http://127.0.0.1:8123/mcp`.
Есть и stdio-вариант — `qoder-1c-debug/server/debug_mcp.py`.

Проверка живости:

```bash
powershell.exe -NoProfile -File qoder-1c-debug/scripts/status.ps1
curl http://127.0.0.1:8123/          # health
```

## Быстрый старт

Обычный сценарий (есть клиентский сеанс или фоновое задание):

```
session_start(base)                    # attachDebugUI + фоновый сбор событий
breakpoints_set(base, configPath=..., modules=[{name: "CommonModule.Х", lines: [42]}])
wait_stop(base)                        # кадры стека, строка, аргументы вызова
locals(base); eval(base, "Х = Истина")
step(base, "Continue"); session_stop(base)
```

Безголовый сценарий (клиента нет вообще):

```
session_start(base)
auto_attach_targets(base, types=["Server", "JOB", "WEBService", "HTTPService"])
stop_on_error(base, on=True)
# ... HTTP/SOAP-вызов опубликованного сервиса базы ...
wait_stop(base)                        # кадр даёт moduleID/objectID/propertyID/version
step(base, "Continue"); stop_on_error(base, on=False)
breakpoints_set(base, modules=[{name: "CommonModule.Х", lines: [71]}], configPath=...)
# ... тот же вызов -> останов уже обычной точкой ...
```

Обязательные правила:

- `session_stop` нужен всегда: незакрытый UI держит базу в `ibInDebug` 90…150 с.
- Одно вычисление за раз на сеанс: параллельные `eval` и `locals` утаскивают чужое
  событие `exprEvaluated` и отвечают пусто (ядро сериализует их локом).
- `stop_on_error` снимайте (`on=False`), иначе база будет вставать на каждой ошибке языка.

## Как это работает

Конфигуратор общается с `dbgs.exe` по HTTP: `POST /e1crdbg/rdbg?cmd=<команда>`, конверт
`<request>` в пространстве `debugBaseData`, параметры — в префиксе схемы команды, события —
long-poll `pingDebugUIParams`. Протокол снят живым захватом и описан по кадрам в
[`docs/rdbg-protocol-2026-10-09.md`](docs/rdbg-protocol-2026-10-09.md); словарь команд и
способ его извлечения из бинарников — в
[`docs/debug-protocol-vocabulary.md`](docs/debug-protocol-vocabulary.md).

Ключевые находки, на которых стоит сервер:

| Находка | Следствие |
|---|---|
| `/DEBUG` не нужен, чтобы цель появилась | любой сеанс базы — цель; HTTP-вызов даёт цель типа `WEBService` |
| `version` точки платформа не сверяет | точку можно ставить по имени модуля, не имея профиля конфигуратора |
| `propertyID` — константа GUID на вид модуля | таблица из четырёх значений покрывает модуль объекта, менеджера, формы и однокомпонентные объекты |
| `attachDebugUI` не «висит» навсегда | `ibInDebug` снимается сам; `credentialsRequired` — несовпадение учётных данных, а не таймаут |
| Снимок `getDbgTargets` живёт дольше сеанса | цель в снимке может быть уже мёртвой; ядро различает это полем `stillInSnapshot` |

## Безопасность

- В репозитории нет паролей, строк соединения и дампов живой базы. Сырые замеры
  (`evidence/…`) не публикуются.
- Учётные данные сервера отладки берутся из `DBGSRV_USER`/`DBGSRV_PASSWORD` окружения
  сервера или из аргументов `session_start`; в ответы они не попадают.
- `credentials` на проводе — base64 от **UTF-8** (UTF-16LE `dbgs` отвергает).
- Учётные данные информационной базы для HTTP/SOAP-триггеров — только из окружения
  (`V8_DB_USER`/`V8_DB_PASS` в примерах), никогда не в командной строке.

## Ограничения

- **Клиентские цели недостижимы**: `Client`/`ManagedClient`/`WEBClient` к `dbgs` не
  соединяются (это канал EDT/WebSocket). Отлаживается серверный код: `Server`, `JOB`,
  `WEBService`, `HTTPService`.
- `fullCredentialsRequired` (файл `--debugServerUsers`) не воспроизведён: формат файла
  `dbgs` отвергает в текстовых вариантах, описание — в ИТС под авторизацией.
- Константы `propertyID` для `RecordSetModule`/`ValueManagerModule` снимаются только с
  кадра останова: статически из поставки платформы они не извлекаются.
- Снимок целей в `dbgs` нестабилен по времени жизни — используйте `auto_attach_targets`
  для коротких сеансов.

## Макет

```
qoder-1c-debug/   плагин Qoder: манифесты, .mcp.json, server/, scripts/
  server/         mcp_core (15 инструментов), rdbg_client, md_index, bp_store, транспорты
docs/             спецификация RDBG и словарь протокола
probes/           воспроизводимые пробы: безголовый останов, SOAP-триггер, таблица propertyID
scripts/          сборка ZIP плагина
```

## Лицензия

MIT — см. [LICENSE](LICENSE).
