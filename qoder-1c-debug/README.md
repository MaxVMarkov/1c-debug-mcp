# 1C Debug — плагин Qoder

MCP-сервер, который даёт агенту управление режимом отладки 1С:Предприятие 8.5:
точки останова, шаги, стек вызовов, вычисление выражений и изменение значений —
через сервер отладки кластера (`dbgs.exe`), без EDT и без кликов в конфигураторе.

## Как это устроено

```
server/mcp_core.py        список из 15 инструментов и их вызов (от транспорта не зависит)
server/debug_mcp_http.py  HTTP-транспорт: POST http://127.0.0.1:8123/mcp — он и объявлен в плагине
server/debug_mcp.py       stdio-транспорт: JSON-RPC по stdin/out, для проверки вслепую без Qoder
server/rdbg_client.py     клиент RDBG: POST /e1crdbg/rdbg?cmd=<команда> + long-poll событий
server/bp_store.py        чтение рабочего листа точек из профиля конфигуратора
```

Протокол воспроизведён по живому захвату трафика конфигуратора, а не по догадкам:
[`docs/rdbg-protocol-2026-10-09.md`](../docs/rdbg-protocol-2026-10-09.md).

## Предпосылки

- кластер 1С запущен, `ragent` стартует с `-debug` — тогда поднимается `dbgs.exe` на 1550;
- отлаживаемый сеанс запущен в режиме отладки: тонкий клиент с
  `/DEBUG /DebuggerURL=http://…` (браузерный веб-клиент предметом отладки не становится);
- **цель присоединена к нашему UI** (`attachDetachDbgTargets`, он же двойной клик в
  конфигураторе). Без неё точки уходят на сервер с HTTP 200, но не останавливают ничего, а
  `eval` отвечает пустым телом. С 0.0.4 это делает `breakpoints_set` (и `eval`/`locals`/
  `step`/`set_variable`) — явно звать `target_attach` не нужно;
- если на сервере отладки задан пароль (`dbgs.exe --password <пароль>`, это его собственный
  переключатель, а не настройка кластера), его надо передать: `session_start` принимает
  `password`/`user`, а без аргументов берёт `DBGSRV_PASSWORD`/`DBGSRV_USER` из окружения
  сервера. `credentials` на проводе — base64 от **UTF-8** (UTF-16LE сервер отвергает).
  Без пароля `attachDebugUI` отвечает `credentialsRequired`, и инструмент возвращает это как
  данные, а не как ошибку: `{'attached': false, 'reason': 'credentialsRequired',
  'passwordProvided': false, 'hint': …}`. Пароль в ответы не попадает (§15 спецификации).

## Типовой порядок вызовов

```
session_start(base)        → attachDebugUI, фоновый сбор событий
targets(base)              → id цели (state тут всегда null, см. спецификацию §5);
                             это СНИМОК dbgs: цель висит здесь 30…90 с после смерти клиента
breakpoints_set(base)      → без modules = рабочий лист конфигуратора; или свой список.
                             Сам присоединяет цель и пишет в attach, что произошло
target_attach(base)        → нужен только чтобы прикрепить/открепить явно (attach=false)
wait_stop(base)            → событие callStackFormed: кадры, строка, presentation с аргументами
eval / locals / step       → работа в приостановленном кадре (цель выбирают и крепят сами)
session_stop(base)         → detachDebugUI (обязателен: незакрытый UI блокирует базу)
```

Безголовый порядок (с 0.0.8) — без клиента вообще, серверный код вызывается HTTP-запросом:

```
session_start(base)
auto_attach_targets(base, types=["Server","JOB","WEBService","HTTPService"])
stop_on_error(base, on=true)          → останов на любом исключении языка, версия модуля не нужна
<свой HTTP/SOAP-вызов публикуемого сервиса базы>
wait_stop(base)                       → кадр с objectID/propertyID/version ЭТОГО модуля
step(base, Continue); stop_on_error(base, on=false)
breakpoints_set(base, modules=[{name, lines}], configPath=<выгрузка>)  # точка по ИМЕНИ модуля
breakpoints_set(base, modules=[{objectID, propertyID, version, lines:[…]}])   # или явно
<тот же вызов>                         → теперь цель встаёт на обычную точку
```

С 0.0.4 агент не обязан помнить про `target_attach`: `breakpoints_set`, `eval`, `locals`,
`set_variable` и `step` вызывают `attachDetachDbgTargets` сами, один раз на цель (повторный
`breakpoints_set` даёт `attachedNow: false`). `breakpoints_set` возвращает в `attach`
`targetType`, `seanceNo` и `stillInSnapshot` — снимок dbgs умеет содержать цель, сеанс которой
уже умер, а attach такой цели отвечает HTTP 200. Если присоединять нечего, `breakpoints_set`
возвращает `attach: {"error": …}` вместо молчаливого «HTTP 200, и ничего не останавливается».


## Проверить, что всё живое

```powershell
powershell.exe -NoProfile -File scripts/status.ps1     # слушает ли :8123 и :1550
powershell.exe -NoProfile -File scripts/start-server.ps1  # поднять сервер фоном
```

Без Qoder, по stdio:

```bash
printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' \
  '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"debug_status","arguments":{}}}' \
  | python server/debug_mcp.py
```

Ожидаемый смысл ответа: `{"dbgs_alive": true, "endpoint": "127.0.0.1:1550", "sessions": []}`.

## Транспорт

Объявлен **HTTP** (`.mcp.json` → `http://127.0.0.1:8123/mcp`): рабочий тип, проверен многократно. HTTP-декларация не поднимает процесс сама,
его запускаешь ты (`scripts/start-server.ps1`); проверка ответа — `GET /` (health).

`debug_mcp.py` оставлен как stdio-вариант: он годится, чтобы прогнать инструменты по stdin
и чтобы переключиться на stdio, если Qoder его всё же поддерживает.

## Установка из ZIP

Qoder ставит плагины из архива (панель плагинов → Upload Plugin → ZIP). **Архив должен
раскладываться манифестом в корне, без папки-обёртки**, поэтому пакуются *содержимое*
каталога, а не сам каталог:

```bash
python ../scripts/pack_plugin.py     # из этого каталога; или python scripts/pack_plugin.py из корня репозитория
```

Результат — `dist/1c-debug-<version>.zip`, имя берётся из `version` манифеста. После
установки — **полный перезапуск Qoder**: MCP подключается только на старте приложения.
Сервер (`scripts/start-server.ps1`) надо поднять **до** старта Qoder, иначе инструменты
не появятся. Правки в этом каталоге в установленный плагин не попадают: установка —
это снимок в `~/.qoder/plugins/cache/local/1c-debug/<version>`, поэтому каждая итерация =
пересобрать ZIP → переустановить → перезапустить.

## Инструменты

| Инструмент | Что делает |
|---|---|
| `debug_status` | жив ли `dbgs.exe`, какие сеансы открыты |
| `session_start` / `session_stop` | `attachDebugUI` + фоновый сбор событий / `detachDebugUI` |
| `targets` | предметы отладки (`state` здесь всегда `null` — `getDbgTargets` не отвечает состоянием, оно приезжает событием) |
| `target_attach` | присоединить цель к нашему UI (`attachDetachDbgTargets`) — то, что в конфигураторе делает двойной клик. Без него точки принимаются сервером, но не останавливают |
| `breakpoints_list` | рабочий лист точек из профиля конфигуратора (там `objectID`/`propertyID`/`version`) |
| `breakpoints_set` / `breakpoints_clear` | push рабочего листа: `modules=[{name, lines}]` (имя модуля + `configPath`) или явно `{objectID, propertyID, version, lines}`; без modules — всё из профиля конфигуратора. `breakpoints_clear` снимает всё |
| `stop_on_error` | включить/снять останов на ран-тайм ошибке (`setBreakOnRTE`): ловит исключение в модуле, где точку поставить нечем; в ответе read-back `getBreakOnRTE` |
| `auto_attach_targets` | приказать серверу самому присоединять цели указанных типов (`setAutoAttachSettings`) — нужно для целей, живущих секунды: сеанс от HTTP-вызова, фоновое задание |
| `wait_stop` | дождаться паузы и вернуть стек кадров |
| `step` | `Step` (F10), `StepIn` (F11), `StepOut` (Shift+F11), `Continue` (F9) |
| `eval` / `locals` / `set_variable` | выражение в кадре, локальные переменные, присвоение |

Вычисления — строго по одному на сеанс (инструменты сами ждут под локом); параллельные
`eval` + `locals` в один момент времени дают пустой ответ без ошибки.

`eval`/`locals`/`set_variable` не полагаются на один синхронный ответ: `dbgs` часто
отвечает пустым `<response/>`, а значение приезжает **следующим событием** `exprEvaluated`
с тем же `expressionResultID`. Ядро берёт его из очереди сборщика (до 6 с) и отличает
«цели нечем отвечать» (пусто) от «выражение с ошибкой» (`withErrors` + декодированный
`exceptionStr`).

## Статус

Проверено на практике: фоновое задание запускается одним SOAP-вызовом
(web-сервис EnterpriseDataExchange -> `ДлительныеОперации.ВыполнитьВФоне`) и встаёт
на точку, заданную именем модуля (docs §17.11).

Спринт 0.0.12: `breakpoints_set` понимает имя модуля — `CommonModule.Х`, `WebService.Х`,
`HttpService.Х`, `Document.Х.ObjectModule`, `Document.Х.ManagerModule`, `Х.Form.Форма`. `objectID`
берётся из `ConfigDumpInfo.xml` выгрузки (`configPath` или `V8_CONFIG_SRC`), `propertyID` — из
таблицы констант, `version` пишется нулями, потому что платформа его не сверяет. Проверено живьём:
точка `CommonModule.МобильноеПриложениеЗаказыКлиентов:71` остановила SOAP-вызов
(`evidence/named_breakpoint_0_0_12.txt`).

Спринты 0.0.10–0.0.11: `version` точки останова платформой НЕ сверяется — точка с сорока нулями
останавливает код и в знакомом модуле, и в том, который агент взял только из `ConfigDumpInfo.xml`
(docs §17.7). Плюс `locals` повторяет запрос с паузой: первый ответ после останова бывает пустой.

Спринт 0.0.9: `eval`/`locals`/`set_variable` сериализованы локом на сеанс — два вычисления,
отправленных одновременно на один UI, утаскивают чужое `exprEvaluated` и отвечают пустотой
(замер 2026-10-17 через плагин: `locals` рядом с `eval` вернул `correctly` без строк).

Спринт 0.0.8: безголовый вход. Сеанс без `/DEBUG` появляется в целях сам (замер 2026-10-17),
цель от SOAP-вызова веб-сервиса имеет тип `WEBService`, добавлены `stop_on_error` и
`auto_attach_targets`, а `version` модуля агент теперь берёт из кадра останова — точка, собранная
из снятой версии, реально останавливает код (`evidence/headless_bp_from_oracle.txt`). Попутно
исправлены две вещи, из-за которых цикл не работал: кадр терял `moduleID` (поля вложены, а парсер
смотрел только прямых детей) и eval/locals уходили в устаревшую цель снимка.

Спринт 0.0.7: `credentialsRequired` описан правильно — это несовпадение учётных данных в обе стороны (сервер без `--password` отвергает UI, приславший пароль), в ответе есть `passwordProvided`/`userProvided`, по которым это видно сразу.

Спринт 0.0.6: `session_start` умеет учётные данные сервера отладки (`user`/`password` или
`DBGSRV_USER`/`DBGSRV_PASSWORD`), отказ по паролю — данные, а не ошибка, и не повторяется
вслепую. Кадр `credentialsRequired` снят на отдельном `dbgs` с `--password` (§15).

Спринт 0.0.5: `session_start` разбирает `ibInDebug` как преходящее состояние, а не как сбой —
отвечает `{'attached': false, 'reason': 'ibInDebug', 'attempts': N, 'retryAfterSec': 120}`,
повторяя `attachDebugUI` внутри вызова не дольше 60 с (`wait`, по умолчанию 30). Дольше ждать
внутри инструмента нельзя: длинный `tools/call` транспорт MCP обрывает раньше (замер:
`wait=110` → `MCP error -32603`, а база к этому моменту уже была свободна).

Спринт 0.0.4: 13 инструментов; `breakpoints_set`/`eval`/`locals`/`step`/`set_variable`
присоединяют цель сами (0.0.3 требовал ручного `target_attach`), `targets` помечает
прикреплённые нами цели (`attachedByThisUI`) и предупреждает, что это снимок, а не живые
сеансы. В 0.0.3 были добавлены `target_attach` и чтение `eval`/`locals`/
`set_variable` из события `exprEvaluated`, локальные парсятся из
`evalExprResBaseData/calculationResult`.

**Конечная проверка пройдена 2026-10-10:** тонкий клиент запущен нами с `/DEBUG`, точка в
заимствованном модуле объекта `ЗаказКлиента` (строка 7, `Расш_ПриКопировании`) остановила
копирование документа, `eval` вернул `ОбъектКопирования.ПоРезервнойКассе = Число 44686`,
`locals` — `ОбъектКопирования` типа `ДокументОбъект.ЗаказКлиента`. Конфигуратор в этом не
участвовал. Transcript — `evidence/step2_final_proof.txt`; полный цикл со `Step`
(37 940 → 0 на строке 7, вызовами из агента) — `evidence/debug_loop_20261010.txt`; разбор
протокола остановки —
[`docs/rdbg-protocol-2026-10-09.md`](../docs/rdbg-protocol-2026-10-09.md) §12.

Не закрыто: `targetType=Client` (клиентский процесс к `dbgs` не соединяется никогда — §9;
типы `Client`/`ManagedClient`/`WEBClient`/`COMConnector` из перечисления `DebugTargetType`
недостижимы) и `fullCredentialsRequired` (нужен файл `--debugServerUsers`, формат которого
`dbgs` отвергает в текстовых вариантах, а описание — в ITS под авторизацией).
