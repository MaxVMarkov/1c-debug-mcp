# RDBG-протокол 1С:Предприятие 8.5 — снят с живого трафика 2026-10-09

> Сырые дампы замеров (`evidence/…`) и часть скриптов рабочего журнала (`probes/…`) в
> публичную версию не входят: в дампах есть данные конкретной информационной базы.
> Имена файлов оставлены как ссылки на журнал замеров; методика воспроизводится по
> описанию в тексте.

Источник — `../evidence/capture_20261009_session1.txt` (первый сеанс конфигуратора) и
`../evidence/capture_20261009_session2.txt` (сеанс с целью отладки, попаданием в
брейкпоинт и шагами). Разбор по кадрам: `dbg_targets_response.txt`, `step_response.txt`,
`step_exchange.txt`, `state_frames.txt`, `push_context.txt`, `base64_fields_decoded.txt`.
Переснять захват: MITM-прокси между конфигуратором и `dbgs:1550` (клиент направляется на
прокси через `/DebuggerURL`), тела запросов/ответов пишутся как есть.

Всё ниже — наблюдение, а не вывод из XSD. Там, где XSD и наблюдение расходятся, сказано
отдельно.

## 1. Транспорт и маршрут

| | |
|---|---|
| Сервер | `dbgs.exe`, HTTP/1.1, `0.0.0.0:1550`, `Server: 1C:Enterprise/8.5.1.1529` |
| Командный ресурс | `POST /e1crdbg/rdbg?cmd=<команда>` |
| Проверка соединения | `POST /e1crdbg/rdbgTest?cmd=test` |
| Обязательные заголовки запроса | `Accept: application/xml`, `Accept-Charset: utf-8`, `Content-Type: application/xml; charset=utf-8` |
| Тело запроса | UTF-8 с BOM (`ef bb bf`) |
| Соединение | короткое на большинство команд; `Connection: Keep-Alive` держит один длинный канал, по которому приходят события |

Дискриминатор команды — **query-параметр `cmd=`**. Пути вида `/DEBUGTARGET`, `/e1crdbg`,
`/e1crdbg/cmd` (мы перебирали ~350 комбинаций) не работают: `/e1crdbg` сам по себе 404.
`GET /` — только баннер «it works», не эндпоинт.

Ответы: `200 OK` с XML-телом, `200 OK` + `Content-Length: 0` (принято без данных),
`204 No content` (пинг без событий). Сервер соединение не закрывает — читать строго по
`Content-Length`.

## 2. Конверт

Запрос (пример `cmd=step`, 915 байт):

```xml
<?xml version="1.0" encoding="UTF-8"?>
<request xmlns="http://v8.1c.ru/8.3/debugger/debugBaseData"
         xmlns:cfg="http://v8.1c.ru/8.1/data/enterprise/current-config"
         xmlns:debugRDBGRequestResponse="http://v8.1c.ru/8.3/debugger/debugRDBGRequestResponse"
         xmlns:v8="http://v8.1c.ru/8.1/data/core" xmlns:xs="…" xmlns:xsi="…">
  <debugRDBGRequestResponse:infoBaseAlias>demo-base</debugRDBGRequestResponse:infoBaseAlias>
  <debugRDBGRequestResponse:idOfDebuggerUI>8faca847-…</debugRDBGRequestResponse:idOfDebuggerUI>
  <debugRDBGRequestResponse:idOfDebuggerUI>8faca847-…</debugRDBGRequestResponse:idOfDebuggerUI>
  <debugRDBGRequestResponse:targetID><id>4436bd7d-…</id></debugRDBGRequestResponse:targetID>
  <debugRDBGRequestResponse:action>Step</debugRDBGRequestResponse:action>
</request>
```

Правила, подтверждённые наблюдением:

* Корень — `<request>` в пространстве `debugBaseData`; команды различаются **только**
  параметром `cmd` в URL. **`xsi:type` в запросах нет ни в одном кадре.**
* Все параметры — дети корня, в префиксе пространства той схемы, где описан тип команды
  (`debugRDBGRequestResponse:`, вложенные структуры — `debugBreakpoints:`, `debugArea:`,
  `debugAutoAttach:`, `debugRTEFilter:`).
* Имена регистросочетаемы с XSD (`infoBaseAlias`, `idOfDebuggerUI`, `bpWorkspace`).
* Квирит платформы: `idOfDebuggerUI` в `cmd=step` продублирован дважды. XSD (`
  RDbgBaseRequest`) объявляет элемент один раз, то есть сериализатор выписывает
  наследованный элемент и элемент самого типа. При чтении это безвредно, при записи —
  не известно, обязательно ли дублировать; безопаснее слать один раз и смотреть ответ.
* Ответ — `<response>` в том же пространстве `debugBaseData`; полиморфный результат
  кладётся в `<result>` **с `xsi:type`**:

```xml
<result xsi:type="debugDBGUICommands:DBGUIExtCmdInfoCallStackFormed"> … </result>
```

То есть вчерашняя гипотеза «xsi:type как дискриминатор» верна ровно наполовину: не для
запроса, а для ответа.

## 3. Команды, снятые в этом сеансе

| `cmd=` | Назначение по XSD | Ключевые поля тела | Ответ |
|---|---|---|---|
| `test` (`/rdbgTest`) | тест связи | пусто | `200`, `Content-Length: 0` |
| `attachDebugUI` | регистрация UI отладчика | `infoBaseAlias`, `idOfDebuggerUI`, `options/foregroundAbility=true` | `<result>registered</result>` |
| `initSettings` | стартовая синхронизация рабочего окружения | `data{bpWorkspace, …}`, префиксы debugArea/debugAutoAttach/debugRTEFilter | — |
| `setBreakpoints` | установить точки | `bpWorkspace{moduleBPInfo[]}` — **весь набор, не дифф** | `200`, `Content-Length: 0` |
| `getDbgTargets` | список предметов отладки | base + UI id | `<id>…</id>` на цель либо пустой `<response/>` |
| `attachDetachDbgTargets` | прикрепить/открепить цель | `attach=true`, `id{id}` | — |
| `step` | шаг/продолжение | `targetID{id}`, `action=Step` | `<item>{targetIDStr, targetID, stateNum, state}</item>` |
| `pingDebugUIParams` | long-poll событий | пустое тело (41 байт — только декларация XML); в URL ещё `&dbgui=<uuid>&str` | `204` или 200+событие |
| `setBreakOnRTE` | поведение при ВП | — | — |
| `setInaccessibleModules` | недоступные модули | — | — |
| `clearBreakOnNextStatement` | сброс «остановить на следующей» | — | — |
| `detachDebugUI` | отключение UI | — | — |

Не снято (остальные имена есть в `docs/debug-protocol-vocabulary.md` и в XSD):
`evalLocalVariables`, `modifyValue`, `getCallStack`, `getBreakpoints` (см. §10 — похоже,
штатно не вызывается), `getAutoAttachSettings`, `restart`. Сняты дополнительно к таблице:
`evalExpr` (§8), `terminateDbgTarget`, `startUpdateIB`/`finishUpdateIB`,
`setBreakOnNextStatement`, `setAutoAttachSettings`.

## 4. Идентификаторы: чем что опознаётся

**Предмет отладки** (`targetID`, он же `id` в `attachDetachDbgTargets`):

```xml
<id>4436bd7d-2bc3-4abb-a55d-169f8cc74ed6</id>          <!-- id цели -->
<seanceId>01cd3354-c404-4b46-ae7d-2eb428a1aea4</seanceId>
<seanceNo>2</seanceNo>
<infoBaseInstanceID>975a42cc-738d-4310-9f4e-49d4395d1f31</infoBaseInstanceID>
<infoBaseAlias>demo-base</infoBaseAlias>
<isServerInfoBase>undefined</isServerInfoBase>
<userName>&lt;user&gt;</userName>
<configVersion>8a8e37de8de0b944b85c0c9a8f8fe1fe00000000</configVersion>
<targetType>Server</targetType>
```

Плюс параллельно `targetIDStr` — непрозрачный base64-бинарь (~120 байт), который сервер
возвращает как есть. **Не текст**: UTF-8/UTF-16 декод не проходит. В командах достаточно
структурного `targetID` с одним `<id>`.

**Модуль** (ключ точек останова и кадров стека):

```xml
<id><type>ExtensionModule</type><extensionName>МоеРасширение</extensionName>
    <objectID>a01a3d99-7a25-4b42-98a4-1da9e2cdf141</objectID>
    <propertyID>a637f77f-3840-441d-a1c3-699c8c5cb7e0</propertyID>
    <version>7c9e581ae4509b944b6726a94d120119f129157f</version></id>
```

Для модулей основной конфигурации `type`/`extensionName` отсутствуют — только
`objectID`/`propertyID`/`version`. Это главная практическая проблема клиента MCP:
**ставить брейкпоинт по имени модуля нельзя, нужен `objectID`/`propertyID`/`version`**.

Происхождение этих трёх полей проверено на всём дереве исходников
(`../evidence/uuid_provenance_in_sources.txt`, `../evidence/setbreakpoints_form.txt`):

| поле | откуда берётся | проверка |
|---|---|---|
| `objectID` | **UUID метаданных** — есть в `ConfigDumpInfo.xml` и в XML объекта | `8f5cef8f…` = `DataProcessor.МоеРасширениеНастройки.Form.Форма`, `a01a3d99…` = `Document.ЗаказКлиента`, `579651ea…` = `DataProcessor.ОперацииЗакрытияМесяца`, `024d5d02…`/`b096d06b…` = формы |
| `propertyID` | **не из исходников** — GUID вида модуля, которым считает платформа | `32e087ab-1491-49b6-aba7-43571b41ac2b` у всех трёх модулей **форм**; у модуля объекта базового `DataProcessor` — `d1b64a2c…`, у нашего **заимствованного** модуля объекта — `a637f77f…`. В `<configSrc>` (расширение + базовая `cf`) ни один из них не встречается |
| `version` | **не `configVersion` объекта** | для формы `8f5cef8f` в кадре `a1295f6639c377a7dfc4a51b5a2a48176a55c324`, в `ConfigDumpInfo.xml` у неё `16683591b522f72f…`, у `…Form.Form` — `e4af1d71b29f51ad…`; совпадений нет |

Вывод, без наивности: по дереву XML агент способен восстановить только `objectID`.
`propertyID` и `version` в исходниках отсутствуют.

**Но источник найден 2026-10-10** (`qoder-1c-debug/server/bp_store.py`, `docs/rdbg-protocol-2026-10-09.md, §4`):
конфигуратор хранит рабочий лист точек в своём профиле —
`%APPDATA%\1C\1cv8\<профиль>\<GUID>\1cv8.pfl`, ключ `Breakpoints`, запись вида

```
{"",0},<objectID>,<propertyID>,0,<version как GUID>,<n>,base64(20 байт),"<имя расширения>"
```

base64-поле и есть `version` из провода (совпало байт в байт на всех 5 модулях
захвата), а «GUID» рядом — те же первые 16 байт в смешанном порядке (little-endian в
первых трёх группах). Строки точек идут следующим блоком как `{1,<line>,1,0,…}`.
Самопроверка сверяет два независимых источника: множество троек из провода обязано
содержаться в том, что читается из профиля (`probes/rdbg_selftest.py`, 11/11).

То есть агент может ставить брейкпоинты без мыши: прочитать профиль, взять оттуда
тройки для уже знакомых модулей и отослать `setBreakpoints` своему `dbgs`. Для модуля,
который в листе никогда не был, тройки всё равно неоткуда взять — это остаётся
ограничением (см. §10).

## 5. Состояния цели

Снимок: `stateNum=16`, `state=Worked`.

`DbgTargetState` из `schemas/debugBaseData.xsd`: `Undefined`, `NotRegistered`,
`Registered`, `WaitDebugger`, `Worked`, `StopOnNextLine`, `Evaluating`, `Terminating`,
`Last`. Нумерация **не совпадает** с позицией в перечислении (Worked — пятый по счёту,
`stateNum` при этом 16), поэтому клиенту надо читать строковый `state`, а `stateNum`
считать платформенным флагом и не пытаться выводить из него состояние.

**Поправка 2026-10-10:** состояния в `getDbgTargets` вообще нет. Сырой ответ на этот
запрос содержит только `id / seanceId / seanceNo / infoBaseInstanceID / infoBaseAlias /
isServerInfoBase / userName / configVersion / targetType` — без `<state>` и `<stateNum>`
(`evidence/raw_eval_state.txt`). Значит `state` приезжает **только событием**
(`dbgTargetStateChanged`), а список целей всегда даёт `state=null`. Тот снимок с
`stateNum=16` был взят из события, не из ответа на `getDbgTargets`.

## 6. Модель событий: long-poll через ping

* UI держит одно keep-alive соединение и шлёт `pingDebugUIParams` каждые **5 секунд**.
* Нет событий → `204 No content` (70-байтовый кадр заголовка).
* Событие готово → оно приходит **ответом на уже отправленный ping** (`200`, тело с
  `<result xsi:type="debugDBGUICommands:DBGUI…">`), после чего UI тут же шлёт следующий
  ping. За один ответ доставляется одно событие.
* Отсюда задержка обнаружения остановки — до 5 с. Наблюдение: `step` отправлен в
  23:33:21.810, событие `callStackFormed` — в 23:33:21.837 тем же висячим пингом
  (`evidence/step_exchange.txt`).

Снятое событие (полностью — `evidence/state_frames.txt`):

```
DBGUIExtCmdInfoCallStackFormed: cmdIDNum=7, cmdID=callStackFormed,
  stopByBP=true, suspendedByOther=false,
  callStack{ moduleID(см. §4), lineNo=7→8, isFantom=false, presentation }
```

`presentation` — base64 UTF-8 человекочитаемого кадра:

```
МоеРасширение Документ.ЗаказКлиента.МодульОбъекта.Расш_ПриКопировании
(ОбъектКопирования = Заказ клиента ЕСТН-002049 от 02.10.2026 13:03:00)
```

То есть стек даёт не только файл/строку, но и подписку вызова с фактическими
аргументами — годится как единственный «что произошло» для агента без дополнительных
запросов.

Но: **отдельного `getCallStack` в сеансе не было ни разу** — в том числе после открытия
панели «Стек вызовов». Панель заполняется из того же `callStackFormed`, и вопрос «верхушка
это или весь стек» **закрыт в 00:34**: когда F11 (`action>StepIn`, третий член enum
`DebugStepAction` = Unknown/Step/StepIn/StepOut/Continue) углубил вызов, число элементов
`<callStack>` в событии выросло вместе с глубиной: 1 → 2 → **3** → 2, а тело события —
2390 → 3407 → 4173 → 3407 байт (~1 КБ на кадр). Раньше стек был реально глубиной 1.

Содержимое трёхкадрового события (`evidence/callstack_depth3.txt`) — порядок сверху вниз,
[0] текущий:

| # | кадр | lineNo |
|---|---|---|
| 0 | `МоеРасширение Обработка.МоеРасширениеНастройки.Форма.Форма.ПриСозданииНаСервере(Отказ = Ложь, СтандартнаяОбработка = Истина)` | 85 |
| 1 | `ОбщийМодуль.ОбновлениеИнформационнойБазы.Модуль.ПроверитьОбъектОбработан(Данные = ДанныеФормыСтруктура, Форма = ФормаКлиентскогоПриложения, …)` | 216 |
| 2 | тот же модуль, выше по стеку | 2939 |

Важная деталь для парсера: у кадров базовой конфигурации `type` и `extensionName`
**отсутствуют** (в XSD это дефолт `ConfigModule`), но `objectID` есть всегда. `presentation`
содержит имя модуля, путь метаданных, имя процедуры и **фактические аргументы вызова** —
этого достаточно, чтобы агент понимал «где я», не разбирая UUID.

## 7. Как вообще появляется предмет отладки (без этого список пуст)

Пустой `getDbgTargets` — не поломка сервера, а отсутствие зарегистрированной цели.
Проверено: `rphost` начинает держать соединения с `1550` только после того, как
пользовательский сеанс запущен в режиме отладки:

```
1cv8c.exe /S localhost/demo-base /N… /P… /DEBUG /DebuggerURL=http://127.0.0.1:15999
```

* `/DEBUG` без схемы в `DebuggerURL` даёт **tcp**-движок и отказ
  «Неверно указан протокол отладки: на сервере - "http", в запускаемом приложении - "tcp"».
  Переключатель — схема внутри `DebuggerURL`; строки `TCP protocol / StartDebugger /
  DebuggerURL / HTTP` в `1cv8c.exe` (`evidence/debug_protocol_switch.txt`).
* Браузерный веб-клиент цели не создаёт.
* `rphost` регистрируется в `dbgs` **напрямую** (`172.16.0.2:1550`), минуя прокси:
  адрес сервера отладки он берёт из настроек кластера. Значит половина DBGTGT
  (`RegisterDebugTarget`, `OnEnterStackFrame`) через конфигураторный перехват недоступна —
  как и предупреждал runbook.
* Настройка адреса сервера отладки, которую видит конфигуратор, хранится в
  `%APPDATA%\1C\1cv8\<profile>\1cv8.pfl` (`remoteDebugServer`, `remoteDebugServerHistory`).

### Цели мало — её надо присоединить к своему UI

Регистрация цели (`rphost` сказался в `dbgs`) не означает, что **наш** отладчик её видит:
пока UI не выполнит `attachDetachDbgTargets` с `attach=true`, `setBreakpoints` уходит на
сервер и принимается (HTTP 200), но останавливать нечего, а `evalExpr` отвечает пустым
телом. Это и есть двойной клик по цели в конфигураторе — форма запроса снята 2026-10-09
(`attach` + `DebugTargetIdLight` внутри `idOfDebuggerUI`), повторена своим клиентом
2026-10-10: `HTTP 200` на `ca03b3c9-…`, `evidence/target_attach_check.txt`.

Порядок для агента поэтому такой: `session_start` → `targets` → `target_attach` →
`breakpoints_set` → `wait_stop`.

### Отладочный сеанс запускается без конфигуратора

```
1cv8c.exe /S localhost/demo-base /N… /P… /DEBUG /DebuggerURL=http://127.0.0.1:15999
```

(`probes/run_debug_session.ps1`, учётные данные из `HKCU\Environment`). Цель появилась через
~20 с после старта окна; при старте в списке было **две** цели — `targetType=JOB`
(seanceNo 4) и `targetType=Server` (seanceNo 1), через минуту осталась только `Server`.
`JOB` — первое наблюдение типа цели, отличного от `Server`, замера его содержания не было.

## 8. Вычисление и изменение значений (`evalExpr`, `evalLocalVariables`, `modifyValue`)

Запрос (снято 4 вызова, `evidence/eval_frames.txt`):

```xml
<debugRDBGRequestResponse:calcWaitingTime>100</…>            <!-- мс ожидания синхронного результата -->
<debugRDBGRequestResponse:targetID><id>7514c255-…</id></…>   <!-- DebugTargetIdLight: достаточно <id> -->
<debugRDBGRequestResponse:expr>
  <debugCalculations:srcCalcInfo>
    <debugCalculations:expressionID>66fd788c-…</…>            <!-- UUID генерирует клиент -->
    <debugCalculations:expressionResultID>7f653735-…</…>      <!-- и correlation id тоже -->
    <debugCalculations:calcItem>
      <debugCalculations:itemType>expression</…>
      <debugCalculations:expression>Объект.ИмяQRКомпоненты</…>
    </…>
  </…>
  <debugCalculations:presOptions><debugCalculations:maxTextSize>10240</…></…>
</debugRDBGRequestResponse:expr>
```

Ответ приходит **дважды и разными дорогами**: синхронно на том же соединении (успех/ошибка
быстро) и отдельным событием `DBGUIExtCmdInfoExprEvaluated` (`cmdIDNum=8`) через висячий
ping — клиент должен сопоставлять их по `expressionResultID`, а не по порядку.

Проверено своим клиентом 2026-10-10, и это же вскрыло баг в нашей реализации (правило-то
было записано, коду оно было не нужно):

* если цель **не приостановлена**, синхронный ответ — `HTTP 200` и пустой
  `<response/>` в 392 байта (только конверт). Ни состояния, ни значения. Инструмент,
  который читает только его, отдаёт `{"state": null, "value": null}` — выглядит как
  сбой разбора, а на самом деле это честное «спросить негде»;
* если цель приостановлена, значение приедет **то ли** в синхронном ответе
  (`<result><evalResultState>correctly` + `valueDecimal`/`valueString` + `pres`),
  **то ли** следующим событием `exprEvaluated` — как успеет. Серия из 12 вызовов
  (`evidence/eval_parity_vs_cache.txt`, `evidence/eval_body_shapes.txt`) дала и то и
  другое на одном и том же выражении; `calcWaitingTime` 100/1000/5000 мс на долю
  синхронных ответов не влияет (`evidence/eval_waiting_time_experiment.txt`), так что
  гадать нельзя — надо ждать события по `expressionResultID`;
* `pres` и строковые значения — base64 (`pres` ответа `10` = `MTA=`);
* payload локальных (`calculationResult` с `valueOfContextPropInfo`) лежит **внутри**
  `evalExprResBaseData`, а не прямо в `<result>` — старый парсер искал его на уровне
  `result` и поэтому молча возвращал пустой список локальных. После правки на том же
  вчерашнем дампе читаются `Отказ = Ложь`, `СтандартнаяОбработка = Истина`,
  `qrLib/fptr = Неопределено` (`evidence/locals_event_shape_probe_after_fix.txt`).

Успешный результат (`evidence/eval_decoded.txt`):

```
evalResultState = correctly
resultValueInfo{ typeCode=4, typeName=Строка,
                 value  = base64("QRCoder.QRCodeHelper"),
                 pres   = base64("\"QRCoder.QRCodeHelper\"") }
```

Значение и представление — **base64**, даже для простой строки. `typeCode` числовой,
`typeName` человекочитаемый; в XSD (`schemas/debugCalculations.xsd:97`) typeCode — просто
decimal, соответствия типов надо накапливать наблюдениями (4 = Строка).

Негатив, который сначала прочитал неправильно (исправлено по `evidence/eval_expressions_map.txt`).
Префикс `{<Неизвестный модуль>(строка,колонка)}` в `exceptionStr` **не означает** отсутствие
контекста: так платформа называет анонимный модуль, в который компилируется набранное
выражение. Он присутствует и при безобидной синтаксической ошибке (`=` → «Ожидается
выражение»), и при настоящем BSL-несоответствии. Diagnostic-нагрузка — только в тексте после
двоеточия.

Снятые случаи (цель всё это время висела на паузе — между 00:15:25 и 00:17:07 не было ни
`Step`, ни `Continue`):

| выражение | `evalResultState` | текст ошибки / значение |
|---|---|---|
| `Объект.ИмяQRКомпоненты` | `correctly` | base64 → `QRCoder.QRCodeHelper` |
| `ПриСозданииНаСервере` | `withErrors` | Поле объекта не обнаружено (ПроверитьОбъектОбработан) |
| `ОбщегоНазначенияУТ.НастроитьПодключаемоеОборудование` | `withErrors` | Поле объекта не обнаружено (…) |
| `=` | `withErrors` | Ожидается выражение |
| `ЭтотОбъект.ЭтоНовый()` | `withErrors` | Метод объекта не обнаружен (ЭтоНовый) |

Открытый вопрос **закрыт** (00:22:22 и 00:23:28, `evidence/eval_last.txt`): `evalExpr` по
имени локальной переменной вернул ровно то же, что панель локальных — две проверки,
`Отказ` → `correctly / Булево / valueBoolean=false / pres=«Ложь»` и
`СтандартнаяОбработка` → `correctly / Булево / valueBoolean=true / pres=«Истина»`. То есть `evalExpr` и
`evalLocalVariables` вычисляются **в одном контексте текущего кадра**; клиенту достаточно
одной механики, а `evalLocalVariables(interfaces=context)` — это только пакетная выборка
имён кадра. Болевым местом остаётся не контекст, а то, что `typeCode`/`value*` надо
разворачивать по коду типа: `2` = `valueBoolean`, `4` = `value`/`pres` в base64,
`100` = разворачиваемый контекст (`isExpandable`), «Неопределено» приходит вообще без
значения, только `typeName`.

## 8b. Пакетная выборка и изменение значения

**`cmd=evalLocalVariables`** (00:21:04) — панель «Локальные переменные». Отличается от
`evalExpr` тем, что вместо выражения передаёт запрашиваемый **интерфейс**:

```xml
<srcCalcInfo><expressionID>…</expressionID><expressionResultID>…</expressionResultID>
  <interfaces>context</interfaces></srcCalcInfo>     <!-- нет <calcItem> -->
<presOptions><maxTextSize>307200</maxTextSize></presOptions>   <!-- в 30 раз больше, чем у evalExpr -->
```

Ответ — то же событие `exprEvaluated`, но корень `typeCode=100, isExpandable=true,
isSupportIContext=true`, а переменные списком `calculationResult/viewInterface=context` →
`valueOfContextPropInfo{propInfo{propName,isReaded}, valueInfo{…}}`. На снятой паузе:
`Отказ=Ложь`, `СтандартнаяОбработка=Истина`, `qrLib`/`fptr` — `Неопределено`.

**`cmd=modifyValue`** (00:25:44, `evidence/modify_request.txt`) — присваивание переменной:

```xml
<targetID><id>7514c255-…</id></targetID>
<modifyDataPath><srcCalcInfo>…<calcItem><expression>QRScale</expression></calcItem>
  <interfaces>context</interfaces></srcCalcInfo>…</modifyDataPath>
<newValueInfo><variant>expr</variant><valueExpression>6</valueExpression></newValueInfo>
```

Ответ **синхронный**, без события: `<newValueState>{evalResultState=correctly,
expressionResultID, resultValueInfo{typeCode=3, typeName=Число, valueDecimal=6,
pres=base64("6")}}`. То есть результат присваивания проверяется перечитыванием значения,
а не булевым «ок».

Сводка кодов типов, наблюдавшихся в этом сеансе (`typeCode` → элемент значения):
`2` Булево → `valueBoolean`; `3` Число → `valueDecimal`; `4` Строка → `value`/`pres`
(base64); `100` → разворачиваемый контекст; «Неопределено» приходит только как `typeName`,
без элемента значения.

## 9. Клиентский код (модуль формы) не отлаживается — проверено

Точка в `ПриОткрытии` модуля формы расширения **не сработала** при открытии формы. Причина не в
том, что точка «не встала» (она ушла на сервер в третьем `setBreakpoints`, `line 11`), а в
том, что исполнять её некому:

* код управляемой формы выполняется в **процессе клиента**, а не в `rphost`;
* клиент, запущенный самим конфигуратором, выглядит так (командная строка снята с PID):
  `1CV8C.exe /IBName"…" /N… /UseHwLicenses+ /TComp -SDC /Lru /VLru … /DEBUGGERURL"127.0.0.1:15999"`
  — то есть конфигуратор передаёт `-SDC` и адрес **без схемы**;
* при этом у этого процесса **нет ни одного соединения** с `15999`/`1550`: он говорит только
  с рабочим процессом сервера (`:1564`);
* **повторено 2026-10-10 на клиенте, запущенном нами** с `/DEBUG` и корректным
  `http://`-`DebuggerURL`, указывающим на записывающий прокси: прокси за весь сеанс не
  увидел от него **ни одного кадра** (в дампе только два моих `rdbgTest`), у PID клиента —
  0 соединений на 1550/15999, только `:1564`. Держат `dbgs` вдвоём `rphost`
  (`172.16.0.2:1550`) и наш отладчик (`127.0.0.1:1550`). То есть «клиент не подключается»
  не следствие `-SDC`/кривого адреса конфигуратора, а свойство платформы
  (`evidence/who_connects_to_dbgs.txt`);
* во всём дампе `targetType` был `Server` (16 запросов `getDbgTargets`, 7 описаний цели) —
  предмета отладки типа `Client` не регистрировалось ни разу.

Вывод для клиента MCP: адресовать можно только серверные предметы отладки. Отлаживаемый
аналог «много шагов на открытии формы» — `ПриСозданииНаСервере` той же формы или серверный
общий модуль, вызываемый при открытии: они исполняются в `rphost` и существующий `Server`
предмет их ловит (на этом же сеансе точка в модуле объекта поймалась).

Не установлено (осталось на будущее): что именно включает отладку клиентского процесса —
флаг ли в командной строке, настройка ли конфигуратора. В профиле
`%APPDATA%\1C\1cv8\<profile>\1cv8.pfl` есть `debugServerType = http`
(`evidence/debug_profile_keys.txt`), но ни одно из его значений не объясняет отсутствие
соединения у клиента.

## 10. Что надо доснять

Уже снято в этом сеансе: `step` с `action` = **Step, StepIn, StepOut, Continue** — то есть
весь рабочий словарь `DebugStepAction` (не снимался только `Unknown`, и он служебный),
`evalExpr` (успех и четыре вида ошибок),
`evalLocalVariables`, `modifyValue`, `attachDetachDbgTargets`, `getDbgTargets` с целями,
`terminateDbgTarget`, `startUpdateIB`/`finishUpdateIB`, `setAutoAttachSettings`,
`setBreakOnNextStatement`, `setInaccessibleModules`. Стек вызовов снимать нечем — запроса
`getCallStack` платформа не делает, весь стек приезжает в `callStackFormed` (§6).

| Кадр | Как получить |
|---|---|
| `getBreakpoints` | **платформой не вызывается**: открытие панели «Точки останова» не порождает запроса (замер 23:49:30). Рабочий лист читается из профиля конфигуратора (§4), а не с сервера |
| последовательность при отказе/неверном пароле | временно задать пароль сервера отладки |
| `targetType` кроме `Server` | отладка клиентского процесса (§9): механизм не найден, и 2026-10-10 показало, что сам клиент к `dbgs` не соединяется никогда. Частично сдвинулось: при старте сеанса в списке целей **появлялась** цель `targetType=JOB` (seanceNo 4) и через минуту исчезала — что это за цель и как её поймать осмысленно, не снимали |

## 11. Клиент работает сам, без конфигуратора (проверка 2026-10-10)

`qoder-1c-debug/server/rdbg_client.py` + самопроверка на живых кадрах (`probes/rdbg_selftest.py`:
194 разобранных тела, 10/10 сверок, 0 сбоев) и живой прогон
(`probes/rdbg_live_probe.py` → `evidence/rdbg_live_probe.txt`):

```
rdbgTest: True
attachDebugUI -> 'registered'   idOfDebuggerUI=08f9ec09-…   (uuid1, генерирует клиент)
getDbgTargets -> 0 целей        (отлаживаемого сеанса не запущено)
setBreakpoints (наше тело, 1 модуль, line 7) -> HTTP 200, тело 0 Б
setBreakpoints пустым списком                -> HTTP 200, тело 0 Б
ping за 10.0с -> None            (204, событий нет)
detachDebugUI -> HTTP 200
```

То есть сервер принимает тело, собранное не конфигуратором: конверт, префиксы
пространств имён и форма `bpWorkspace` воспроизведены верно, дублировать
`idOfDebuggerUI` (квирит конфигуратора) не требуется.

### Цена ошибки: `AttachDebugUIResult = ibInDebug`

Единственная неудача прогона оказалась интереснее удачи: после того как первый
вариант упал посередине, не сняв UI, `attachDebugUI` для `demo-base` стал отвечать
`ibInDebug` («база уже отлаживается»), хотя к `1550` не было ни одного соединения.
`detachDebugUI` чужим id сервер отвергает (`400`). Проверено:

* флаг привязан к базе — для `demo-base-2` attach/detach в тот же момент прошли нормально;
* флаг **протухает сам** — через несколько минут `demo-base` снова отвечает
  `registered`, перезапуск `dbgs`/кластера не потребовался;
* вывод для клиента: держать UI зарегистрированным можно только в `finally`, иначе
  база блокируется для всех остальных отладчиков на время жизни флага.

## 12. Конечная проверка: точка из агента останавливает сеанс (2026-10-10, 20:0x)

Главный вопрос всего исследования — «остановится ли код по точке, которую поставил агент,
в сеансе, который агент сам и запустил, без конфигуратора». Ответ **да**. Transcript —
`evidence/step2_final_proof.txt`, порядок такой:

| Шаг | Что ушло на сервер | Ответ |
|---|---|---|
| `session_start demo-base` | `attachDebugUI` | `registered`, ui `85fa13f6-…` |
| `targets` | `getDbgTargets` | 1 цель: `Server`, seanceNo 1, alias `demo-base`, configVersion `8ade47e3…` |
| `target_attach` | `attachDetachDbgTargets attach=true` | `HTTP 200` |
| `breakpoints_set` | `setBreakpoints`, 1 модуль: `a01a3d99… / a637f77f… / 7c9e581a…`, строка 7, `ExtensionModule`, `МоеРасширение` | `HTTP 200` |
| пользователь копирует документ | — | событие `callStackFormed`, `stopByBP=true`, `lineNo=7`, `presentation` = «МоеРасширение Документ.ЗаказКлиента.МодульОбъекта.Расш_ПриКопировании(ОбъектКопирования = Заказ клиента АБВ-000123 от 03.10.2026 17:00:10)» |
| `eval "ОбъектКопирования.ПоРезервнойКассе"` | `evalExpr` | **`Число 44686`**, `presentation` «44 686», за 0.1 с |
| `locals` | `evalLocalVariables` | `ОбъектКопирования`, тип `ДокументОбъект.ЗаказКлиента`, представление «Заказ клиента АБВ-000123…» |
| `session_stop` | `detachDebugUI` | `HTTP 200` |

Что это закрывает: конверт `bpWorkspace` работает не только «принят», но и **действует**;
`objectID/propertyID/version` из профиля конфигуратора пригодны нашему UI без пересчёта;
`presentation` кадра содержит фактические аргументы, так что агент понимает контекст
остановки без единого дополнительного запроса.

Оговорка к строке про `eval`: я тогда спросил `ОбъектКопирования.ПоРезервнойКассе` и по
неосторожности написал, что «в копии значение не обнулилось». Это неверно:
`ОбъектКопирования` — исходный документ, у него 44 686 и должно быть. Полный цикл с
шагом через строку 7 (`ЭтотОбъект.ПоРезервнойКассе = 0`) показывает 37 940 → 0, то есть
перехватчик на уровне объекта работает; закрыт ли вопрос для **сохранённой** копии —
другой замер, см. `evidence/debug_loop_20261010.txt`.

Оговорка про «свежесть» остановки: за ~40 с до этого `eval` ждал 6 с и получил пустой
ответ (цель не приостановлена), а событие приехало уже после `breakpoints_set` новым UI —
значит срабатывание новое, а не остаток прежней паузы. Подтверждено пользователем
(«да это я»): копирование было сделано в этот момент.

### 12b. Шаг как отдельное событие: `stopByBP` не различает точку и шаг

Снималось вызовами из агента (`evidence/debug_loop_20261010.txt`, плагин 0.0.3):

```
eval "ЭтотОбъект.ПоРезервнойКассе"   → Число 37940        (строка 7 ещё не исполнена)
step Step (F10)                       → state=Worked, stateNum=16
wait_stop                             → callStackFormed, lineNo=8, stopByBP=true
eval "ЭтотОбъект.ПоРезервнойКассе"   → Число 0            (присваивание сработало)
```

Практические следствия для агента:

* `step` отвечает **сразу** и состояние в этом ответе — `Worked`; кадр приходит следующим
  событием, поэтому после шага надо снова читать события, а не полагаться на ответ команды;
* шаг с последней исполняемой строки процедуры останавливается на `КонецПроцедуры`
  (`lineNo=8`) — то есть кадр ещё жив и в нём можно вычислить выражения «после»;
* `stopByBP` в этом пошаговом событии тоже `true` — по нему нельзя отличить попадание в
  точку останова от обычного шага. Различать можно только сопоставлением `lineNo` с
  множеством наших точек (или вести собственный счётчик: первое событие после
  `breakpoints_set` — останов, последующие после `step` — шаги).

Полезно к перечню §3: `attachDebugUI` наблюдались исходы `registered` и `ibInDebug`;
`credentialsRequired` не снимали (пароль сервера отладки на этой машине не задан).

## 13. Что такое `JOB` и сколько живёт цель после смерти клиента (2026-10-16)

Повторили цикл «сервер сам запускает клиента» на свежем сеансе и закрыли вопрос о цели
`targetType=JOB`, который висел с 2026-10-10. Полный протокол замеров —
`evidence/job_target_and_staleness_20261016.txt`.

**Определение взято из схемы платформы, а не из догадки.** `DebugTargetType`
(`schemas/debugBaseData.xsd:125-172`) перечисляет 19 значений; у `JOB` комментарий
«Предмет отладки работает на сервере как задание». Рядом — `Client`, `ManagedClient`,
`WEBClient`, `COMConnector` (клиентские), `Server`/`ServerEmulation`, серверные сервисы
(`WEBService`, `HTTPService`, `OData`), файловые варианты заданий и `WebSocket`.

**`JOB` — это не побочный эффект `attachDetachDbgTargets`.** Замер:

| действие | целей после |
|---|---|
| `targets` до attach | 1 (`Server`, seance_no=1) |
| `attach=true` | 2 — вторая `JOB`, seance_no=4, свой `seance_id`, тот же пользователь |
| `targets` через ~1 мин | 1 — `JOB` исчезла сама |
| `attach=false` → `attach=true` повторно | 1 → 1, `JOB` **не вернулась** |
| перезапуск клиента, 3 мин простоя | стабильно 1 `Server`, `JOB` не появлялась |

Значит `JOB` — самостоятельный сеанс задания той же ИБ (у неё свой `seance_id`/`seance_no`
при том же `info_base_instance_id` и `config_version`), живёт секунды-минуты и к нашему UI
никак не привязана. Наблюдение 2026-10-10 «JOB появляется на старте сеанса» — совпадение по
времени с разовым заданием, а не следствие запуска клиента.

**Цель переживает клиента на 30…90 с.** После `taskkill` клиента (pid 3812) `getDbgTargets`
всё ещё отдавала его цель `Server` seance_no=1; новая цель живого клиента (seance_no=2)
пришла в тот же снимок; устаревшая отвалилась только к T0+70 s. Для клиента MCP это значит,
что `targets` — снимок состояния `dbgs`, а не список живых сеансов: прежде чем ждать
останов по цели, надо убедиться, что её `seance_no`/`id` соответствует текущему запуску.

**`target_attach` без `target_id`** корректно берёт единственную цель (`target=a3942bd3…`
при одном клиенте) — штатный путь на случай «один отлаживаемый сеанс».

**Транспорт не изменился:** `1cv8c.exe` по-прежнему не имеет ни одного соединения с 1550
(только `:1564` к `rphost`), а `dbgs` держат `rphost` (2 соединения) и наш MCP-сервер (1).
Клиентские типы из перечисления (`Client`/`ManagedClient`/`WEBClient`) остаются
недостижимы через RDBG-адресацию тонкого клиента — см. §9.

**Про `rac` (чтобы не наступать второй раз):** хост передаётся без слэшей
(`rac localhost:1541 …`, форма `//host` даёт «No such host is known»), а `session list`
фильтруется **`--infobase=<uuid>`** — UUID базы, не имя (`-infobase demo-base` →
«неверный формат параметра»). Живой список сеансов в этот раз получить не удалось: вызов
зависает >60 с, процесс убит. `ragent` запущен без `-authon`, то есть дело не в пароле
кластера, а в форме команды.

### Хвост снимка длиннее 90 с, и attach на мёртвой цели отвечает HTTP 200

Поймал ту же ловушку на своей проверке 0.0.4: клиента в процессах уже нет, `rphost` с `dbgs`
не соединён, а `breakpoints_set` в этот момент находит цель и успешно её прикрепляет
(`attach.target=2690ec91…`, `attachedNow=true`), причём двумя вызовами позже `targets` отдаёт
пустой список. Идентификатор не совпадает ни с одной целью этого дня, так что природу
установить нечем — снимаю как факт «в снимке бывает цель без сеанса», а не как разбор.

Последствия для клиента MCP (реализовано в 0.0.4/0.0.5): `attach` в ответе
`breakpoints_set` возвращает ещё `targetType`, `seanceNo` и `stillInSnapshot` — второй
снимок на момент выхода из инструмента. Иначе агент читает HTTP 200 как «точка работает»,
тогда как остановиться нечему. Полная последовательность —
`evidence/0_0_4_check_and_phantom_target.txt`.

### Окно переснято: 4 замера, 90…150 с, повторные попытки его не продлевают

1…2 минуты из первого абзаца — это был один замер. Всего получилось четыре, и я дважды
ошибся, поэтому фиксирую все числа и что именно мерялось:

| цикл | держатель UI | как ждали | база свободна к |
|---|---|---|---|
| 1 | stdio-ребёнок Qoder (pid 26364) | одна попытка на t+3 с и t+11 с, дальше тишина | t+~95 с |
| 2 | `probes/dangling_ui.py` (pid 33608) | цикл `wait=110` (≈22 попытки по 5 с) | t+~145 с |
| 3 | тот же probe (pid 32796), тихо | попытка на t+~20 с, дальше тишина | t+~91 с |
| 4 | тот же probe (pid 29664) | `wait=10` (3 попытки), потом одна попытка | уже свободна к t+~140 с |

Промежуточный вывод по циклам 2 и 3: настойчивые повторы **не** продлевают блок — я это
заподозрил, неправильно прочитав таймлайн цикла 2 (считал «250 с», а реально t+~145 с),
подозрение снято, в цикле 3 специально мерил тишиной: 91 с. Диапазон держится:
**90…150 с**, и снимается сам, без `terminateDbgTarget` и без перезапуска `dbgs`.

### Почему `session_start` не ждёт внутри себя дольше минуты

Причина измерена, а не угадана: **`tools/call` в Qoder живёт ~72 с**. Замер 2026-10-16 —
`wait_stop(timeout=200)` (инструмент, который гарантированно блокируется на всю длину) запущен
в 18:57:12, оборван с `MCP error -32603: MCP tool invocation did not complete` в 18:58:24.
Сервер при этом не пострадал: `debug_status` сразу после обрыва ответил
`dbgs_alive: true, sessions: ["demo-base"]` (сеанс дожил), а `session_stop` отработал штатно.
Раньше я объяснял это «вызов с `wait=110` не досидел» — вывод тот же, но число было на глаз;
теперь оно мерено.

Отсюда конструкция 0.0.5: `wait` обрезан до 60 с, а `ibInDebug` возвращается **данными**, а не
ошибкой — `{'attached': false, 'reason': 'ibInDebug', 'attempts': 3, 'waitedSec': 10.0,
'retryAfterSec': 120, 'hint': …}`, и спит/повторяет уже агент. Любой инструмент, который может
блокироваться больше минуты, обязан отдавать управление вызывающему, иначе ответ теряется
вместе с соединением. Проверено живьём (цикл 4): на t+~10 с — `attached: false`, `attempts: 3`;
на t+~140 с — `attached: true, attempts: 1`.

Второе, про что надо не путать: `-32603` имеет **две разные** причины, и обе наблюдались сегодня.
(1) Длинный вызов, сверху порезанный транспортом (замер выше). (2) Устаревший
`mcp-session-id` после перезапуска сервера или потери процесса-ребёнка — тогда режутся уже
**все** вызовы плагина, пока приложение не перезапустят (зафиксировано ещё 2026-10-06 на
`delphi-mcp`, повторено сегодня на `1c-debug-stdio`, `python.exe` с `debug_mcp.py`).
Различать просто: после `dbgs_alive`-подобного вызова другой сервер отвечает, а этот — нет, и
`debug_status` по http живёт.

Заодно это единственный наблюдаемый исход `attachDebugUI` кроме `registered`/`ibInDebug`:
`credentialsRequired` по-прежнему не снят (пароль на `dbgs` не задан) — задача №27.

## 14. Сколько висит незакрытый `attachDebugUI` (снято 2026-10-16)

Раньше про это было только «незакрывшийся UI блокирует базу состоянием `ibInDebug`» (§11) и
без комментариев про сроки. Теперь срок измерен: процесс, державший UI, убит `taskkill /F` в
18:37:39; TCP-соединение с `dbgs` сервер сбросил сразу, но `attachDebugUI` отвечал
`ibInDebug` на t+3 с и на t+11 с, а на t+~90 с уже `registered`. То есть **висячий UI
блокирует базу порядка 1…2 минут и отпускает сам**, без перезапуска `dbgs` и без
`terminateDbgTarget`.

Последствия для клиента MCP:

* `ibInDebug` — это не «занято навсегда», а «подожди минуту». Инструмент должен уметь
  повторить, а не валить ошибку (задача на 0.0.5);
* сеанс нельзя держать как побочный эффект вызова: если процесс сервера умирает, база
  блокируется для всех, кто придёт следом, включая конфигуратор;
* `session_stop` — часть протокола вежливости, а не опция.

Попутно закрыт вопрос транспорта плагинов: Qoder умеет `stdio` в `.mcp.json` и поднимает
сервер сам, но поднимает **два** процесса и маршрутизирует в один из них, а потеря этого
процесса ломает плагин до перезапуска приложения. Замеры и разбор —
`evidence/stdio_transport_check_20261016.txt`.

## 15. Учётные данные сервера отладки: `credentialsRequired` снят (2026-10-16)

### Как это снималось, не трогая кластер

Пароль сервера отладки оказывается **свойством самого `dbgs.exe`**, а не кластера: `dbgs.exe
--help` перечисляет `--addr=<host>`, `--port=<port>`, `--portRange=<range>`,
`--ownerPID=<pid>`, `--service`, `--notify=<file>`, **`--password=<password> | -pwd`** и
**`--debugServerUsers=<file>`**. Значит рядом с рабочим `dbgs:1550` можно поднять ВТОРОЙ,
одноразовый сервер отладки на свободном порту со своим паролем:

```
probes/start_test_dbgs.ps1 -Port 1551 -Password <одноразовый>
probes/credentials_check.py --port 1551
probes/stop_test_dbgs.ps1 -Port 1551
```

Он ничего не знает ни о кластере, ни о базах — `attachDebugUI` ключуется только по
`infoBaseAlias`, и на вымышленной базе отвечает так же. Риск нулевой: `ragent -debug`,
`dbgs:1550` и сами базы не меняются. Проверка на свободность порта в скрипте не случайна:
с занятым портом `dbgs` падает сам (`Only one usage of each socket address`).

### Что показала матрица (`evidence/credentials_required_frames.txt`)

| случай | `result` | размер ответа |
|---|---|---|
| без `credentials` | `credentialsRequired` | 488 Б |
| `credentials` = base64(**UTF-8**) пароля | `registered` | 479 Б |
| `credentials` = base64(**UTF-16LE**) пароля | `credentialsRequired` | 488 Б |
| `credentials` = base64 неверного пароля | `credentialsRequired` | 488 Б |
| `userName` + верный UTF-8 пароль | `registered` | 479 Б |
| `userName` + UTF-16LE пароль | `credentialsRequired` | 488 Б |

Отсюда три факта, которых раньше не было:

1. **`credentials` — это base64 от UTF-8 пароля** (не UTF-16LE, иначе сервер отвечает тем же
   отказом). Вопрос из §3 «как упакованы userName/credentials» закрыт для пароля.
2. **`userName` без `--debugServerUsers` игнорируется**: с ним и без него при верном пароле —
   `registered`. Формат упаковки `userName` остаётся непроверенным (проверять не на чем), в
   клиенте он передаётся как base64 от UTF-8 — по аналогии с паролем, и это помечено в коде.
3. `credentialsRequired` и `fullCredentialsRequired` в `AttachDebugUIResult`
   (`schemas/debugBaseData.xsd:18-33`) имеют **одинаковый комментарий** в схеме: «отсутствует
   или неправильно указан пароль сервера отладки». Второй, судя по `--debugServerUsers`, —
   вариант «нужен ещё и пользователь».

### Чего снять не удалось (и почему)

`fullCredentialsRequired` — нет. Он требует файла списка пользователей, а его формат
`dbgs` не принимает в двух текстовых вариантах: файл из строки `probe` и файл из строки
`probe=<пароль>` оба приводят к немедленному выходу процесса (в `dbgs.exe` есть строка
`IDS_ERROR_CHECKING_USER_LIST`, то есть файл проверяется при старте). Описание формата —
в ITS («Приложение 4. Вспомогательные утилиты»), а он на этом аккаунте отвечает 401. Так что
ветка «пользователь + пароль» остаётся неснятой **осознанно**, а `CREDENTIAL_HINTS` в
`mcp_core` различает оба кода заранее, по тексту схемы.

### Что из этого вышло в клиенте (0.0.6)

`session_start` принимает `user`/`password`, а если их нет — берёт `DBGSRV_USER`/
`DBGSRV_PASSWORD` из окружения сервера (пароль в разговор не попадает). Отказ по учётным
данным — **не исключение, а данные**: `{'attached': false, 'reason': 'credentialsRequired',
'passwordProvided': false, 'hint': …}`, и повторять такую попытку бессмысленно, поэтому
цикл `wait` на этих кодах прерывается сразу (в отличие от `ibInDebug`, где ожидание
осмысленно). Ответ пароля не содержит.

Проверка ядра против того же тестового сервера — `probes/creds_core_check.py`:

```
1. без пароля        → {'attached': False, 'reason': 'credentialsRequired', attempts: 1,
                        passwordProvided: False, userProvided: False, hint: …}
2. пароль в аргументе → {'attached': True, ui: 'e860eda4-…'}      session_stop → 200
3. пароль из DBGSRV_PASSWORD → {'attached': True, ui: 'e8636abc-…'}  session_stop → 200
итог: логика ОК, пароль в ответах — отсутствует
```

## 16. Два канала одного инструмента — это два независимых отладчика (2026-10-16)

После того как рядом оказались `1c-debug` (http) и `1c-debug-stdio`, состоянием нельзя делиться:
сеанс, открытый через один канал, для второго — просто чужой `attachDebugUI`. Замер:

```
stdio:  session_start(demo-base, wait=0) → {"attached": true,  "ui": "e3fabf58-…", "attempts": 1}
http:   session_start(demo-base, wait=0) → {"attached": false, "reason": "ibInDebug",
                                            "attempts": 1, "retryAfterSec": 120, "hint": …}
stdio:  session_stop → {"detached_http": 200}; после этого на обоих каналах sessions: []
```

Три следствия. Первое: база занимает одна пара «`dbgs` + UI», и вторая попытка получает
законный `ibInDebug` — как и должно, но агент увидит это как «база кем-то занята», если не
помнит, что сам открыл сеанс в другом канале. Второе: фоновый сборщик событий живёт в процессе
своего канала, поэтому `wait_stop` из http никогда не увидит останов, случись он по точке,
поставленной через stdio. Третье: в `dbgs` это выглядит как два разных `idOfDebuggerUI`, и
оба надо снимать — незакрытый UI любого из них блокирует базу на 90…150 с (§14).

Правило для агента: держать один канал на сеанс. Второй — либо не открывать, либо открывать
осознанно на другую базу.

### Уточнение к §15, снятое на сервисном dbgs: `credentialsRequired` двусторонний

Замер 2026-10-16 (docs/rdbg-protocol-2026-10-09.md §15). `dbgs --service --port=1552`, запущенный
**без** `--password`:

| что прислал UI | `attachDebugUI` |
|---|---|
| `credentials` (тестовый пароль) | `credentialsRequired` |
| ничего | `registered` |

Значит код читается как «учётные данные не совпали», а не как «сервер требует пароль»:
безотказно работает и в обратную сторону — сервер **без** пароля отвергает UI, который пароль
прислал. Практическое следствие для агента: `credentialsRequired` при заведомо безпарольном
`dbgs` — это не «попросят пароль», а «лишний `DBGSRV_PASSWORD` в окружении сервера»; в 0.0.7
подсказка и описание `session_start` переписаны под обе стороны, в ответе есть `passwordProvided`
/ `userProvided`, по которым это видно не выходя из вызова.

Там же: `attachDebugUI` с пустым `infoBaseAlias` возвращает ответ **без** элемента `result` (ни
`registered`, ни отказа) — пустой алиас использовать нельзя, проверять `result is None`.

---

## 17. Безголовый вход: цель от HTTP-вызова, останов по RTE и версия модуля из кадра (2026-10-17)

Ночь, когда упало главное ограничение проекта. Всё ниже замерено живьём на `demo-base`
(`evidence/headless_bp_from_oracle.txt`, `evidence/headless_acceptance_0_0_8.txt`,
`evidence/job_target_watch_raw.txt`, `evidence/http_target_watch.txt`).

### 17.1 Ключ `/DEBUG` для появления цели не нужен

В 00:28 на базе сидели два сеанса: один запущен с `/DEBUG /DebuggerURL=http://127.0.0.1:1550`,
второй — обычный тонкий клиент без ключей. В снимке `getDbgTargets` при этом:

```
seanceNo=1  targetType=Server   (с /DEBUG)
seanceNo=10 targetType=Server   (без /DEBUG)
seanceNo=11 targetType=JOB      (через ~6 с, его никто не запускал)
```

То есть регистрация цели — свойство **сеанса сервера**, а не ключа запуска; `/DEBUG` нужен был
только для того, чтобы сам клиент позвонил отладчику (что, как установлено 2026-10-16, он и так
не делает). Утверждение §7 «предметов отладки нет: запускай сеанс с /DEBUG» в ядре исправлено.

### 17.2 Сеанс из HTTP-запроса тоже становится целью, и тип его `WEBService`

Публикация базы: `/ws/` отвечает (веб-сервисы), `/hs/` и `/odata/` — 404 (не опубликованы),
`/app` — 404 (веб-клиент не опубликован). SOAP `POST /demo-base/ws/EnterpriseDataExchange_1_0_1_1`
даёт в снимке цель `targetType=WEBService` (`seanceNo` 31 и 34 в двух прогонах) — процесса
клиента на этой машине нет вообще. UI по такому сеансу получает `targetStarted` и `targetQuit`;
цель живёт секунды, поэтому вручную через `attachDetachDbgTargets` к ней не успеть.

Практическое следствие для маршрутизации: у этих целей в снимке **нет `state`** (`state=None`),
так что прежнее правило «выбрать приостановленную» не работает, а `eval`/`locals`, отправленные
не в ту цель, отвечают пустым (`{'state': None, ...}`) без ошибки. Ядро теперь выбирает так:
цель из последнего останова (по `targetIDStr`) > приостановленная > с наибольшим `seanceNo`.

### 17.3 `setBreakOnRTE` — останов без точки и без версии

Команды `setBreakOnRTE` / `getBreakOnRTE` (тип запроса `RDBGSetRunTimeErrorProcessingRequest`,
тело — `state` из `debugRTEFilter.xsd`: `stopOnErrors`, `analyzeErrorStr`, `strTemplate*`)
принимаются и читаются обратно:

```
setBreakOnRTE(stop) -> HTTP 200
getBreakOnRTE       -> 200, <stopOnErrors>true</stopOnErrors><analyzeErrorStr>false</analyzeErrorStr>
```

Останов приходит как обычный `callStackFormed` с кадром места падения. Это обходит стену §4: версия
модуля для такого останова не нужна вовсе.

Триггер обязан давать именно ошибку языка, а не «вежливый» ответ:
`CustomerOrdersExchange.GetCustomers` с незарегистрированным устройством возвращает
`Success=false` и текстом «Синхронизация с устройством не настроена» — кода BSL-исключения нет,
останова нет (проверено). А `EnterpriseDataExchange.TestConnection` с планом обмена, которого нет,
падает по-настоящему: `{WebСервис.EnterpriseDataExchange_1_0_1_1.Модуль(40)}: Поле объекта не
обнаружено (ПланаТакогоНет)`.

### 17.4 Оракул версии: `version` приезжает в кадре останова

Все способы достать `version` модуля для `bpWorkspace`, перепробованные до этого, оказались
негодны: это не хеш текста модуля (`probes/module_version_hash.py`: sha1/ripemd160 × 8 видов
нормализации × 2 кодировки = 48 комбинаций, 0 совпадений), не `configVersion` из
`ConfigDumpInfo.xml` (расходится даже для модуля, где точка в тот же день сработала), и
`correctedBP` платформа не присылает (`probes/bp_corrected_oracle.py`: 90 с long-poll, 0 кадров,
в том числе на заведомо неверной версии).

Версия лежит в кадре: у `<callStack>` есть `<moduleID>` с `objectID`/`propertyID`/`version`
(+`type`/`extensionName`), и `callStackFormed` отдаёт её по приостановленной цели. Наш парсер
её не видел, потому что `text()` смотрит только прямых детей, а эти поля вложены в `moduleID` —
исправлено (там же и `type` читался под неверным именем).

Живое подтверждение того, что это рабочий ключ, а не echo:

```
фаза 1: stopOnErrors + SOAP -> останов, кадр:
  module =cb3a5c5b-7bdc-4e12-96f1-11b1213b6853
  property=d5963243-262e-4398-b4d7-fb16d06484f6
  version =13fa4019b2145c489f85990c337a846a00000000  line=40
фаза 2: stopOnErrors ВЫКЛЮЧЕН, breakpoints_set(те же id, строка 37) -> повторный SOAP
  -> останов на строке 37, locals и eval в этом кадре работают
```

Во второй фазе RTE не вооружён, значит остановлен процесс точкой, координаты которой агент
взял сам. Граница метода: оракул даёт версию только модуля, который ХОТЬ РАЗ остановился
(RTE, чужая точка из профиля, исключение в нём). Холодный модуль так не вскрывается — но
«первый останов по ошибке, дальше точки» теперь полностью безлюден.

### 17.5 Константы `propertyID` видов модулей

`objectID` берётся из `ConfigDumpInfo.xml` живой выгрузки (145 225 записей, там есть и сами
модули: `Document.ЗаказКлиента.ObjectModule`), `propertyID` — константа вида модуля:

| вид модуля | propertyID |
|---|---|
| модуль формы | `32e087ab-1491-49b6-aba7-43571b41ac2b` |
| модуль объекта | `a637f77f-3840-441d-a1c3-699c8c5cb7e0` |
| модуль менеджера | `d1b64a2c-8078-4982-8190-8f81aefda192` |
| единственный модуль объекта: `CommonModule`, `WebService`, `HttpService` | `d5963243-262e-4398-b4d7-fb16d06484f6` |

Первые три выведены из пяти записей профиля (`probes/property_id_table.py`), четвёртая — из
кадра §17.4 и подтверждена 2026-10-17 на общем модуле: кадр `ОбщийМодуль.МобильноеПриложение
ЗаказыКлиентов.Модуль` принёс тот же `d5963243…`, что и кадр веб-сервиса — то есть это константа
свойства «Модуль», общего для всех одно-модульных объектов. Индекс после точки в
`ConfigDumpInfo.xml` (`.0`, `.2`, `.3`) между типами объектов не совпадает, поэтому резолвер
(`qoder-1c-debug/server/md_index.py`) ключуется по ИМЕНИ узла, а не по индексу. `BSLModuleIdUser` (человеческие `MDObject`/`MDProperty` строками) на проводе не
используется: `RDBGSetBreakpointsRequest` принимает только `BPWorkspaceInternal`.

### 17.6 То же через инструменты установленного плагина (2026-10-17, 0.0.8)

Полный след — `evidence/acceptance_0_0_8_via_plugin_mcp.txt`. Агент ничего не импортирует, только
вызывает инструменты; триггер — внешний SOAP-запрос. Цикл: `session_start` →
`auto_attach_targets` → `stop_on_error(on)` → SOAP → `wait_stop` (строка 40, кадр даёт
`module/property/version`) → `eval`/`locals` → `Continue` → `stop_on_error(off)` →
`breakpoints_set` со снятой тройкой на строку 37 → SOAP → `wait_stop` (строка 37,
`stopByBP=true`) → `Step` → `wait_stop` (`stopByBP=false`, кадр уже в другом модуле:
`МодульСеанса.УстановкаПараметровСеанса(16)`) → `locals` → `Continue` → очистка.

Что это добавило к спецификации:

* **`stopByBP` различает останов по точке и останов по шагу**: точка — `true`, шаг — `false`.
  прежнее наблюдение (§5: «на шаге тоже true») относилось к шагу внутри останова по точке; здесь
  шаг из останова, поднятого точкой, дал `false`.
* **Шаг со строки, где уже летит исключение, исполняет её снова** и роняет сеанс: на останове
  по RTE нельзя «перешагнуть» ошибку шагом, надо либо `Continue`, либо ставить точку раньше.
* **Два вычисления на одном UI одновременно ломают чтение**: отправленные одним блоком `eval`
  и `locals` дали `{"state":"correctly"}` с пустым списком переменных — событие утаскивает не
  тот, кто ждёт. По одному вызову всё на месте. С 0.0.9 ядро сериализует
  `eval`/`locals`/`set_variable` локом на сеанс.
* Ещё один `propertyID` снят с живого кадра: `9b7bbbae-9771-46f2-9e4d-2489e0ffc702` у модуля
  сеанса (`МодульСеанса`, `objectID=61ee2494-c14a-4992-8c93-8e78b20bea27`).
* id цели в снимке непостоян между командами (`2f18e31a` на шаге, `5defb71b` на `Continue` при
  том же сеансе) — ориентироваться на `seance_no`, а на `id` только в пределах одной команды.

### 17.7 `version` точка останова не проверяет: холодный модуль берётся из XML-исходников

Замер 2026-10-17 02:0x, только MCP-инструменты, `evidence/cold_module_breakpoint.txt`.

Точка с **обнулённым** `version` (сорок нулей) останавливает код:

* в модуле, чью настоящую версию мы знали (`WebСервис.EnterpriseDataExchange_1_0_1_1`,
  `objectID=cb3a5c5b…`, `propertyID=d5963243…`) — останов на строке 37, `stopByBP=true`;
* в модуле, который агент **никогда не видел** и который никогда не останавливался:
  `WebService.CustomerOrdersExchange` взят из `ConfigDumpInfo.xml`
  (`objectID=c0aa0d5d-598d-474f-b169-5b289e06a605`), `propertyID` — та же константа модуля
  веб-сервиса, `version` — сорок нулей, `line=145`. Вызов `GetCustomers(MobileDeviceID =
  "qoder-probe")` встал ровно там, `locals` отдал четыре параметра метода, `Continue` — и бизнес-
  вызов штатно завершился своим 200.

Выводы, отменяющие прежние:

* §4 и §17.4 («агент не может вывести `propertyID` и `version`, берёт их из профиля
  конфигуратора») для **установки** точки больше не стена: платформе достаточно
  `objectID` + `propertyID` + номера строки. Оракул из кадра останова остаётся полезным, но не
  обязательным.
* Версия, которую платформа показала в кадре этого холодного модуля, —
  `dfee976ef332ab44aa00026cb90fd34800000000` — это в точности `configVersion` того же объекта из
  `ConfigDumpInfo.xml`. Значит прежняя проверка «`configVersion` ≠ версия модуля» опиралась на
  `.pfl`, записанный под **старой** ревизией конфигурации, и была неверной как вывод: для
  актуальной выгрузки `configVersion` совпадает.
* Обратная сторона: раз версия не сверяется, точка привязана к **номеру строки**. После
  обновления конфигурации строки съезжают, и старая точка молча начнёт останавливать другое
  место. Правило для агента: перед прогоном переснять исходники (или сверить `configVersion`
  цели из `getDbgTargets` с `ConfigDumpInfo.xml`).

Попутно про `evalLocalVariables`: после останова ПЕРВЫЙ запрос отвечает пустотой (`correctly` без
строк), второй — полным списком. 0.0.10 повторял моментально внутри того же лога и не помог
(замер: снова пусто); помогла пауза ~1 с перед повтором — с 0.0.11 `locals` так и делает, и один
вызов инструмента отдаёт все четыре параметра.


### 17.8 Точка по имени модуля (0.0.12, 2026-10-17)

Собрал `md_index.py`: `breakpoints_set` принимает `modules: [{name, lines}]` и `configPath`
(каталог выгрузки или путь к `ConfigDumpInfo.xml`, по умолчанию — `V8_CONFIG_SRC` из окружения).
Имя узла в дампе → `objectID`, вид модуля → `propertyID` из таблицы §17.5, `version` пишется
нулями (§17.7). Поддержаны `CommonModule.Х`, `WebService.Х`, `HttpService.Х`,
`Документ.Х.ObjectModule`, `Документ.Х.ManagerModule`, `Х.Form.Форма`; `RecordSetModule`/
`ValueManagerModule` пока требуют явного `propertyID` — констант нет.

Живая проверка: точка `{name: "CommonModule.МобильноеПриложениеЗаказыКлиентов", lines: [71]}`
→ SOAP `GetCustomers` → останов на строке 71, кадр `a7f21201-b234-4b3b-b676-9ad813e3d816` — тот же
guid, что отдал резолвер по дампу. След: `evidence/named_breakpoint_0_0_12.txt`.

Ещё один порядок, снявший вопрос §6: **кадры в `callStackFormed` идут от вызывающего к текущему** —
текущий кадр ПОСЛЕДНИЙ. Проверено дважды: после останова на строке 71 кадр [0] был вызывающий
(`WebСервис…GetCustomers(145)`), кадр [1] — уже остановленный общий модуль, и `locals` показал именно
параметры последнего (`ИдентификаторМобильногоУстройства`, `ВсеКлиенты`, `УникальныйИдентификатор`,
`АдресДанных` + локальные `СтруктураОтвета`, `УзелОбмена`, `СообщениеОбмена`, `Отказ`).

### 17.9 Почему константы propertyID нельзя взять из поставки (негатив 2026-10-17)

Казалось бы: `backbas.dll` показывает рядом `[16 байт GUID][имя свойства UTF-16]` — в одном месте
(`+0x6593a8`) перед именем и правда лежал известный `a637f77f…`. Проверил систему целиком
(`probes/extract_property_table.py`, 1501 пара имя->чанк): соседство НЕ является таблицей. Перед
`RecordSetModule` лежит `0065004d-0074-0068-6f00-640073000000`, что есть не GUID, а кусок строки
«Methodso», перед `ValueManagerModule` — `…Иачтc` и т.п. Текстовых форм GUID (`a637f77f-…`,
`{A637F77F-…}`, UTF-16) во всём `bin` нет вовсе (`probes/scan_property_guids.py`: 0 вхождений в
ASCII/UTF-16, 85 вхождений сырыми байтами в 16-битных представлениях — без привязки к именам).

Практический вывод не меняется: константу вида модуля надо снимать с **кадра останова**
(§17.4/§17.8) — это дёшево и надёжно, а обратная разработка дескрипторов свойств платформы
стоит дороже, чем редкие `RecordSetModule`/`ValueManagerModule`. Пока этих двух констант нет,
`md_index.resolve` для них отдаёт `objectID` и требует `propertyID` явно.

### 17.11 Фоновое задание по требованию: пассивно не ждём, зовём инициатор (2026-10-17, #33)

Дорога A (ждать, пока кластер сам запустит задание) — тупик: 8 минут наблюдения с UI и
авто-присоединением `JOB` в пустой базе — ноль целей (`evidence/job_target_watch_long.txt`).
Виденная ранее цель `JOB` рождалась сеансом клиента через ~6 с после входа, а не расписанием.

Дорога B работает: web-сервис `EnterpriseDataExchange_1_0_1_1` в функции
`ПодготовитьДанныеКПолучению` (`WebServices/…/Ext/Module.bsl:131`) вызывает
`ДлительныеОперации.ВыполнитьВФоне("ОбменДаннымиСлужебный.ПодготовитьДанныеДляВыгрузки…")`,
то есть один SOAP-POST заводит настоящее фоновое задание. Точка, заданная именем
(`breakpoints_set` c `modules=[{name: "CommonModule.ОбменДаннымиСлужебный", lines: [459]}]`),
остановила именно JOB-цель (сеанс 3; рядом висела WEBService-цель сеанса 1), `locals` отдал
19 переменных, `eval` — `ПараметрыПроцедуры.ПараметрыWEBСервиса.ИмяПланаОбмена = "ОбменССайтом"`.
Стек задания заодно показал путь диспетчеризации: `ДлительныеОперации.ВыполнитьСКонтекстомКлиента`
→ `ВызватьПроцедуру` → `ОбщегоНазначения.ВыполнитьМетодКонфигурации` → безымянная обёртка
(кадр с пустым `moduleID`) → метод. Полный след: `evidence/job_breakpoint_20261017.txt`.

Ещё про UI: **две отладочные панели на одной базе живут одновременно** (наблюдатель держал свой
UI, второй подключился и получил `registered`); блокирует новые подключения не второй UI, а
**висячий** — после убийства процесса наблюдателя третий `attachDebugUI` получил `ibInDebug`
(снимается само, §14). Практически: завершать сеанс всегда `session_stop`, а не `taskkill`.
