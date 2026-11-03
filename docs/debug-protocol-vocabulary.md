# Словарь протокола отладки 8.5: что извлечено из бинарников и как

> Сырые выгрузки строк и дампы замеров (`evidence/…`) в публичную версию не входят;
> имена файлов оставлены как ссылки на рабочий журнал.

Отвечает на законный вопрос: **«как ты получил словарь команд, если XSD нет в DLL?»**

Потому что это два разных объекта поиска, и они дают разное:

| Что искали | Чем | Итог |
|---|---|---|
| **Тексты XSD-схем** (структура сообщений) | `probes/xsd_dump.py` — поиск блоков `<?xml …</xsd:schema>` в `debug.dll`, `dbgtgsrv.dll`, `dbgtgt.dll`, `dbgbase.dll` | **0 схем.** XDTO-модель в 1С компилируется в бинарный формат, XML-текстом не лежит |
| **Имена** (идентификаторы команд, типов, пространств имён) | `probes/dbg_vocab2.py`, `verb_context.py`, `command_table.py`, `namespace_scan.py` — разбор **печатных последовательностей UTF-16LE** (`(?:[\x20-\x7e]\x00){3,}`) и ASCII | Имена есть, и их много. Их DLL обязана держать строками: XDTO-тип и команду адресуют по имени |

Первая попытка (`probes/dbg_vocab.py`) смотрела **только ASCII** и дала `verbs=0` на всех
четырёх DLL (`evidence/dbg_vocab.txt`) — имена хранятся в UTF-16. Это и есть объяснение,
почему «нет XSD» ≠ «нет словаря».

Доказательство, что это таблица, а не случайные строки: `probes/verb_context.py`
(`evidence/verb_context.txt`) показывает, что имена лежат **континуальным блоком с шагом
~24 байта** — `0x86f20 pingDBGTGT`, `0x86f38 stopDBGTGT`, `0x86f50 rtgt`,
`0x86f60 startDBGTGT`, … — то есть таблица регистрации/диспетчера.

Сырые дампы: `evidence/command_table.txt`, `evidence/xdto_namespaces.txt`,
`evidence/verb_context.txt` (в публичную версию не входят).

## 1. Пространства имён XDTO (наблюдено дословно)

Все — `http://v8.1c.ru/8.3/debugger/…`, из `dbgtgt.dll` / `dbgtgsrv.dll` / `dbgbase.dll`:

```
dbgtgtCommands      dbgtgtData          dbgtgtBP          dbgtgtErrorInfo
dbgtgtRequestResponse                 dbgtgtRemoteRequestResponse
debugArea           debugAutoAttach   debugBaseData     debugBreakpoints
debugCalculations   debugDBGUICommands debugForegroundData debugMeasure
debugRDBGRequestResponse              debugRTEFilter    debugRTEInfo
```

Плюс сопутствующие: `http://v8.1c.ru/8.2/data/bsl`, `http://v8.1c.ru/8.2/bsl`,
`http://v8.1c.ru/8.1/data/core`, `http://v8.1c.ru/v8/debugcfg`.

Корень `http://v8.1c.ru/8.3/debugger/` — то, что должно стоять в `xmlns` тела запроса.
Какой именно из пакетов — **гадание**: имена пакетов известно, но какой из них несёт
обёртку команды — пока нет.

## 2. Имена типов запросов/ответов (наблюдено)

Из таблицы в `dbgtgsrv.dll` и `dbgtgt.dll` — это готовые имена корневых элементов:

```
DBGTGTRemoteCallDebuggerRequestType            DBGTGTRemoteCallDebuggerResponseType
DBGTGTRemoteCallDebuggerModifyValueRequestType
DBGTGTRemoteCallDebuggerMeasureServerTimeRequestType
DBGTGTRemoteCallDebuggerMeasureResultsRequestType
DBGTGTRemoteCallDebuggerEvalProcessedRequestType
DBGTGTRemoteCallDebuggerEvalStartStopProcessedRequestType
DBGTGTRemoteCallDebuggerData
DBGTGTRemoteRegisterTargetRequestType          DBGTGTRemoteRegisterTargetResponseType
DBGTGTRemoteUnregisterTargetRequestType
DBGTGTRemoteIsUpdateIBProcessingRequestType
DBGTGTRemoteGetUserRestrictionsRequestType     DBGTGTRemoteGetUserRestrictionsResponseType
DBGTGTRemoteGetIDOfDebuggerUIRequestType       DBGTGTRemoteGetIDOfDebuggerUIResponseType
DBGTGTRemoteGetDbgForegroundWndRequestType     DBGTGTRemoteGetDbgForegroundWndResponseType
DBGTGTRemoteCallDSInfoRequestType              DBGTGTRemoteCallDSInfoResponseType
DBGTGTRemoteCallDSInfoItem
DBGTGTRemoteCallSMORequestType                 DBGTGTRemoteCallRCTERequestType
DBGTGTRemotePingRequest                        DBGTGTRemotePingResponse
DBGTGTZoneInfo
```

`…CallSMORequestType` / `…CallRCTERequestType` — обращений к SMO и к «RCTE»; их
расшифровка не проверялась.

## 3. Имена действий и структур данных (наблюдено)

Короткие имена из `dbgtgt.dll` (похоже на значения перечислений/команд внутри конверта):

```
EvalExpr   evalExpr   BPEvalExpr   BPMessageEval   ModifyValue   valModified
Continue   Terminate  Restart      ReCall          step          stopOnDebugger
NextLineResult        NextLineResultHTTP           Unknown
CallStackItemInfo     ParameterInfo  ParametersInfo  DebugDataSeparatorInfo
```

Глагольные команды (`dbgtgsrv.dll`, сторона сервера; `debug.dll`, сторона конфигуратора):

```
getDbgTargets   getDbgTargetState   getDbgAllTargetStates   attachDetachDbgTargets
terminateDbgTarget   restartDbgTarget
setBreakpoints   getBreakpoints   getBreakpointsCorrected
setBreakOnNextStatement   clearBreakOnNextStatement   setBreakOnRTE   getBreakOnRTE
evalExpr   evalExprStartStop   evalLocalVariables   modifyValue   step
getCallStack   setInaccessibleModules   getInaccessibleModules
setListOfDebugArea   getListOfDebugArea   setAutoAttachSettings   getAutoAttachSettings
attachDebugUI   detachDebugUI   pingDebugUI   pingDebugUIParams   idOfDebuggerUI
initSettings   getUserRestrictions   getDbgForegroundWnd   getDebugID   getRDbgAPIVer
startDBGTGT   stopDBGTGT   pingDBGTGT   rtgt   dsInfo   showMetadataObject
startUpdateIB   finishUpdateIB   getUpdateIBProcessing
setForegroundHelper   applyForegroundHelper   requestForegroundHelper
setMeasureMode   measureServerTime   measureRes   endErrorViewInfos
register   unregister   shootdown   notifyOnFinishSeance   stopOnDebugger
```

`shootdown`, `notifyOnFinishSeance`, `str`, `cmd`, `Area`, `Command` — без контекста;
могут быть и служебными, не только командами.

## 4. Маршруты виртуальных ресурсов (наблюдено + вывод)

Наблюдаемые строки-имена ресурсов: `/DEBUGTARGET`, `/dbgtgtCommands.xsd`,
`/dbgtgtBP.xsd`, `/dbgtgtData.xsd`, `/dbgtgtErrorInfo.xsd`,
`/dbgtgtRemoteRequestResponse.xsd`, `/dbgtgtRequestResponse.xsd`, `/model.xdto`
(`dbgtgt.dll`); `/debug*.xsd` (`dbgbase.dll`); `/DEBUG`, `/DEBUGGERURL`
(`debug.dll`).

И — самое говорящее — имена маршрутов в `dbgtgt.dll`:

```
debugTarget_remoteDebuggerRunTimeRegisterDebugTarget
debugTarget_remoteDebuggerRunTimeEvalExpr
debugTarget_remoteDebuggerRunTimeGetIDOfDebuggerUI
debugTarget_remoteDebuggerRunTimeStopOnDebugger
debugTarget_remoteDebuggerRunTimeStopOnDebugger_onNextLine
debugTarget_remoteDebuggerRunTimeStopOnDebugger_onNextLineEx_1 … _5
debugTarget_remoteDebuggerRunTimeStopOnDebugger_reCall
debugTarget_remoteDebuggerRunTimeValueModified
```

Схема `<область>_<сервис><метод>` почти наверняка отражает, как 1C регистрирует
виртуальный ресурс. Рядом в той же таблице лежат короткие сегменты `e1csys`, `e1crdbg`,
`rdbg`, `cmd`, `dbgui`, `rtgt`, `str` — кандидаты на часть URL. Это **вывод**, а не
наблюдение: проверять перебором (`probes/route_brute.py` → `evidence/route_brute.txt`).

## 5. Что DLLsays о самой архитектуре (наблюдено: пути исходников сборки)

`dbgtgsrv.dll` и `debug.dll` содержат пути к своим `.cpp` — побочный продукт сборки на
Jenkins (`D:\Jenkins\ci_builder\WindowsBuild2_HJZX7XY8S0UP\Platform\src\…`). Из имён
файлов следует:

| Исходник | Что означает |
|---|---|
| `dbgtgsrv/src/IDebuggerHTTPServiceImpl.cpp` | HTTP-реализация сервиса отладки |
| `dbgtgsrv/src/RemoteDebuggerIDEVResourceServerImpl.cpp` | сервер отладки = **виртуальный ресурс** (VRS) |
| `dbgtgsrv/src/RemoteDebuggerRunTimeVResourceServerImpl.cpp` | отдельный VRS для runtime-команд |
| `dbgtgsrv/src/RemoteDebuggerRunTimePingVResourceServerImpl.cpp` | отдельный VRS для ping |
| `dbgtgsrv/src/IClusterDefaultDebuggerServiceImpl.cpp` | cluster default debugger |
| `debug/src/DebuggerEngineHTTP.cpp` и `DebuggerEngineTCP.cpp` | **два транспорта**: HTTP и TCP |
| `debug/src/DebuggerCommandTargetIDebugTargetsHTTP.cpp`, `…IDebugBrkptMngrHTTP.cpp`, `…IDebugCallStackMngrHTTP.cpp`, `…IDebugCalculationMngrHTTP.cpp`, `…IDebugRTEProcMngrHTTP.cpp`, `…IDebugInacessibleModuleMngrHTTP.cpp`, `…IDebugForegroundMngrHTTP.cpp` | по HTTP-обработчику на каждый менеджер: цели, брейкпоинты, стек, вычисления, RTE, недоступные модули, foreground |
| `dbgtgt/src/IDebuggerTCPImpl.cpp`, `IDefaultDebuggerServiceTCPImpl.cpp`, `DebuggerConnectionMap.cpp` | сторона отлаживаемого процесса говорит по **TCP** |
| `debug/src/DebuggerServerPingConnection.cpp` | пинг сервера отладки отдельным соединением |

Отсюда следует важная для проектирования вещь: **TCP-транспорт (`DebuggerEngineTCP`)
может быть проще, чем выдумывать HTTP-конверт**, потому что он же используется для
`IDebuggerTCPImpl`. Какой порт его слушает — на этой машине не наблюдалось; `dbgs.exe`
известен только как HTTP на 1550.

Файлы конфигурации/реестра, которые всплыли рядом: `debug/debuggerSettingsDirectly`,
`debug/debuggerType`, `debug/debuggerTypeTmp` — это имена параметров настроек отладки.

## 6. Границы применимости

- Всё выше — **имена**, а не формат. Ни порядок полей, ни обязательность атрибутов, ни
  кодировку envelope (git-совместимый XDTO XML в UTF-8 или UTF-16) строки не дают.
- Регулярки по строкам дают и ложные срабатывания: часть имён может относиться не к
  wire-протоколу, а к внутренним вызовам/перечислениям UI.
- `dbgbase.dll` не содержит ни одного имени команды из списка якорей (`anchor_hits=0` в
  `evidence/command_table.txt`) — там только XSD-имена и типы данных.
- Единственный способ превратить этот словарь в рабочий клиент — **одна запись живого
  трафика** конфигуратор↔`dbgs` (`probes/capture_proxy.py`) или удача в переборе
  маршрутов.
