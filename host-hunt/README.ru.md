# PHP2Shell: локальный поиск следов

[English guide](README.md)

Раздел `host-hunt/` дополняет [правила Sigma](../sigma/php2shell_http_exploit_attempt.yml)
проверкой файлов, оставшихся на сервере. Источники IOC проверены 28 октября 2026 года.

## Назначение

Sigma анализирует собранные события. Этот набор читает существующие файлы:
webroot, файловые PHP-сессии, выбранные временные каталоги и сохранённые тела
HTTP-запросов. Он не запускает PHP, не десериализует сессии, не делает сетевых
запросов и не исправляет/удаляет найденное. Чтение живой файловой системы может
изменить atime; для сохранения состояния предпочтительна копия или snapshot.

Ни один отрицательный результат не означает «сервер не был взломан».
Обработка запроса может не оставить файлов; upload-progress cleanup удаляет
свои данные; удалённые файлы, память процессов и внешние session backends этим
инструментом не покрываются.

## Состав

- `php2shell_hosthunt.yar`: 7 оригинальных YARA-правил с классами свидетельств.
- `hosthunt.py`: обход явно указанных каталогов, JSONL с метаданными и SHA-256.
- `iocs.json`: 2 точных хеша, датированные сетевые признаки, пути и PoC-маркеры
  с источником и ролью. Сетевые признаки предназначены для поиска в телеметрии;
  runner автоматически не ищет IP/домены во всех файлах.
- `test_hosthunt.py`: 25 локальных регрессионных тестов; фикстуры — данные,
  PHP-код не выполняется.
- `validation.json`: результат проверки и её пределы.

## Что означают правила

| Правило | Где применяется | Значение находки |
|---|---|---|
| `Associated_Malware_Exact_SHA256` | Любой заданный scope | Точное совпадение опубликованного loader/ELF; не атрибуция способа проникновения |
| `PublicPoC_8512_Named_Shell` | web/artifact | Имя `p2s_8512_shell.php` вместе с характерным PHP-вызовом; проверить назначение файла |
| `PublicPoC_Session_Webshell` | session/web | Два маркера другого session-backed PoC и PHP execution function |
| `Session_UploadProgress_PHP` | session | PHP-текст в данных с default upload-progress prefix; сохранённый ввод, не доказательство исполнения |
| `Session_Progress_ObjectSeed` | session | Объектный seed в progress key; обычные `key|a:` и `key|O:` не являются самостоятельными IOC |
| `PHP_Direct_Request_Execution_Heuristic` | web/artifact | Прямая передача request variable в execution function; общая PHP-эвристика |
| `Captured_Integer_Key_Sequence` | capture | Близкая последовательность трёх integer keys, по мотивам Corelight SID3000653 |

Короткие имена в таблице соответствуют суффиксам rule IDs. Полные имена и
источники находятся в YARA metadata. Public PoC, документация, примеры кода,
административные инструменты и авторизованные проверки могут давать совпадения.
Маркер теста не является автоматическим исключением.

## Быстрый запуск

Python 3.10+; проверено с Python 3.12 и yara-python 4.5.4.
Установка зависимости нужна на машине анализа; содержимое проверяемого сервера
можно подключить как snapshot. Команды ниже выполняются из корня репозитория:

```bash
cd host-hunt
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python -m unittest -v test_hosthunt

.venv/bin/python hosthunt.py \
  --webroot /mnt/server/var/www/html \
  --session-dir /mnt/server/var/lib/php/sessions \
  --artifact-dir /mnt/server/tmp \
  --artifact-dir /mnt/server/var/tmp \
  > findings.jsonl
```

Все пути в примере следует заменить на существующие пути исследуемого instance.
Каталог анализа, тестовые фикстуры и отчёты следует хранить вне проверяемых каталогов.
Один аргумент можно повторять. `--session-dir` проверяет только имена `sess_*`
включая вложенные каталоги. Используйте фактические `session.save_handler` и
`session.save_path` web SAPI/FPM pool; вывод CLI может отличаться. Для Redis/
Memcached этот scope ничего не говорит о данных backend. Подкаталоги из
`N;MODE;/path` учитывать; само значение с `;` не является именем каталога.

Для захваченных запросов: один декодированный HTTP body на файл, без chunked
framing и архивной упаковки. Это не HTTP/PCAP-парсер; он не декодирует URL,
JSON escapes, gzip или TCP streams. Следующая команда выполняется из `host-hunt/`:

```bash
.venv/bin/python hosthunt.py \
  --capture-dir /mnt/evidence/decoded-http-bodies \
  --max-bytes 67108864 > capture-findings.jsonl
```

Default cap — 8 MiB на файл, максимум 64 MiB. Крупные, меняющиеся при чтении,
архивные, недоступные файлы, специальные файлы и symlinks отмечаются как
пропущенные. Пропуски и пустые корни отражаются в `incomplete`.
Symlinks не обходятся; нужный resolved target нужно указать отдельно.
Снимок не гарантируется при проверке живой, меняющейся системы.

В YARA нет встроенной переменной имени файла. Runner передаёт `filename` и
`scope` для каждого файла. Одно `yara -r -d filename=...` не заменяет это.
Файл правил требует объявления этих externals; используйте runner.

## Результаты и коды возврата

JSONL содержит записи `start`, `finding`, `skip/error/coverage`, `summary`.
Находка включает путь, размер, mtime, SHA-256, rule IDs и metadata; совпавшие
байты сессии и токены пользователей не выводятся.

| Exit | Значение |
|---|---|
| 1 | Есть совпадения; проверить также `incomplete` |
| 2 | Совпадений нет, но проверка неполная/ошибка |
| 0 | `NO_MATCH_IN_SCANNED_SCOPE`: совпадений в прочитанном объёме нет |

`incomplete=false` описывает только явно выбранные корни, ограничения размера
и scope. Это не утверждение о полноте образа сервера или всех источников данных.

## Можно начать с grep

Широкие кандидаты в PHP-сессиях; выводятся только имена файлов:

```bash
rg -a -i -l --hidden --no-ignore -g 'sess_*' \
  '<\?(php|=)' /mnt/server/var/lib/php/sessions
```

Подозрительные автоподключения: сравнить с утверждённой конфигурацией, поскольку
`auto_prepend_file` и `auto_append_file` бывают легитимными:

```bash
rg -n --hidden --no-ignore -g '.user.ini' -g '.htaccess' \
  'auto_(prepend|append)_file' /mnt/server/var/www/html
```

Исторические access/error logs, включая gzip при установленном декомпрессоре:

```bash
rg -z -n -i \
  'p2s_8512_shell\.php|(/|%2f)sess_|Session object destruction failed|Failed to decode session object|Allowed memory size.*exhausted' \
  /mnt/server/var/log/nginx /mnt/server/var/log/apache2
```

Отдельно — поиск payload/C2 в DNS, proxy, firewall и process-commandline logs:

```bash
rg -z -n -F \
  -e '92.118.112.100' -e 'thunder.godofthunder.st' -e '134.199.154.64' \
  /mnt/evidence/network-logs
```

Это первичный текстовый поиск, не нормализующий парсер. Совпадение IP как части
строки, request parameter или поля forwarded header нужно проверить в исходном
событии. В обычном nginx combined access log нет POST body, response body и
Cookie: absence строк `PHP_SESSION_UPLOAD_PROGRESS`/`SHELL_ALIVE` там не даёт
отрицательного вывода. Нужны сохранённые WAF/HTTP данные или соответствующая
телеметрия. Не включайте без разбора запись всех тел production-трафика.

## Источники и границы атрибуции

1. [cowrAI, опубликовано 22 Oct, уточнение 26 Oct](https://cowrai.com/research/php2shell-godofthunder/):
   два хеша, delivery/C2. Сенсоры эмулируют PHP; бот отдельно исследован в sandbox.
   Это известные вредоносные образцы, а не доказательство их установки через
   конкретную CVE на произвольном сервере. Список не включает адреса жертв DDoS
   и легитимные публичные Ethereum RPC как признаки злоумышленника.
2. [0x4D31, 24 Oct](https://github.com/0x4D31/honeypot-data/blob/main/reports/php2shell/2026-10-24-confirmed-rce.md):
   35 Apache-parent shell events на трёх намеренно удобных single-worker mod_php
   honeypots. Downloaded second stage не наблюдался. Некоторые финальные запросы
   отсутствовали в завершённых access entries после падения worker. SHA-256
   request bodies из этого отчёта не включены в список malware file hashes.
3. [Rafalohaki, pinned source](https://github.com/rafalohaki/php2shell-poc/tree/6102cff317b4b7ae9188fc8e82f6a4a64e6fd950):
   `p2s_8512_shell.php` — default drop одного PoC; `SHELL_ALIVE` и
   `PAYLOAD_PERSISTED sid=` — другой session-backed PoC. Их нельзя требовать
   одновременно для обнаружения стандартного 8512 drop.
4. [Corelight, pinned source](https://github.com/corelight/php2shell-detect/blob/3b3715aa6ce50b6c2a8b03d2863506645b364b98/suricata/php2shell.rules):
   structural integer sequence; в этом наборе самостоятельное правило для
   сохранённых request bodies, не полный перенос Suricata engine semantics.
5. [PHP session configuration](https://www.php.net/manual/en/session.configuration.php):
   upload progress сохраняет управляемые клиентом значения, default prefix
   `upload_progress_`, cleanup удаляет данные. Prefix может быть изменён;
   два правила session-hunt используют только default prefix.
6. [nginx logging](https://nginx.org/en/docs/http/ngx_http_log_module.html):
   состав combined logs. [Правила Sigma](../sigma/php2shell_http_exploit_attempt.yml)
   требует request-body, PHP error и process-creation telemetry.
7. [MyCERT MA-1490.102026](https://www.mycert.org.my/portal/advisory?id=MA-1490.102026):
   готовые YARA в разделе 4.6 предназначены для exploit-script tooling.
   Наличие такого инструмента на сервере требует контекста; он не обязан
   находиться на жертве при удалённой эксплуатации. Правила MyCERT здесь не копируются.

## Следующий уровень Sigma

Добавлять корреляции только после выбора endpoint collector и field mapping:
web-worker file writes в webroot/uploads, изменения .user.ini/.htaccess,
неожиданный egress, web-worker → shell/interpreter. Связывать с WAF/PHP errors
по host/container/process identity и времени. OOM, HTTP 403 и session decode
warning отдельно не доказывают ни блокировку до PHP, ни успешную эксплуатацию.

## Проверка качества

7 правил скомпилированы без предупреждений в yara-python 4.5.4; 25 тестов прошли.
Есть отрицательные контроли обычных сессий/объектов, положительные синтетические
фикстуры, проверки renamed shell, marker contamination, per-file externals,
ограничения размера, symlink, ошибок доступа, перекрывающихся корней и exit codes.
Exact-hash plumbing проверен подстановкой хеша безопасной фикстуры в копию
правила в памяти. Реальные malware samples не скачивались и не запускались;
частота FP на корпусе реальных приложений не измерялась. Это проверяемый набор
для triage, не утверждение о полном покрытии всех способов эксплуатации.
