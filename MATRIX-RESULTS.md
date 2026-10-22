# php2shell safechecks — матрица совместимости по версиям PHP (реальные прогоны)

Репо: https://github.com/scadastrangelove/php2shell/ (обновлено до `8ce12d1`, фикс `local_mode`)
Стенд: Docker-образы `php:{8.2,8.1,8.0,7.4,7.3,7.2,7.0,5.6}-{apache,cli}` на выделенном тестовом хосте.
Даты прогонов: 2026-10-22 (оба этапа). Все контейнеры после прогонов удалены.

Легенда: ✅ — детект работает и вердикт корректный; ⚠️ — INCONCLUSIVE (нет сигнатуры); ❌ — сломано; ☠️ — найден краш; 🔧 — починено нашим патчем.

## Итоговая матрица (после апстрим-фикса + наших патчей)

| Версия PHP | Remote (`-u`) | Local 109618 (`--php-cgi`) | Local 109619 (`--php-cli`) | Post-patch surface | Nuclei (наш шаблон) |
|---|---|---|---|---|---|
| 8.2.35 (patched) | ✅ PATCHED (w1+w2, w3=0) | — (fix от 8.2.35) | — | — | ✅ info/patched сработал, unpatched молчит |
| 8.1.34 | ✅ VULNERABLE | ✅ AFFECTED (4 формы) | 🔧✅ VULNERABLE | ✅ SURFACE EXPOSED | ✅ high |
| 8.0.30 | ✅ VULNERABLE | ✅ AFFECTED | 🔧✅ VULNERABLE | ✅ SURFACE EXPOSED | ✅ high |
| 7.4.33 | 🔧✅ VULNERABLE* | ⚠️ INCONCLUSIVE (rc=255 silent) | 🔧✅ VULNERABLE | ✅ SURFACE EXPOSED | ✅ high |
| 7.3.33 | 🔧✅ VULNERABLE* | ⚠️ INCONCLUSIVE (rc=255 silent) | 🔧✅ VULNERABLE | ✅ SURFACE EXPOSED | — |
| 7.2.34 | 🔧✅ VULNERABLE* | ⚠️ INCONCLUSIVE (rc=255 silent) | 🔧✅ VULNERABLE | ✅ SURFACE EXPOSED | — |
| 7.0.33 | 🔧✅ VULNERABLE* | ☠️ VULNERABLE (rc=139 SIGSEGV, mpheaders) | 🔧✅ VULNERABLE | ✅ SURFACE EXPOSED | — |
| 5.6.40 | 🔧✅ VULNERABLE* (w2=0, решает w3) | ⚠️ INCONCLUSIVE (rc=255 silent) | 🔧✅ VULNERABLE | ✅ SURFACE EXPOSED | ✅ high |

\* Remote на ≤7.4 работает только если на таргете `display_startup_errors=On` — это RINIT-warning'и,
на 7.x/5.6 без этого флага они в ответ не попадают (фундаментальное ограничение PHP, не скрипта).

## Этап 2 (2026-10-22): что найдено и починено

### Находка 1: 109619 local — ложный SAFE на всех ≤7.4 (критично)
После апстрим-фикса `local_mode` скрипт на 7.4.33 сказал «SAFE: fix present» — **невозможно**, 7.4.33 вышел в 2022, фикса CVE-2026-109619 там нет. Ручная проверка: callback **срабатывает** на ВСЕХ старых версиях (7.4/7.3/7.2/7.0/5.6) — `var_dump` вызывается дважды и печатает `string(8) "SC109619"` **прямо в HTTP-ответ**, до вывода скрипта. Просто на ≤7.4 нет warning'а «hasn't defined the class it was called for» — матчер его ждал и промахивался.
**Патч** (наш, в `safechecks/cyberok_safecheck_cve_2026_109619.py`): дополнительный сигнал — `"SC109619"` (вывод var_dump) в теле ответа → fired=True. После патча: 7.4/7.3/7.2/7.0/5.6 → VULNERABLE ✔. Итог: **109619 уязвимы все ветки 5.6–8.1**, SAFE-вердикта на EOL-версиях быть не должно.

### Находка 2: remote-сигнатуры на 7.x/5.6 отличаются
Полный дифф ответов (apache + `display_startup_errors=On`):
- **8.x**: `Session ID is too long or contains illegal characters. Only the A-Z...` + `Failed to read session data` + `Failed to write session data (`
- **7.4**: `The session id is too long...` (другой регистр и текст!) + w2 + w3
- **5.6**: w1 ×4, **w2 отсутствует вообще**, w3 ×2
Т.е. оригинальный матчер (точный регистр + обязательная w2) не мог сработать ни на одной старой версии, даже когда warning'и в ответе есть.
**Патч** (оба скрипта): w1 case-insensitive (`session id is too long or contains illegal characters`), w3 — решающий, w2 не обязателен. Verdict: w1+w3 → VULNERABLE; w1+w2 без w3 → PATCHED.

### Находка 3: `display_startup_errors` — ключ к remote на старых версиях
Без него (типичный prod) на ≤7.4 в ответе нет НИЧЕГО — ни при illegal SID, ни при write attempt (проверено полным диффом: ответы идентичны valid-SID случаю). С ним — сигнатура есть. Вывод для blackbox: remote-вердикт на ≤7.4 возможен только на таргетах с включённым `display_startup_errors` (dev/staging/кривой prod); иначе честный INCONCLUSIVE, альтернатива — version-based fallback (уже есть в 109618).

### Находка 4: апстримный nuclei-шаблон нерабочий
`nuclei/cyberok_php2shell_detect.yaml` использует `{{randstr(16)}}` — в nuclei v3.6.0 helper `randstr` не принимает аргументов → «unresolved variables», запрос **вообще не отправляется** (0 детектов даже на 8.1). Плюс матчеры case-sensitive и требуют все 3 warning'а → не ловил бы 7.x/5.6 даже после починки.

### Наши nuclei-шаблоны (`nuclei/`)
- `cve-2026-109618-109619-unpatched.yaml` — high: w1 + w3, case-insensitive, path-payloads (`/`, `index.php`, `show_config_errors.php` для phpMyAdmin-случая), экстрактор X-Powered-By.
- `php-session-startup-surface-patched.yaml` — info: w1 + NOT w3 (patched/mitigated; в описании оговорка про 5.6, где w2 не диагностичен).

**Динамическая валидация end-to-end (nuclei v3.6.0, Tamm):**
| Стенд | unpatched-шаблон | patched-шаблон |
|---|---|---|
| PHP 8.2.35 (patched) | молчит ✔ | ✅ info |
| PHP 8.1.34 | ✅ high (PHP/8.1.34) | молчит ✔ |
| PHP 7.4.33 | ✅ high (PHP/7.4.33) | молчит ✔ |
| PHP 5.6.40 | ✅ high (PHP/5.6.40) | молчит ✔ |

## Этап 1: базовая матрица (исторические детали)

### Local 109618 (`--php-cgi`, OOM-формы nested/bigvalue/manyvars/mpheaders)
- **8.1 / 8.0** — все 4 формы → clean memory-fatal → PRE-FIX SIGNAL (AFFECTED).
- **7.4 / 7.3 / 7.2 / 5.6** — все формы → **rc=255 с пустым выводом** → INCONCLUSIVE. Ручная проверка на 7.4: процесс молча умирает (bailout без текста `Allowed memory size`), benign-контроль rc=0. «rc=255 + пустой вывод» на 7.x/5.6 — это и есть pre-fix bailout; скрипт мог бы маппить её в AFFECTED. Калибровочный гэп.
- **7.0** — mpheaders → **rc=139 (SIGSEGV)** → VULNERABLE. Единственный реальный краш.

### Post-patch surface (`--php-cli`)
Все 7 версий (5.6–8.1): **SURFACE EXPOSED** — form-SID ingestion + progress-key persistence при `cleanup=0`; при stock `cleanup=1` маркер не персистит; сериализованный payload с `<?php` пишется в sess-файл; handler mismatch завершается безопасным «Failed to decode session object» (включая 5.6, проверено вручную).

Инфра-заметки обёртки для `php -S` в Docker: контейнер должен работать от uid хост-пользователя (иначе sess-файлы root:root 600 нечитаемы с хоста), stdin — из `/dev/null` (иначе `php:5.6-cli` молча не стартует через `docker run -i`).

## Рекомендации апстриму (scadastrangelove/php2shell)
1. ~~Починить `local_mode` в 109619~~ — **принято апстримом** (`8ce12d1`).
2. 109619 local: добавить сигнал «var_dump маркера в теле ответа» для ≤7.4 — иначе ложный SAFE на всех EOL-ветках (наш патч готов).
3. Remote обоих CVE: w1 case-insensitive, w3 решающий, w2 не обязателен (наш патч готов) + задокументировать роль `display_startup_errors` на ≤7.4.
4. 109618 local: маппить «rc=255 + пустой вывод» на ≤7.4 в PRE-FIX SIGNAL.
5. Nuclei: починить `randstr(16)` → `rand_base(16)` (или наши шаблоны) + case-insensitive матчеры.
