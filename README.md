# «Устранение» — управление уязвимостями и обновлениями

Третий продукт семейства «Сканер» / «Устранение» / «Аттестация». «Устранение» доводит каждую уязвимость, найденную «Сканером», до конца: заявка → исполнитель → исправление → **повторная проверка сканером** → закрытие с доказательством. Работает только с системами заказчика в рамках договора.

Архитектура, модель данных, API и план по задачам — в [docs/roadmap.md](docs/roadmap.md).

## Быстрый старт (Docker)

Нужны Docker Engine 24+ с Compose v2 и `openssl`.

```bash
scripts/gen-env.sh                # .env со случайными секретами, печатает пароль администратора
docker compose up --build -d      # app (API), web (nginx), db (PostgreSQL 16)
scripts/smoke.sh                  # проверка стека через веб
```

Интерфейс — `http://localhost:18081`, вход — администратор из `.env`. Порты меняются в `.env` (`VM_WEB_PORT`, `VM_API_PORT`, `VM_DB_PORT`); API и БД слушают только `127.0.0.1`.

Демо-стенд без настоящего «Сканера» (встроенный мок: 3 ОС, 20 хостов, три плановых прогона; пользователи `manager`, `ciso`, `engineer`, `engineer2`, `viewer`):

```bash
scripts/gen-env.sh --demo && docker compose up --build -d
```

| Документ | О чём |
|---|---|
| [docs/INSTALL.md](docs/INSTALL.md) | установка, `.env`, HTTPS, подключение «Сканера», обновление, резервное копирование и восстановление, частые проблемы |
| [docs/TESTING.md](docs/TESTING.md) | пошаговая ручная проверка на демо-стенде с ожидаемым результатом по каждому шагу |
| [docs/roadmap.md](docs/roadmap.md) | архитектура, модель данных, API, решения и план по задачам |

Резервная копия и восстановление: `scripts/backup.sh`, `scripts/restore.sh КАТАЛОГ --yes`.

## Состояние

Этап 1 (MVP) готов. Задачи выполнялись по одной, каждая — отдельным PR.

- [x] 1.1 Каркас бэкенда: модели, миграция `0001`, вход, роли, журнал аудита, манифест, health
- [x] 1.2 Адаптер «Сканера» (HTTP и мок API) и демо-фикстура: 3 ОС, 20 хостов, три плановых прогона; формы ответов сверены с кодом «Сканера» (`backend/tests/scanner_contract.py`)
- [x] 1.3 Источники и привязки, фоновые задачи, импорт прогонов по кнопке и опросом без дублей
- [x] 1.4 Зеркало уязвимостей по `dedup_key` и заявки из действий «Что исправить» с подзадачами по хостам
- [x] 1.5 Назначение, статусы, комментарии, история, массовые действия
- [x] 1.6 Повторная проверка прицельным прогоном и автозакрытие, регрессии
- [x] 1.7 Интерфейс: Сводка, Заявки, Заявка, Мои задачи, Администрирование; светлая и тёмная тема, телефон
- [x] 1.8 Docker Compose, CI, документация

Дальше — этап 2 (окна обслуживания, правила назначения, раскатка, исключения), см. [docs/roadmap.md](docs/roadmap.md#6-этапы).

## Разработка

Бэкенд (Python 3.12):

```bash
cd backend
python3.12 -m venv .venv && . .venv/bin/activate
pip install -r requirements-dev.txt
ruff check . && ruff format --check . && pytest -q
# Все тесты на PostgreSQL (необязательно; так же идёт CI). Нужна отдельная пустая база:
# схема public в ней пересоздаётся перед каждым тестом.
VM_TEST_ON_PG=1 VM_TEST_PG_URL=postgresql+psycopg://vm:vm@127.0.0.1:5432/vm_test pytest -q
```

Демо-фикстура «Сканера» генерируется скриптом и проверяется в CI на совпадение:

```bash
python -m app.integrations.scanner.fixtures.generate > app/integrations/scanner/fixtures/demo.json
```

Фронтенд (Node 22):

```bash
cd frontend
npm ci
npm run lint && npm run typecheck && npm test
npm run dev   # http://localhost:5174, /api проксируется на API :8000 (VM_API_URL)
```

Запуск API без Docker — [docs/INSTALL.md, раздел 11](docs/INSTALL.md#11-запуск-без-docker-разработка). CI (`.github/workflows/ci.yml`): ruff, pytest с миграциями на PostgreSQL, ESLint, typecheck, vitest, сборка, а также сборка образов и проверка всего стека `docker compose up`.
