# «Устранение» — управление уязвимостями и обновлениями

Третий продукт семейства «Сканер» / «Устранение» / «Аттестация». «Устранение» доводит каждую уязвимость, найденную «Сканером», до конца: заявка → исполнитель → исправление → **повторная проверка сканером** → закрытие с доказательством. Работает только с системами заказчика в рамках договора.

Архитектура, модель данных, API и план по задачам — в [docs/roadmap.md](docs/roadmap.md).

## Состояние

Идёт этап 1 (MVP), задачи выполняются по одной, каждая — отдельным PR.

- [x] 1.1 Каркас бэкенда: модели, миграция `0001`, вход, роли, журнал аудита, манифест, health
- [x] 1.2 Адаптер «Сканера» (HTTP и мок API) и демо-фикстура: 3 ОС, 20 хостов, три плановых прогона; формы ответов сверены с кодом «Сканера» (`backend/tests/scanner_contract.py`)
- [x] 1.3 Источники и привязки, фоновые задачи, импорт прогонов по кнопке и опросом без дублей
- [x] 1.4 Зеркало уязвимостей по `dedup_key` и заявки из действий «Что исправить» с подзадачами по хостам
- [x] 1.5 Назначение, статусы, комментарии, история, массовые действия
- [x] 1.6 Повторная проверка прицельным прогоном и автозакрытие, регрессии
- [x] 1.7 Интерфейс: Сводка, Заявки, Заявка, Мои задачи, Администрирование; светлая и тёмная тема, телефон
- [ ] 1.8 Docker Compose, CI, документация

## Бэкенд: запуск тестов

```bash
cd backend
python3.12 -m venv .venv && . .venv/bin/activate
pip install -r requirements-dev.txt
ruff check . && pytest -q
# Миграции на PostgreSQL (необязательно):
VM_TEST_PG_URL=postgresql+psycopg://vm:vm@127.0.0.1:5432/vm pytest -q tests/test_migrations.py
```

Запуск API локально (без Docker, на SQLite):

```bash
cd backend
export VM_SECRET_KEY=dev-secret VM_ENCRYPTION_KEY=$(python -c "import os,base64;print(base64.b64encode(os.urandom(32)).decode())")
export VM_DATABASE_URL=sqlite:///./vm.db VM_ADMIN_PASSWORD=admin-password-1
alembic upgrade head && uvicorn app.main:app --reload
```

С `VM_DEMO=1` при старте создаются демо-проект, источник `mock://demo` с привязкой и пользователи `manager`, `engineer`, `engineer2`, `viewer` (пароль — `VM_DEMO_PASSWORD`). Опрос источника сразу импортирует три плановых прогона.

Демо-фикстура «Сканера» генерируется скриптом и проверяется в CI на совпадение:

```bash
python -m app.integrations.scanner.fixtures.generate > app/integrations/scanner/fixtures/demo.json
```

## Фронтенд

```bash
cd frontend
npm ci
npm run lint && npm run typecheck && npm test
npm run dev   # http://localhost:5174, /api проксируется на API :8000 (VM_API_URL)
```

Демо-вход при `VM_DEMO=1`: `manager`, `engineer`, `engineer2`, `viewer` с паролем `VM_DEMO_PASSWORD`; администратор — `VM_ADMIN_USERNAME` / `VM_ADMIN_PASSWORD`.

Docker Compose и полная документация (`docs/INSTALL.md`, `docs/TESTING.md`) появятся в задаче 1.8.
