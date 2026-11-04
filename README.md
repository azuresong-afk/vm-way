# «Устранение» — управление уязвимостями и обновлениями

Третий продукт семейства «Сканер» / «Устранение» / «Аттестация». «Устранение» доводит каждую уязвимость, найденную «Сканером», до конца: заявка → исполнитель → исправление → **повторная проверка сканером** → закрытие с доказательством. Работает только с системами заказчика в рамках договора.

Архитектура, модель данных, API и план по задачам — в [docs/roadmap.md](docs/roadmap.md).

## Состояние

Идёт этап 1 (MVP), задачи выполняются по одной, каждая — отдельным PR.

- [x] 1.1 Каркас бэкенда: модели, миграция `0001`, вход, роли, журнал аудита, манифест, health
- [x] 1.2 Адаптер «Сканера» (HTTP и мок API) и демо-фикстура: 3 ОС, 20 хостов, три плановых прогона; формы ответов сверены с кодом «Сканера» (`backend/tests/scanner_contract.py`)
- [ ] 1.3–1.8 — см. план

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

Демо-фикстура «Сканера» генерируется скриптом и проверяется в CI на совпадение:

```bash
python -m app.integrations.scanner.fixtures.generate > app/integrations/scanner/fixtures/demo.json
```

Docker Compose, фронтенд и полная документация (`docs/INSTALL.md`, `docs/TESTING.md`) появятся в задачах 1.7–1.8.
