#!/bin/sh
# Подготовка и запуск API «Устранения»:
#   проверка секретов -> миграции схемы -> запуск API.
# Первого администратора (VM_ADMIN_USERNAME / VM_ADMIN_PASSWORD) и демо-данные
# (VM_DEMO=1) создаёт само приложение при старте, если пользователей ещё нет.
set -eu

# Пустые, шаблонные (CHANGE_ME) или слабые секреты останавливают старт с причиной в логе.
python -m app.preflight

# Миграции. База может подниматься дольше API — несколько попыток, затем понятная
# ошибка вместо цикла перезапусков с трассировкой.
echo "[entrypoint] применяю миграции схемы БД (alembic upgrade head)..."
attempt=1
max_attempts="${VM_DB_WAIT_ATTEMPTS:-30}"
until alembic upgrade head; do
  if [ "$attempt" -ge "$max_attempts" ]; then
    echo "[entrypoint] ОШИБКА: миграции не применены за $max_attempts попыток." >&2
    echo "[entrypoint] Проверьте, что БД доступна и POSTGRES_PASSWORD совпадает с тем," \
         "с которым создавался том vm_pg_data." >&2
    exit 1
  fi
  echo "[entrypoint] БД недоступна или миграция не прошла (попытка $attempt/$max_attempts), жду 2 с..." >&2
  attempt=$((attempt + 1))
  sleep 2
done

echo "[entrypoint] запускаю API на :8000 ..."
# Строго один процесс: фоновые задачи (импорт, опрос источников, проверки)
# исполняются пулом потоков внутри API и восстанавливаются после рестарта.
exec uvicorn app.main:app --host 0.0.0.0 --port 8000 --workers 1 --no-server-header
