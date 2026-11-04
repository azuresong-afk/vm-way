#!/bin/sh
# Резервная копия «Устранения»: база PostgreSQL (pg_dump, формат custom).
#
#   scripts/backup.sh [каталог]       по умолчанию ./backups/ГГГГ-ММ-ДД_ЧЧММСС
#
# Работает при запущенном стеке (сервис db должен быть запущен); фоновые задачи
# не останавливаются — pg_dump снимает согласованный снимок.
# ВАЖНО: файл .env (VM_ENCRYPTION_KEY) в копию НЕ входит — храните его отдельно
# и надёжно: без того же ключа пароли источников из копии не расшифруются.
set -eu

cd "$(dirname "$0")/.."
DEST="${1:-backups/$(date +%Y-%m-%d_%H%M%S)}"
mkdir -p "$DEST"

# Имя БД и пользователь — из окружения контейнера db (как их задал .env).
echo "[backup] база данных -> $DEST/db.dump"
docker compose exec -T db sh -c 'pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB" --format=custom --no-owner' > "$DEST/db.dump"
# pg_dump с ошибкой оставит пустой или обрезанный файл — проверяем оглавлением.
docker compose exec -T db pg_restore --list < "$DEST/db.dump" > /dev/null

REV=$(docker compose exec -T db sh -c 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -tAc "SELECT version_num FROM alembic_version"' | tr -d '[:space:]')
{
  echo "created_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "alembic_revision=$REV"
  echo "git_commit=$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
} > "$DEST/manifest.txt"
( cd "$DEST" && sha256sum db.dump > SHA256SUMS )

echo "[backup] готово: $DEST ($(du -sh "$DEST" | cut -f1)), миграция $REV"
echo "[backup] не забудьте отдельно сохранить .env (ключ шифрования)."
