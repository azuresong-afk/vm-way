#!/bin/sh
# Создаёт .env из .env.example и заполняет секреты случайными значениями:
# VM_SECRET_KEY, VM_ENCRYPTION_KEY, POSTGRES_PASSWORD, VM_ADMIN_PASSWORD.
#
#   scripts/gen-env.sh            # обычная установка
#   scripts/gen-env.sh --demo     # демо-стенд: VM_DEMO=1 и случайный VM_DEMO_PASSWORD
#
# Существующий .env не перезаписывается: ключ шифрования в нём нужен, чтобы
# расшифровать уже сохранённые пароли источников.
set -eu

cd "$(dirname "$0")/.."
if [ -f .env ]; then
  echo "[gen-env] .env уже есть — не трогаю. Удалите его вручную, если нужен новый." >&2
  exit 1
fi
command -v openssl >/dev/null 2>&1 || { echo "[gen-env] нужен openssl" >&2; exit 1; }

# Только буквы и цифры: значения подставляются в URL БД и в sed.
rand() { openssl rand -base64 48 | tr -dc 'A-Za-z0-9' | cut -c1-"$1"; }

SECRET_KEY=$(rand 48)
ENC_KEY=$(openssl rand -base64 32)
PG_PASSWORD=$(rand 32)
ADMIN_PASSWORD=$(rand 16)

umask 077
sed -e "s|^VM_SECRET_KEY=.*|VM_SECRET_KEY=$SECRET_KEY|" \
    -e "s|^VM_ENCRYPTION_KEY=.*|VM_ENCRYPTION_KEY=$ENC_KEY|" \
    -e "s|^POSTGRES_PASSWORD=.*|POSTGRES_PASSWORD=$PG_PASSWORD|" \
    -e "s|^VM_ADMIN_PASSWORD=.*|VM_ADMIN_PASSWORD=$ADMIN_PASSWORD|" \
    .env.example > .env

if [ "${1:-}" = "--demo" ]; then
  DEMO_PASSWORD=$(rand 16)
  sed -i -e "s|^VM_DEMO=.*|VM_DEMO=1|" -e "s|^VM_DEMO_PASSWORD=.*|VM_DEMO_PASSWORD=$DEMO_PASSWORD|" .env
fi

echo "[gen-env] .env создан (права 600)."
echo "[gen-env] администратор: $(grep '^VM_ADMIN_USERNAME=' .env | cut -d= -f2) / $ADMIN_PASSWORD"
if [ "${1:-}" = "--demo" ]; then
  echo "[gen-env] демо-пользователи manager, engineer, engineer2, viewer / $DEMO_PASSWORD"
fi
echo "[gen-env] запомните пароли и сохраните .env отдельно от резервных копий: в нём ключ шифрования."
