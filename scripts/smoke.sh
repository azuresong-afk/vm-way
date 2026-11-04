#!/bin/sh
# Быстрая проверка поднятого стека через веб (nginx -> API -> БД).
#
#   scripts/smoke.sh [адрес]      по умолчанию http://127.0.0.1:${VM_WEB_PORT:-18081}
#
# Проверяет: nginx жив, заголовки безопасности, SPA отдаётся на любом пути,
# API готов (схема на последней миграции), манифест, вход администратора из .env.
# При VM_DEMO=1 — ещё вход менеджера и что импорт демо-прогонов создал заявки.
# Нужны curl и python3. Используется в CI (job «compose»).
set -eu

cd "$(dirname "$0")/.."
env_val() { grep -E "^$1=" .env | tail -n1 | cut -d= -f2-; }
BASE="${1:-http://127.0.0.1:$(env_val VM_WEB_PORT || true)}"
case "$BASE" in *:) BASE="${BASE}18081" ;; esac

fail() { echo "[smoke] ОШИБКА: $*" >&2; exit 1; }
ok() { echo "[smoke] ok: $*"; }
json() { python3 -c "import json,sys; d=json.load(sys.stdin); print($1)"; }

[ "$(curl -fsS "$BASE/healthz")" = "ok" ] || fail "nginx /healthz"
ok "nginx /healthz"

HDRS=$(curl -fsS -D - -o /dev/null "$BASE/tickets")
echo "$HDRS" | grep -qi "^content-security-policy: default-src 'self'" || fail "нет CSP на SPA"
echo "$HDRS" | grep -qi "^x-frame-options: DENY" || fail "нет X-Frame-Options"
curl -fsS "$BASE/tickets" | grep -q '<div id="root">' || fail "SPA не отдаётся на /tickets"
ok "SPA и заголовки безопасности"

curl -fsS "$BASE/api/health/ready" | grep -q '"ok"' || fail "API не готов (/api/health/ready)"
ok "API готов, схема на последней миграции"
[ "$(curl -fsS "$BASE/api/manifest" | json 'd["id"]')" = "vm" ] || fail "манифест"
ok "манифест"

login() {
  curl -fsS -X POST "$BASE/api/auth/token" -H 'Content-Type: application/json' \
    -d "{\"username\": \"$1\", \"password\": \"$2\"}" | json 'd["access_token"]'
}
TOKEN=$(login "$(env_val VM_ADMIN_USERNAME)" "$(env_val VM_ADMIN_PASSWORD)") || fail "вход администратора"
[ "$(curl -fsS "$BASE/api/me" -H "Authorization: Bearer $TOKEN" | json 'd["username"]')" = "$(env_val VM_ADMIN_USERNAME)" ] \
  || fail "/api/me администратора"
ok "вход администратора"

if [ "$(env_val VM_DEMO)" = "1" ]; then
  TOKEN=$(login manager "$(env_val VM_DEMO_PASSWORD)") || fail "вход manager"
  AUTH="Authorization: Bearer $TOKEN"
  PID=$(curl -fsS "$BASE/api/projects" -H "$AUTH" | json 'd[0]["id"] if isinstance(d, list) else d["items"][0]["id"]')
  # Демо-прогоны импортирует опрос источника при старте — ждём до минуты.
  n=0
  for _ in $(seq 1 30); do
    n=$(curl -fsS -D - -o /dev/null "$BASE/api/projects/$PID/tickets?limit=1" -H "$AUTH" \
      | tr -d '\r' | awk -F': ' 'tolower($1)=="x-total-count"{print $2}')
    [ "${n:-0}" -gt 0 ] && break
    sleep 2
  done
  [ "${n:-0}" -gt 0 ] || fail "демо-импорт не создал заявок"
  ok "демо: вход manager, заявок в проекте — $n"
fi
echo "[smoke] всё в порядке: $BASE"
