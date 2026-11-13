# API «Устранения»: FastAPI + фоновые задачи в том же процессе.
FROM python:3.15-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Pango и шрифты с кириллицей — для PDF-отчётов (WeasyPrint) и подписей графиков в DOCX.
RUN apt-get update && apt-get install -y --no-install-recommends \
        libpango-1.0-0 \
        libpangoft2-1.0-0 \
        fonts-dejavu-core \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt ./
RUN pip install -r requirements.txt

# Код — после зависимостей: правка кода не пересобирает слой с пакетами.
COPY alembic.ini ./
COPY alembic ./alembic
COPY app ./app
COPY docker/entrypoint.sh /usr/local/bin/vm-entrypoint
RUN chmod 0755 /usr/local/bin/vm-entrypoint \
    && useradd --system --uid 10001 --no-create-home --shell /usr/sbin/nologin vm

# Процесс без root: API пишет только в БД.
USER vm
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health/ready', timeout=5).status == 200 else 1)"

# Проверка секретов -> миграции -> запуск (первый администратор создаётся при старте API).
ENTRYPOINT ["vm-entrypoint"]
