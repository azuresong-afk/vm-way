"""Точка входа API «Устранения»."""

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI

from app import bootstrap, jobs
from app.api import (
    assets,
    audit_log,
    auth,
    credentials,
    meta,
    projects,
    rollouts,
    rules,
    sources,
    summary,
    ticket_work,
    tickets,
    users,
    windows,
)
from app.config import get_settings
from app.db import SessionLocal
from app.services import importer, verification  # noqa: F401 — регистрируют обработчики задач

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")


@asynccontextmanager
async def lifespan(_: FastAPI):
    if not get_settings().secret_key:
        raise RuntimeError("VM_SECRET_KEY не задан")
    s = get_settings()
    if s.demo:
        # Демо-стенд SSH: поддельные хосты фикстуры для раскаток (app/integrations/sshsim.py).
        from app.integrations import sshsim

        sshsim.start_demo(s.secret_key)
    with SessionLocal() as db:
        bootstrap.ensure_admin(db)
        bootstrap.ensure_demo(db)
    jobs.runner.inline = s.jobs_inline
    jobs.runner.start(poll=s.poll_enabled)
    try:
        yield
    finally:
        jobs.runner.stop()


def create_app() -> FastAPI:
    app = FastAPI(
        title="Устранение API",
        version=get_settings().product_version,
        lifespan=lifespan,
        docs_url="/docs",
        openapi_url="/openapi.json",
    )
    for r in (
        meta.router,
        auth.router,
        users.router,
        projects.router,
        sources.router,
        tickets.router,
        ticket_work.router,
        windows.router,
        assets.router,
        rules.router,
        credentials.router,
        rollouts.router,
        summary.router,
        audit_log.router,
    ):
        app.include_router(r)
    return app


app = create_app()
