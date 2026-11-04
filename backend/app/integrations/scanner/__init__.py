"""Адаптер «Сканера»: всё обращение к его API идёт только через этот пакет."""

from app.integrations.scanner.client import (
    FINISHED_STATUSES,
    HttpScannerClient,
    ScannerClient,
    ScannerError,
    make_client,
)
from app.integrations.scanner.mock import MockScanner

__all__ = ["FINISHED_STATUSES", "HttpScannerClient", "MockScanner", "ScannerClient", "ScannerError", "make_client"]
