"""Logging configuration for Flask, Werkzeug and Gunicorn."""

from __future__ import annotations

import logging
import os
from typing import Any, Mapping

from concurrent_log_handler import ConcurrentTimedRotatingFileHandler
from flask import Flask


class LineBreakEscapeFilter(logging.Filter):
    """Escapes CR / LF in every log message (log injection).

    :func:`app.core.log_utils.safe` escapes request values where they are
    logged; this filter, installed on the handlers, also covers any message
    that misses it, so no record can start a forged log line.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        """Rewrites ``record`` with its final message escaped.

        Args:
            record: The log record.

        Returns:
            Always ``True`` (records are never dropped).
        """
        message = record.getMessage()
        if "\r" in message or "\n" in message:
            record.msg = message.replace("\r", "\\r").replace("\n", "\\n")
            record.args = None
        return True


class WerkzeugFilter(logging.Filter):
    """Drops Werkzeug per-request access log lines (``... HTTP/1.1 ...``)."""

    def filter(self, record: logging.LogRecord) -> bool:
        """Decides whether ``record`` is logged.

        Args:
            record: The log record.

        Returns:
            ``False`` for access-log lines, ``True`` otherwise.
        """
        return "HTTP/1" not in record.getMessage()


def configure_logging(app: Flask, config: Mapping[str, Any]) -> None:
    """Configures file + console logging for Flask, Werkzeug and Gunicorn.

    Logs rotate daily and seven days are kept.

    Args:
        app: The Flask application.
        config: The ``logging`` configuration section (``backend_path``,
            optional ``log_level``).
    """
    log_file_path = config["backend_path"]
    log_level = getattr(logging, config.get("log_level", "INFO").upper(), logging.INFO)

    log_dir = os.path.dirname(log_file_path)
    if log_dir:
        os.makedirs(log_dir, exist_ok=True)

    log_formatter = logging.Formatter(
        '%(asctime)s | %(name)-20s | %(levelname)-8s | %(message)s'
    )

    file_handler = ConcurrentTimedRotatingFileHandler(
        filename=log_file_path,
        when='midnight',
        interval=1,
        backupCount=7,
        encoding='utf-8'
    )
    file_handler.setFormatter(log_formatter)
    file_handler.setLevel(log_level)

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(log_formatter)
    console_handler.setLevel(log_level)

    line_break_filter = LineBreakEscapeFilter()
    file_handler.addFilter(line_break_filter)
    console_handler.addFilter(line_break_filter)

    # Sync with Gunicorn's level if it's more specific than what config says
    gunicorn_logger = logging.getLogger('gunicorn.error')
    if gunicorn_logger.level != logging.NOTSET:
        log_level = gunicorn_logger.level

    loggers_to_configure = [
        logging.getLogger(),
        app.logger,
        logging.getLogger('werkzeug'),
        logging.getLogger('gunicorn.error'),
        logging.getLogger('gunicorn.access'),
    ]

    for logger in loggers_to_configure:
        logger.handlers.clear()
        logger.addHandler(file_handler)
        logger.addHandler(console_handler)
        logger.setLevel(log_level)
        logger.propagate = False

    logging.getLogger('werkzeug').addFilter(WerkzeugFilter())

    app.logger.info("Logging initialized. Outputting to console and %s", log_file_path)