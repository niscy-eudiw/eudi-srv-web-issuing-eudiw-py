import os
import logging
from logging.handlers import TimedRotatingFileHandler

def configure_logging(app, CONFIGURATION):
    """
    Configures logging for Flask, Werkzeug, and Gunicorn.
    
    :param app: The Flask application instance.
    :param CONFIGURATION: Your configuration dictionary.
    """
    # 1. Extract log file path from the configuration dictionary
    log_file_path = CONFIGURATION["logging"]["backend_path"]
    
    # Ensure the directory for the log file exists
    log_dir = os.path.dirname(log_file_path)
    if log_dir:
        os.makedirs(log_dir, exist_ok=True)

    # 2. Create a standard formatter for all logs
    log_formatter = logging.Formatter(
        '%(asctime)s | %(name)-15s | %(levelname)-8s | %(message)s'
    )

    # 3. Setup File Handler (Rotates daily at midnight, keeps 7 days)
    file_handler = TimedRotatingFileHandler(
        filename=log_file_path,
        when='midnight',
        interval=1,
        backupCount=7,
        encoding='utf-8'
    )
    file_handler.setFormatter(log_formatter)
    file_handler.setLevel(logging.INFO)

    # 4. Setup Console Handler
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(log_formatter)
    console_handler.setLevel(logging.INFO)

    # 5. Define the loggers we want to override
    loggers_to_configure =[
        app.logger,                           # Flask's internal logger
        logging.getLogger('werkzeug'),        # Werkzeug (handles dev server & request routing logs)
        logging.getLogger('gunicorn.error'),  # Gunicorn error logs
        logging.getLogger('gunicorn.access')  # Gunicorn access logs
    ]

    # 6. Apply handlers to loggers and prevent duplicate logs
    for logger in loggers_to_configure:
        # Clear default handlers to prevent duplicate output
        logger.handlers.clear()
        
        # Add our custom handlers
        logger.addHandler(file_handler)
        logger.addHandler(console_handler)
        
        # Set base logging level
        logger.setLevel(logging.INFO)
        
        # Disable propagation to the root logger to avoid duplicate log entries
        logger.propagate = False

    # Optional: If Gunicorn is dictating the log level via CLI, sync Flask to it
    gunicorn_logger = logging.getLogger('gunicorn.error')
    if gunicorn_logger.level != logging.NOTSET:
        app.logger.setLevel(gunicorn_logger.level)
        
    app.logger.info("Logging initialized. Outputting to console and %s", log_file_path)




import logging
import os
from concurrent_log_handler import ConcurrentTimedRotatingFileHandler


def configure_logging(app, config):
    """
    Configures logging for Flask, Werkzeug, and Gunicorn.

    :param app: The Flask application instance.
    :param config: The configuration dictionary.
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

    app.logger.info("Logging initialized. Outputting to console and %s", log_file_path)