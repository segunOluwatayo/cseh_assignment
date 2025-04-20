"""
This module manages secure logging for the encryption/decryption application.
It configures a rotating file handler to prevent unlimited log file growth
and offers helper functions to log operations and errors without exposing sensitive data.
"""

import logging
import os
from logging.handlers import RotatingFileHandler
import config 
import re

logger = logging.getLogger("EncryptionAppLogger")
logger.setLevel(logging.INFO)

def initialize_logger():
    """
    Initializes and configures the logging system with a rotating file handler.

    Reads configuration values from config.py for the log file path and format.
    Sets up log rotation so that the log file is rotated after reaching a specified size.
    Also adds a console handler for real-time logging.
    """
    # Avoid duplicate handlers if the logger has already been configured
    if logger.handlers:
        return logger

    # Define log file size threshold and backup count for rotation
    max_log_size_bytes = 5 * 1024 * 1024 
    backup_count = 5  

    # Retrieve configuration settings from config.py
    log_file_path = getattr(config, "LOG_FILE_PATH", "encryption_app.log")
    log_format = getattr(config, "LOG_FORMAT", "%(asctime)s - %(levelname)s - %(message)s - %(filename)s:%(lineno)d")

    formatter = logging.Formatter(log_format)

    # Set up rotating file handler to manage log file size
    file_handler = RotatingFileHandler(log_file_path, maxBytes=max_log_size_bytes, backupCount=backup_count)
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    logger.info("Logger initialized with rotating file handler.")
    return logger

def log_operation(file_path, operation_type):
    """
    Logs a non-sensitive message for file operations.
    """
    # Sanitize the file path to prevent exposure of full directory structure
    file_name = os.path.basename(file_path)
    message = f"Operation: {operation_type} performed on file: {file_name}"
    logger.info(message)

def log_error(error_message, error_type):
    """
    Logs an error message with its associated type, ensuring sensitive data is not exposed.
    """
    sanitized_message = re.sub(r'[A-Za-z0-9+/=]{32,}', '[REDACTED_POTENTIAL_KEY]', str(error_message))
    
    logger.error(f"Error Type: {error_type} | Message: {sanitized_message}")
