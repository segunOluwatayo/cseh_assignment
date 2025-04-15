"""
This module provides file I/O operations to support the encryption/decryption tool.
It includes functions to read and write files in binary mode with error handling,
validate file accessibility, generate cryptographic checksums to verify file integrity,
and create backups as a safety measure for decryption processes.
"""

import os
import hashlib
import shutil
import tempfile
from log_manager import log_error, log_operation

def read_file_binary(file_path):
    """
    Reads the contents of the specified file in binary mode.
    """
    try:
        with open(file_path, 'rb') as file:
            data = file.read()
        log_operation(file_path, "read_binary")
        return data
    except FileNotFoundError as fnf_error:
        log_error(f"File not found: {file_path}", "FileNotFoundError")
        raise
    except PermissionError as perm_error:
        log_error(f"Permission denied: {file_path}", "PermissionError")
        raise

def write_file_binary(file_path, data):
    """
    Writes binary data to a file in an atomic manner to prevent data corruption.
    The function writes data to a temporary file in the same directory and then
    replaces the original file with the temporary file, ensuring an atomic write.
    """
    directory = os.path.dirname(file_path)
    temp_file = None
    try:
        # Create a temporary file in the same directory to ensure atomic replacement
        temp_file = tempfile.NamedTemporaryFile(delete=False, dir=directory)
        temp_file.write(data)
        temp_file.close()
        os.replace(temp_file.name, file_path)
        log_operation(file_path, "write_binary")
        return True
    except Exception as error:
        log_error(f"Error writing file {file_path}: {error}", "WriteError")
        # Attempt to clean up the temporary file if it exists
        if temp_file and os.path.exists(temp_file.name):
            try:
                os.remove(temp_file.name)
            except Exception as cleanup_error:
                log_error(f"Error during cleanup of temp file: {cleanup_error}", "CleanupError")
        return False

def validate_file_access(file_path):
    """
    Checks whether a file exists and has both read and write access.
    """
    if not os.path.exists(file_path):
        log_error(f"File does not exist: {file_path}", "FileAccessError")
        return False
    if not os.access(file_path, os.R_OK):
        log_error(f"No read access to file: {file_path}", "FileAccessError")
        return False
    if not os.access(file_path, os.W_OK):
        log_error(f"No write access to file: {file_path}", "FileAccessError")
        return False
    log_operation(file_path, "validate_access_success")
    return True

def calculate_file_checksum(file_path, algorithm='sha256'):
    """
    Calculates a cryptographic hash (checksum) for the specified file.
    """
    try:
        hash_func = hashlib.new(algorithm)
        with open(file_path, 'rb') as file:
            for chunk in iter(lambda: file.read(8192), b""):
                hash_func.update(chunk)
        checksum = hash_func.hexdigest()
        log_operation(file_path, f"checksum_calculated_{algorithm}")
        return checksum
    except Exception as error:
        log_error(f"Checksum calculation failed for {file_path}", "ChecksumError")
        return None

def create_backup(file_path):
    """
    Creates a backup copy of the specified file.

    The backup file is created in the same directory with a '.bak' extension appended
    to the original file's name. This is done as an additional safety measure.
    """
    directory = os.path.dirname(file_path)
    base_name = os.path.basename(file_path)
    backup_file_name = f"{base_name}.bak"
    backup_file_path = os.path.join(directory, backup_file_name)
    try:
        shutil.copy2(file_path, backup_file_path)
        log_operation(backup_file_path, "backup_created")
        return backup_file_path
    except Exception as error:
        log_error(f"Backup creation failed for {file_path}", "BackupError")
        return None