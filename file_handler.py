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
import logging

def read_file_binary(file_path):
    """
    Reads the contents of the specified file in binary mode.
    """
    try:
        with open(file_path, 'rb') as file:
            data = file.read()
        return data
    except FileNotFoundError as fnf_error:
        logging.error(f"File not found: {file_path} - {fnf_error}")
        raise
    except PermissionError as perm_error:
        logging.error(f"Permission denied: {file_path} - {perm_error}")
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
        return True
    except Exception as error:
        logging.error(f"Error writing file {file_path}: {error}")
        # Attempt to clean up the temporary file if it exists
        if temp_file and os.path.exists(temp_file.name):
            try:
                os.remove(temp_file.name)
            except Exception as cleanup_error:
                logging.error(f"Error during cleanup of temp file: {cleanup_error}")
        return False

def validate_file_access(file_path):
    """
    Checks whether a file exists and has both read and write access.
    """
    if not os.path.exists(file_path):
        return False
    if not os.access(file_path, os.R_OK):
        return False
    if not os.access(file_path, os.W_OK):
        return False
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
        return hash_func.hexdigest()
    except Exception as error:
        logging.error(f"Checksum calculation failed for {file_path}: {error}")
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
        return backup_file_path
    except Exception as error:
        logging.error(f"Backup creation failed for {file_path}: {error}")
        return None
