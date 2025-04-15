#!/usr/bin/env python3
"""
Minimal Command-Line Interface for testing the Encryption/Decryption Tool's core functionality.
This script allows testing of key generation, file encryption/decryption, and file handling 
without the GUI components.
"""

import os
import sys
import logging
import hashlib
from argparse import ArgumentParser

# Import the modules
import config
import crypto_engine
import file_handler

# Set up basic logging
logging.basicConfig(
    level=logging.INFO,
    format=config.LOG_FORMAT,
    handlers=[
        logging.FileHandler(config.LOG_FILE_PATH),
        logging.StreamHandler()
    ]
)

def encrypt_file(file_path):
    """
    Encrypts the specified file and displays the decryption key.
    """
    # Validate file first
    if not os.path.exists(file_path):
        logging.error(f"File not found: {file_path}")
        return False, f"Error: {config.ERROR_FILE_NOT_FOUND}"
    
    if not file_handler.validate_file_access(file_path):
        logging.error(f"Cannot access file: {file_path}")
        return False, f"Error: {config.ERROR_PERMISSION_DENIED}"
    
    # Calculate checksum before encryption for later verification
    original_checksum = file_handler.calculate_file_checksum(file_path)
    logging.info(f"Original file checksum: {original_checksum}")
    
    try:
        # Read file content
        file_data = file_handler.read_file_binary(file_path)
        file_size_mb = len(file_data) / (1024 * 1024)
        
        # Check file size
        if file_size_mb > config.MAX_FILE_SIZE_MB:
            logging.error(f"File too large: {file_size_mb}MB exceeds limit of {config.MAX_FILE_SIZE_MB}MB")
            return False, f"Error: {config.ERROR_FILE_TOO_LARGE}"
        
        # Encrypt data
        encrypted_data, key = crypto_engine.encrypt_data(file_data)
        
        # Write encrypted data back to file
        if not file_handler.write_file_binary(file_path, encrypted_data):
            logging.error(f"Failed to write encrypted data to {file_path}")
            return False, "Error: Failed to write encrypted data to file."
        
        logging.info(f"File encrypted successfully: {file_path}")
        return True, key
    
    except Exception as e:
        logging.error(f"Encryption failed: {str(e)}")
        return False, f"Error: Encryption failed - {str(e)}"

def decrypt_file(file_path, key):
    """
    Decrypts the specified file using the provided key.
    """
    # Validate file first
    if not os.path.exists(file_path):
        logging.error(f"File not found: {file_path}")
        return False, f"Error: {config.ERROR_FILE_NOT_FOUND}"
    
    if not file_handler.validate_file_access(file_path):
        logging.error(f"Cannot access file: {file_path}")
        return False, f"Error: {config.ERROR_PERMISSION_DENIED}"
    
    # Validate key
    if not crypto_engine.validate_decryption_key(key):
        logging.error("Invalid decryption key")
        return False, f"Error: {config.ERROR_INVALID_KEY_MESSAGE}"
    
    try:
        # Create backup if enabled
        if config.BACKUP_ENABLED:
            backup_path = file_handler.create_backup(file_path)
            if backup_path:
                logging.info(f"Backup created at: {backup_path}")
            else:
                logging.warning("Failed to create backup")
        
        # Read encrypted file
        encrypted_data = file_handler.read_file_binary(file_path)
        
        # Decrypt data
        try:
            decrypted_data = crypto_engine.decrypt_data(encrypted_data, key)
        except ValueError as e:
            logging.error(f"Decryption failed: {str(e)}")
            return False, f"Error: {config.ERROR_DECRYPTION_FAILED}"
        
        # Write decrypted data back to file
        if not file_handler.write_file_binary(file_path, decrypted_data):
            logging.error(f"Failed to write decrypted data to {file_path}")
            return False, "Error: Failed to write decrypted data to file."
        
        logging.info(f"File decrypted successfully: {file_path}")
        return True, "Decryption successful."
    
    except Exception as e:
        logging.error(f"Decryption failed: {str(e)}")
        return False, f"Error: Decryption failed - {str(e)}"

def main():
    """
    Main function that processes command-line arguments and executes the 
    appropriate encryption or decryption operation.
    """
    parser = ArgumentParser(description="File Encryption/Decryption CLI")
    parser.add_argument("file", help="Path to the file to encrypt or decrypt")
    
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-e", "--encrypt", action="store_true", help="Encrypt the file")
    group.add_argument("-d", "--decrypt", action="store_true", help="Decrypt the file")
    
    parser.add_argument("-k", "--key", help="Decryption key (required for decryption)")
    
    args = parser.parse_args()
    
    # Check if file exists
    if not os.path.exists(args.file):
        print(f"Error: File '{args.file}' not found.")
        return 1
    
    if args.encrypt:
        success, result = encrypt_file(args.file)
        if success:
            print("\n" + "="*50)
            print("ENCRYPTION SUCCESSFUL")
            print("="*50)
            print(f"File: {args.file}")
            print("\nIMPORTANT: Save this decryption key to decrypt your file later!")
            print("="*50)
            print(f"Decryption Key: {result}")
            print("="*50)
            print("\nWARNING: This key will only be displayed ONCE!")
            return 0
        else:
            print(f"Encryption failed: {result}")
            return 1
    
    elif args.decrypt:
        if not args.key:
            print("Error: Decryption key is required for decryption.")
            return 1
        
        success, result = decrypt_file(args.file, args.key)
        if success:
            print("\n" + "="*50)
            print("DECRYPTION SUCCESSFUL")
            print("="*50)
            print(f"File: {args.file}")
            print("="*50)
            return 0
        else:
            print(f"Decryption failed: {result}")
            return 1

if __name__ == "__main__":
    sys.exit(main())