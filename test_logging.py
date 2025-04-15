#!/usr/bin/env python3
"""
Script to test the logging integration across all modules.
This script performs various operations to ensure proper logging is in place.
"""

import os
import sys
import tempfile
import crypto_engine
import file_handler
from log_manager import initialize_logger, logger, log_error

def create_test_file(content, directory=None):
    """Create a temporary file with the given content for testing."""
    if directory is None:
        directory = os.getcwd()
        
    fd, path = tempfile.mkstemp(prefix="test_log_", suffix=".txt", dir=directory)
    with os.fdopen(fd, 'w') as f:
        f.write(content)
        
    return path

def run_log_tests():
    """Run a series of tests to verify logging functionality."""
    # Initialize the logger
    initialize_logger()
    logger.info("====== STARTING LOGGING INTEGRATION TESTS ======")
    
    try:
        # ===== Test 1: File Operations =====
        logger.info("Test 1: Testing file operations logging")
        test_content = "This is test content for logging verification."
        test_file = create_test_file(test_content)
        logger.info(f"Created test file at: {test_file}")
        
        # Read file
        data = file_handler.read_file_binary(test_file)
        
        # Calculate checksum
        checksum = file_handler.calculate_file_checksum(test_file)
        
        # Create backup
        backup = file_handler.create_backup(test_file)
        
        # Validate access
        access = file_handler.validate_file_access(test_file)
        
        # Write modified data
        modified_data = data + b"\nModified for testing"
        file_handler.write_file_binary(test_file, modified_data)
        
        logger.info("Test 1 completed: File operations with logging")
        
        # ===== Test 2: Crypto Operations =====
        logger.info("Test 2: Testing crypto operations logging")
        
        # Generate key
        key = crypto_engine.generate_encryption_key()
        
        # Test key validation (valid)
        valid = crypto_engine.validate_decryption_key(key)
        
        # Test key validation (invalid)
        invalid_key = "This is not a valid key"
        invalid = crypto_engine.validate_decryption_key(invalid_key)
        
        # Encrypt data
        encrypted_data, used_key = crypto_engine.encrypt_data(data)
        
        # Decrypt data
        try:
            decrypted_data = crypto_engine.decrypt_data(encrypted_data, used_key)
        except Exception as e:
            log_error(f"Unexpected decryption error: {e}", "TestDecryptionError")
        
        # Decrypt with wrong key
        try:
            another_key = crypto_engine.generate_encryption_key()
            crypto_engine.decrypt_data(encrypted_data, another_key)
        except ValueError:
            logger.info("Expected error caught: Decryption with wrong key")
        
        logger.info("Test 2 completed: Crypto operations with logging")
        
        # ===== Test 3: Error Logging =====
        logger.info("Test 3: Testing error logging")
        
        # Test file not found
        try:
            file_handler.read_file_binary("non_existent_file.txt")
        except FileNotFoundError:
            logger.info("Expected error caught: File not found")
        
        # Test permission error (simulated)
        log_error("Simulated permission denied error", "PermissionError")
        
        # Test crypto error
        try:
            # Corrupt data
            corrupted_data = encrypted_data[:-10] + b"corrupted"
            crypto_engine.decrypt_data(corrupted_data, used_key)
        except Exception:
            logger.info("Expected error caught: Corrupted data")
        
        logger.info("Test 3 completed: Error logging")
        
        # Clean up test files
        try:
            os.remove(test_file)
            if backup and os.path.exists(backup):
                os.remove(backup)
        except Exception as e:
            log_error(f"Cleanup error: {e}", "CleanupError")
            
        return True
            
    except Exception as e:
        log_error(f"Test suite error: {e}", "TestSuiteError")
        return False
    finally:
        logger.info("====== COMPLETED LOGGING INTEGRATION TESTS ======")

if __name__ == "__main__":
    success = run_log_tests()
    sys.exit(0 if success else 1)