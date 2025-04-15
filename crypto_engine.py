"""
This module handles all encryption and decryption operations using symmetric key cryptography.
It leverages the cryptography package's Fernet implementation to provide strong cryptographic
guarantees. The module includes functions to generate keys, encrypt data, decrypt data, and validate keys.
"""

from cryptography.fernet import Fernet, InvalidToken
import base64
from log_manager import logger, log_error

def generate_encryption_key():
    """
    Generates a cryptographically secure random key.
    """
    key_bytes = Fernet.generate_key()  
    key_str = key_bytes.decode('utf-8') 
    logger.info("New encryption key generated")
    return key_str

def encrypt_data(data, key=None):
    """
    Encrypts binary data using Fernet symmetric encryption.
    """
    try:
        if key is None:
            key = generate_encryption_key()
            logger.info("Using newly generated encryption key")
        else:
            if not validate_decryption_key(key):
                log_error("Invalid encryption key format", "KeyValidationError")
                raise ValueError("Invalid encryption key provided.")
            logger.info("Using provided encryption key")
        
        # Create a Fernet object with the given key. 
        # Ensure key is properly formatted
        key_bytes = key.encode('utf-8')
        fernet = Fernet(key_bytes)
        encrypted_data = fernet.encrypt(data)
        logger.info(f"Data encrypted successfully: {len(data)} bytes → {len(encrypted_data)} bytes")
        return encrypted_data, key
    except Exception as e:
        # Don't log the actual key or exception details that might contain sensitive info
        log_error(f"Encryption operation failed: {type(e).__name__}", "EncryptionError")
        raise

def decrypt_data(encrypted_data, key):
    """
    Decrypts encrypted binary data using the provided decryption key.
    """
    try:
        # Clean the key by removing any whitespace
        key = key.strip()
        
        if not validate_decryption_key(key):
            log_error("Invalid decryption key format", "KeyValidationError")
            raise ValueError("Invalid decryption key provided.")
        
        # Ensure key is properly encoded
        key_bytes = key.encode('utf-8')
        fernet = Fernet(key_bytes)
        
        try:
            decrypted_data = fernet.decrypt(encrypted_data)
            logger.info(f"Data decrypted successfully: {len(encrypted_data)} bytes → {len(decrypted_data)} bytes")
            return decrypted_data
        except InvalidToken as it:
            # Log the error without exposing the key
            log_error("Decryption failed - Invalid token", "DecryptionError")
            # Raise an informative error that does not leak sensitive details
            raise ValueError("Decryption failed. The key may be incorrect or the data is corrupted.")
    except Exception as e:
        if not isinstance(e, ValueError) or "Invalid decryption key provided" not in str(e):
            log_error(f"Unexpected error during decryption: {type(e).__name__}", "DecryptionError")
        raise

def validate_decryption_key(key):
    """
    Validates the structure and format of the decryption key.
    The key must be a URL-safe base64-encoded string of 32 bytes.
    """
    if not isinstance(key, str):
        logger.warning("Key validation failed: not a string")
        return False
    
    # Clean up the key - remove any whitespace
    key = key.strip()
    
    try:
        # Attempt to decode the key; this ensures it is properly base64 encoded
        key_bytes = key.encode('utf-8')
        decoded = base64.urlsafe_b64decode(key_bytes)
        
        # Check that the decoded key is exactly 32 bytes long
        result = len(decoded) == 32
        if result:
            logger.debug("Key validation successful")
        else:
            logger.warning(f"Key validation failed: incorrect length ({len(decoded)} bytes instead of 32)")
        return result
    except Exception as e:
        logger.warning(f"Key validation failed: not valid base64. Error: {type(e).__name__}")
        return False