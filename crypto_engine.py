"""

This module handles all encryption and decryption operations using symmetric key cryptography.
It leverages the cryptography package's Fernet implementation to provide strong cryptographic
guarantees. The module includes functions to generate keys, encrypt data, decrypt data, and validate keys.
"""

from cryptography.fernet import Fernet, InvalidToken
import base64

def generate_encryption_key():
    """
    Generates a cryptographically secure random key.
    """
    key_bytes = Fernet.generate_key()  # Generates a URL-safe base64-encoded key (bytes)
    key_str = key_bytes.decode('utf-8')  # Convert bytes to a string for easier handling/storage
    return key_str

def encrypt_data(data, key=None):
    """
    Encrypts binary data using Fernet symmetric encryption.
    """
    if key is None:
        key = generate_encryption_key()
    else:
        if not validate_decryption_key(key):
            raise ValueError("Invalid encryption key provided.")
    
    # Create a Fernet object with the given key. Fernet expects the key as bytes.
    fernet = Fernet(key.encode('utf-8'))
    encrypted_data = fernet.encrypt(data)
    return encrypted_data, key

def decrypt_data(encrypted_data, key):
    """
    Decrypts encrypted binary data using the provided decryption key.
    """
    if not validate_decryption_key(key):
        raise ValueError("Invalid decryption key provided.")
    
    fernet = Fernet(key.encode('utf-8'))
    try:
        decrypted_data = fernet.decrypt(encrypted_data)
    except InvalidToken as e:
        # Raise an informative error that does not leak sensitive details.
        raise ValueError("Decryption failed. Possibly due to an incorrect key or corrupted data.") from e
    
    return decrypted_data

def validate_decryption_key(key):
    """
    Validates the structure and format of the decryption key.
    The key must be a URL-safe base64-encoded string of 32 bytes.
    """
    if not isinstance(key, str):
        return False
    
    try:
        # Attempt to decode the key; this ensures it is properly base64 encoded.
        key_bytes = key.encode('utf-8')
        decoded = base64.urlsafe_b64decode(key_bytes)
    except Exception:
        return False

    # Check that the decoded key is exactly 32 bytes long.
    return len(decoded) == 32
