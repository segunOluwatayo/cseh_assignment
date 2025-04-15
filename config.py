import os

# === Application Information ===
APP_VERSION = "1.0.0"  # Version information for logging and display

# === Logging Configuration ===
LOG_FILE_PATH = os.path.join(os.getcwd(), "encryption_app.log")
LOG_FORMAT = "%(asctime)s - %(levelname)s - %(message)s - %(filename)s:%(lineno)d"
LOG_LEVEL = "INFO"

# === File Processing Configuration ===
MAX_FILE_SIZE_MB = 100
READ_BLOCK_SIZE = 4096
BACKUP_ENABLED = True

# === Encryption Configuration ===
KEY_DISPLAY_TIMEOUT_SECONDS = 60
ENCRYPTION_STRENGTH = "strong" 

# === UI/Window Configuration ===
APP_TITLE = "Secure File Encryptor"
WINDOW_SIZE = (700, 500)
PADDING = 10
THEME_COLOR = "#f0f0f0"
ACCENT_COLOR = "#4a7abc"
ERROR_COLOR = "#e74c3c"
SUCCESS_COLOR = "#2ecc71"

# === UI Text Constants ===
ENCRYPT_BUTTON_TEXT = "Encrypt File"
DECRYPT_BUTTON_TEXT = "Decrypt File"
BROWSE_BUTTON_TEXT = "Browse..."
KEY_PROMPT_TEXT = "Enter Decryption Key:"
STATUS_READY = "Ready to encrypt or decrypt files."
STATUS_ENCRYPTING = "Encrypting file... Please wait."
STATUS_DECRYPTING = "Decrypting file... Please wait."
STATUS_SUCCESS_ENCRYPT = "File encrypted successfully. SAVE YOUR DECRYPTION KEY!"
STATUS_SUCCESS_DECRYPT = "File decrypted successfully."
ERROR_INVALID_KEY_MESSAGE = "Invalid decryption key. Please try again."
ERROR_FILE_ACCESS_MESSAGE = "Unable to access file. Check permissions and try again."
ERROR_UNSUPPORTED_FILE_MESSAGE = "This file type is not supported."

# === Error Messages and Codes ===
ERROR_FILE_NOT_FOUND = "The selected file could not be found."
ERROR_PERMISSION_DENIED = "Permission denied. Cannot access the file."
ERROR_FILE_TOO_LARGE = f"File exceeds the maximum size limit of {MAX_FILE_SIZE_MB}MB."
ERROR_DECRYPTION_FAILED = "Decryption failed. The key may be incorrect or the file is corrupted."

SUCCESS = 0
ERROR_INVALID_KEY = 1
ERROR_FILE_ACCESS = 2
ERROR_FILE_TOO_LARGE_CODE = 3
ERROR_ENCRYPTION_FAILED = 4
ERROR_DECRYPTION_FAILED_CODE = 5

# === File Support ===
SUPPORTED_FILE_TYPES = [("All Files", "*.*")]
