import os

# === Logging Configuration ===
LOG_FILE_PATH = os.path.join(os.getcwd(), "encryption_app.log")
LOG_FORMAT = "%(asctime)s - %(levelname)s - %(message)s"
LOG_LEVEL = "INFO"

# === File Configuration ===
MAX_FILE_SIZE_MB = 100  # Increased to 100MB for larger files
BACKUP_ENABLED = True  # Create temporary backup during decryption

# === Encryption Configuration ===
KEY_DISPLAY_TIMEOUT_SECONDS = 60  # How long to show the key before auto-dismissing
ENCRYPTION_STRENGTH = "strong"  # Options: "standard", "strong" (affects key generation)

# === UI/Window Configuration ===
APP_TITLE = "Secure File Encryptor"
WINDOW_SIZE = (600, 400)  # Appropriate size for an encryption UI
THEME_COLOR = "#f0f0f0"  # Light gray background
ACCENT_COLOR = "#4a7abc"  # Blue accent for buttons
ERROR_COLOR = "#e74c3c"  # Red for errors
SUCCESS_COLOR = "#2ecc71"  # Green for success messages

# === UI Text Configuration ===
STATUS_READY = "Ready to encrypt or decrypt files."
STATUS_ENCRYPTING = "Encrypting file... Please wait."
STATUS_DECRYPTING = "Decrypting file... Please wait."
STATUS_SUCCESS_ENCRYPT = "File encrypted successfully. SAVE YOUR DECRYPTION KEY!"
STATUS_SUCCESS_DECRYPT = "File decrypted successfully."

# === Error Messages ===
ERROR_FILE_NOT_FOUND = "The selected file could not be found."
ERROR_PERMISSION_DENIED = "Permission denied. Cannot access the file."
ERROR_INVALID_KEY = "Invalid decryption key format. Please check and try again."
ERROR_DECRYPTION_FAILED = "Decryption failed. The key may be incorrect or the file is corrupted."
ERROR_FILE_TOO_LARGE = f"File exceeds the maximum size limit of {MAX_FILE_SIZE_MB}MB."

# === File Support ===
# For encryption, we support all file types since encryption works on binary data
# This is just for display in file dialogs
SUPPORTED_FILE_TYPES = [("All Files", "*.*")]