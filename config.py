import os

# === Application Information ===
APP_VERSION = "1.0.0"
APP_TITLE = "Secure File Encryptor"

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
WINDOW_SIZE = (950, 650)
MIN_WINDOW_SIZE = (640, 480)
PADDING = 10
MAIN_FRAME_PADDING = (20, 20, 20, 20)
CARD_BG_COLOR = "#ffffff"
ENTRY_BG_COLOR = "#ffffff"
SEPARATOR_COLOR = "#d0d0d0"
BUTTON_COLOR = "#f0f0f0"
ACCENT_COLOR = "#4a7abc"
ERROR_COLOR = "#e74c3c"
SUCCESS_COLOR = "#2ecc71"
THEME_COLOR = "#f0f0f0"

# === Fonts ===
FONT_MAIN = ("Segoe UI", 10)
FONT_MAIN_BOLD = ("Segoe UI", 10, "bold")
FONT_HEADER = ("Segoe UI", 12, "bold")
FONT_STATUS = ("Segoe UI", 9)
FONT_MONO = ("Consolas", 11)

# === UI Text Constants ===
ENCRYPT_BUTTON_TEXT = "Encrypt File"
DECRYPT_BUTTON_TEXT = "Decrypt File"
BROWSE_BUTTON_TEXT = "Browse..."
KEY_PROMPT_TEXT = "Enter Decryption Key:"
KEY_LABEL_TEXT = "Your Decryption Key:"
KEY_POPUP_HEADER = "IMPORTANT - SAVE YOUR DECRYPTION KEY"
KEY_POPUP_SIZE = "850x520"
COPY_BUTTON_TEXT = "Copy to Clipboard"
COPY_BUTTON_SUCCESS_TEXT = "Key Copied!"
CLOSE_BUTTON_TEXT = "I've Saved My Key"
KEY_TIMEOUT_MSG_PREFIX = "This window will close in"
KEY_TIMEOUT_MSG_SUFFIX = "seconds."
KEY_CLOSE_CONFIRMATION = (
    "You haven't copied the key to clipboard. Are you sure you've saved it elsewhere?\n\n"
    "Without this key, you CANNOT decrypt your file."
)

# === Status and Error Messages ===
STATUS_READY = "Ready to encrypt or decrypt files."
STATUS_ENCRYPTING = "Encrypting file... Please wait."
STATUS_DECRYPTING = "Decrypting file... Please wait."
STATUS_SUCCESS_ENCRYPT = "File encrypted successfully. SAVE YOUR DECRYPTION KEY!"
STATUS_SUCCESS_DECRYPT = "File decrypted successfully."
SUCCESS_MESSAGE_DECRYPTED = "File decrypted successfully."

ERROR_INVALID_KEY_MESSAGE = "Invalid decryption key. Please try again."
ERROR_FILE_ACCESS_MESSAGE = "Unable to access file. Check permissions and try again."
ERROR_UNSUPPORTED_FILE_MESSAGE = "This file type is not supported."
ERROR_FILE_NOT_FOUND = "The selected file could not be found."
ERROR_PERMISSION_DENIED = "Permission denied. Cannot access the file."
ERROR_FILE_TOO_LARGE = f"File exceeds the maximum size limit of {MAX_FILE_SIZE_MB}MB."
ERROR_DECRYPTION_FAILED = "Decryption failed. "
ERROR_ENCRYPTION_FAILED = "Encryption failed. "
ERROR_DECRYPTION_HINT = (
    "Decryption failed. This usually means:\n"
    "1. The key is incorrect\n"
    "2. The file has been corrupted\n"
    "3. The file is not encrypted\n\n"
    "Check if you copied the entire key correctly."
)
ERROR_WRITE_ENCRYPTED_FILE = "Failed to write encrypted data to file."
ERROR_WRITE_DECRYPTED_FILE = "Failed to write decrypted data to file."
ERROR_NO_FILE_SELECTED_ENCRYPT = "No file selected for encryption."
ERROR_NO_FILE_SELECTED_DECRYPT = "No file selected for decryption."
ERROR_EMPTY_KEY = "Please enter the decryption key."

# === File Support ===
SUPPORTED_FILE_TYPES = [("All Files", "*.*")]

# Define a list of supported extensions for programmatic checking
SUPPORTED_EXTENSIONS = [
    ".txt", 
    ".pdf", 
    ".jpg", ".jpeg", ".png", ".gif",
    ".doc", ".docx", ".odt",
    ".xls", ".xlsx", ".csv"
]

# Update the error message for unsupported file types
ERROR_UNSUPPORTED_FILE_TYPE = "This file type is not supported. Please select a file with one of the following extensions: {}"

# === Key Display Colors ===
POPUP_BG_COLOR = "#ffffff"
KEY_BG_COLOR = "#f0f8ff"
KEY_FG_COLOR = "#000000"

# === Warning Message ===
KEY_WARNING_MESSAGE = (
    "This key will be shown ONLY ONCE and is required to decrypt your file.\n"
    "Without this key, your file CANNOT be recovered."
)