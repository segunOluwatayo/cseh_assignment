
# Secure File Encryptor

A secure file encryption/decryption application that performs **in-place encryption** for various file types. The application uses strong cryptographic methods to ensure your files remain private and secure.

## 🔐 Features

- **Secure Encryption**: Uses symmetric encryption (Fernet) for file security  
- **In-place Operation**: Encrypts and decrypts files without creating duplicates  
- **Random Key Generation**: Creates a unique random key for each encryption operation  
- **One-time Key Display**: Shows the decryption key only once after encryption  
- **Secure Logging**: Maintains a log of operations without exposing sensitive key data  
- **User-friendly Interface**: Intuitive GUI for easy file selection and processing  
- **File Type Validation**: Verifies supported file types and provides clear error messages  
- **Backup Creation**: Creates backups before decryption as a safety measure  

## 📁 Supported File Types

- Text files: `.txt`  
- PDFs: `.pdf`  
- Images: `.jpg`, `.jpeg`, `.png`, `.gif`  
- Documents: `.doc`, `.docx`, `.odt`  
- Spreadsheets: `.xls`, `.xlsx`, `.csv`

## 🖥️ OS Compatibility

This application is built and tested on **Windows**.

---

## 🧪 Installation

### ✅ Prerequisites

- Python 3.8 or higher  
- `pip` (Python package installer)

### 🛠️ From Source

```bash
# Clone the repository
git clone https://github.com/segunOluwatayo/cseh_assignment.git
cd cseh_assignment

# Create a virtual environment (recommended)
python -m venv venv
venv\Scripts\activate 

# Install dependencies
pip install -r requirements.txt

# Run the application
python main.py
