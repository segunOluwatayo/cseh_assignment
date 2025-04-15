"""
This module implements the GUI components for the encryption/decryption tool using Tkinter.
It integrates with the crypto, file, and logging modules to allow users to select files,
encrypt/decrypt them, and receive secure, clear notifications regarding the operations.
"""

import tkinter as tk
from tkinter import filedialog, messagebox
import config
import file_handler
import crypto_engine
import log_manager

class EncryptionApp:
    def __init__(self, root):
        """
        Initializes the main application window, sets up the layout and style,
        and initializes UI components.
        """
        self.root = root
        self.root.title(config.APP_TITLE)
        self.root.geometry(f"{config.WINDOW_SIZE[0]}x{config.WINDOW_SIZE[1]}")
        self.root.configure(bg=config.THEME_COLOR)
        
        # Variable to hold the currently selected file path
        self.file_path = ""
        
        # Initialize UI components
        self.create_widgets()

    def create_widgets(self):
        """
        Creates and positions all UI elements 
        """
        # --- File Selection Frame ---
        file_frame = tk.Frame(self.root, bg=config.THEME_COLOR, padx=config.PADDING, pady=config.PADDING)
        file_frame.pack(fill='x', pady=(10, 0))
        
        self.file_label = tk.Label(file_frame, text="No file selected", bg=config.THEME_COLOR)
        self.file_label.pack(side='left', fill='x', expand=True)
        
        browse_button = tk.Button(file_frame, text=config.BROWSE_BUTTON_TEXT, command=self.browse_for_file)
        browse_button.pack(side='right')

        # --- Key Entry Frame (for decryption) ---
        key_frame = tk.Frame(self.root, bg=config.THEME_COLOR, padx=config.PADDING, pady=config.PADDING)
        key_frame.pack(fill='x', pady=(10, 0))
        
        self.key_label = tk.Label(key_frame, text=config.KEY_PROMPT_TEXT, bg=config.THEME_COLOR)
        self.key_label.pack(side='left')
        
        self.key_entry = tk.Entry(key_frame)
        self.key_entry.pack(side='left', fill='x', expand=True)

        # --- Buttons Frame ---
        button_frame = tk.Frame(self.root, bg=config.THEME_COLOR, padx=config.PADDING, pady=config.PADDING)
        button_frame.pack(pady=(10, 0))
        
        encrypt_button = tk.Button(button_frame, text=config.ENCRYPT_BUTTON_TEXT, command=self.encrypt_file)
        encrypt_button.pack(side='left', padx=5)
        
        decrypt_button = tk.Button(button_frame, text=config.DECRYPT_BUTTON_TEXT, command=self.decrypt_file)
        decrypt_button.pack(side='left', padx=5)

        # --- Status Label ---
        self.status_label = tk.Label(self.root, text=config.STATUS_READY, bg=config.THEME_COLOR)
        self.status_label.pack(pady=(10, 0))

    def browse_for_file(self):
        """
        Opens a file selection dialog, validates file accessibility,
        updates the UI to display the selected file path, and logs the operation.
        """
        file_path = filedialog.askopenfilename(filetypes=config.SUPPORTED_FILE_TYPES)
        if file_path:
            # Validate file access using file_handler
            if file_handler.validate_file_access(file_path):
                self.file_path = file_path
                self.file_label.config(text=file_path)
                self.update_status("File selected: " + file_path)
            else:
                self.show_error_message(config.ERROR_FILE_ACCESS_MESSAGE)

    def encrypt_file(self):
        """
        Handles the encryption process
        """
        if not self.file_path:
            self.show_error_message("No file selected for encryption.")
            return

        self.update_status(config.STATUS_ENCRYPTING)
        try:
            # Read file data
            data = file_handler.read_file_binary(self.file_path)
            # Encrypt data; generate a key if not provided
            encrypted_data, key = crypto_engine.encrypt_data(data)
            # Write encrypted data back to file
            if file_handler.write_file_binary(self.file_path, encrypted_data):
                log_manager.log_operation(self.file_path, "encrypt")
                self.update_status(config.STATUS_SUCCESS_ENCRYPT)
                self.show_success_message("File encrypted successfully. SAVE YOUR DECRYPTION KEY!")
                self.display_key(key)
            else:
                self.show_error_message("Failed to write encrypted data to file.")
        except Exception as e:
            log_manager.log_error(str(e), "encryption_error")
            self.show_error_message("Encryption failed: " + str(e))

    def decrypt_file(self):
        """
        Handles the decryption process with improved key handling
        """
        if not self.file_path:
            self.show_error_message("No file selected for decryption.")
            return

        key = self.key_entry.get().strip()
        if not key:
            self.show_error_message("Please enter the decryption key.")
            return

        # Validate key format before attempting decryption
        if not crypto_engine.validate_decryption_key(key):
            self.show_error_message(
                "The decryption key appears to be invalid.\n"
                "Please make sure you've copied the entire key correctly."
            )
            return

        self.update_status(config.STATUS_DECRYPTING)
        try:
            # Read encrypted file data
            encrypted_data = file_handler.read_file_binary(self.file_path)
            
            # Create a backup before attempting decryption
            if config.BACKUP_ENABLED:
                backup_path = file_handler.create_backup(self.file_path)
                log_manager.log_operation(backup_path, "backup")
                
            # Decrypt the data
            try:
                decrypted_data = crypto_engine.decrypt_data(encrypted_data, key)
            except ValueError as e:
                # Handle decryption failure specifically
                self.show_error_message(
                    "Decryption failed. This usually means:\n"
                    "1. The key is incorrect\n"
                    "2. The file has been corrupted\n"
                    "3. The file is not encrypted\n\n"
                    "Check if you copied the entire key correctly."
                )
                return
                
            # Write the decrypted data back to file
            if file_handler.write_file_binary(self.file_path, decrypted_data):
                log_manager.log_operation(self.file_path, "decrypt")
                self.update_status(config.STATUS_SUCCESS_DECRYPT)
                self.show_success_message("File decrypted successfully.")
            else:
                self.show_error_message("Failed to write decrypted data to file.")
        except Exception as e:
            log_manager.log_error(str(e), "decryption_error")
            self.show_error_message(f"Decryption failed: {str(e)}")

    def display_key(self, key):
        """
        Displays the decryption key in a secure, temporary pop-up window.
        The key can be copied via a button and will auto-close after a set timeout.
        """
        key_window = tk.Toplevel(self.root)
        key_window.title("Decryption Key")
        key_window.geometry("500x200")
        key_window.configure(bg=config.THEME_COLOR)
        
        # Make window modal to force attention
        key_window.transient(self.root)
        key_window.grab_set()
        
        warning_label = tk.Label(
            key_window, 
            text="WARNING: Save this key in a secure location!\nYou will need it to decrypt your file later.",
            fg="red",
            bg=config.THEME_COLOR,
            font=("Arial", 10, "bold")
        )
        warning_label.pack(pady=10)
        
        instruction = tk.Label(
            key_window, 
            text="This is your decryption key:",
            bg=config.THEME_COLOR
        )
        instruction.pack(pady=5)
        
        # Use a Text widget for better visibility and selection
        key_text = tk.Text(key_window, height=2, width=60)
        key_text.insert("1.0", key)
        key_text.config(state='normal', bg="white", fg="black")
        key_text.pack(pady=5, padx=20)
        
        # Select all text by default for easier copying
        key_text.tag_add("sel", "1.0", "end")
        key_text.focus_set()
        
        def copy_to_clipboard():
            # Clear clipboard and add the key
            self.root.clipboard_clear()
            self.root.clipboard_append(key)
            confirm_label.config(text="Key copied to clipboard!")
        
        copy_button = tk.Button(
            key_window, 
            text="Copy to Clipboard",
            command=copy_to_clipboard
        )
        copy_button.pack(pady=5)
        
        confirm_label = tk.Label(key_window, text="", bg=config.THEME_COLOR)
        confirm_label.pack(pady=5)
        
        close_button = tk.Button(
            key_window, 
            text="I've Saved My Key", 
            command=key_window.destroy
        )
        close_button.pack(pady=5)
        
        # Auto-dismiss the key window after timeout
        key_window.after(config.KEY_DISPLAY_TIMEOUT_SECONDS * 1000, key_window.destroy)

    def show_error_message(self, message):
        """
        Displays an error pop-up and updates the status label with an error message.
        """
        messagebox.showerror("Error", message)
        self.update_status(message, is_error=True)

    def show_success_message(self, message):
        """
        Displays a success pop-up and updates the status label with a success message.
        """
        messagebox.showinfo("Success", message)
        self.update_status(message)

    def update_status(self, status_text, is_error=False):
        """
        Updates the status label in the main window.
        """
        color = config.ERROR_COLOR if is_error else config.SUCCESS_COLOR
        self.status_label.config(text=status_text, fg=color)


if __name__ == "__main__":
    # Initialize and start the Tkinter main loop if this module is executed directly.
    root = tk.Tk()
    app = EncryptionApp(root)
    root.mainloop()
