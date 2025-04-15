"""
This module implements the GUI components for the encryption/decryption tool using Tkinter.
It integrates with the crypto, file, and logging modules to allow users to select files,
encrypt/decrypt them, and receive secure, clear notifications regarding the operations.
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import os
import config
import file_handler
import crypto_engine
import log_manager

class EncryptionApp:
    def __init__(self, root):
        self.root = root
        self.root.configure(bg=config.THEME_COLOR)
        self.root.title(config.APP_TITLE)
        self.root.geometry(f"{config.WINDOW_SIZE[0]}x{config.WINDOW_SIZE[1]}")
        self.root.minsize(*config.MIN_WINDOW_SIZE)

        self.style = ttk.Style()
        self.style.theme_use('clam')

        self.configure_styles()

        self.file_path = ""

        self.main_frame = ttk.Frame(self.root, padding=config.MAIN_FRAME_PADDING)
        self.main_frame.pack(fill='both', expand=True)

        self.create_widgets()

    def configure_styles(self):
        self.style.configure('TLabel', font=config.FONT_MAIN)
        self.style.configure('Header.TLabel', font=config.FONT_HEADER)
        self.style.configure('Status.TLabel', font=config.FONT_STATUS)

        self.style.configure('TButton', font=config.FONT_MAIN, background=config.BUTTON_COLOR)
        self.style.configure('Accent.TButton', font=config.FONT_MAIN_BOLD, background=config.ACCENT_COLOR)

        self.style.configure('Card.TFrame', background=config.CARD_BG_COLOR, relief='raised', borderwidth=1)

        self.style.configure('TEntry', font=config.FONT_MAIN, fieldbackground=config.ENTRY_BG_COLOR)
        self.style.configure('TSeparator', background=config.SEPARATOR_COLOR)
        self.style.configure('TFrame', background=config.THEME_COLOR)
        self.style.configure('TLabelFrame', background=config.THEME_COLOR)
        self.style.configure('TLabelFrame.Label', background=config.THEME_COLOR)


    def create_widgets(self):
        title_frame = ttk.Frame(self.main_frame)
        title_frame.pack(fill='x', pady=(0, 15))

        title_label = ttk.Label(title_frame, text=config.APP_TITLE, style='Header.TLabel')
        title_label.pack(side='left')

        version_label = ttk.Label(title_frame, text=f"v{config.APP_VERSION}", style='Status.TLabel')
        version_label.pack(side='right', padx=(10, 0))

        separator1 = ttk.Separator(self.main_frame, orient='horizontal')
        separator1.pack(fill='x', pady=(0, 15))

        file_selection_frame = ttk.LabelFrame(self.main_frame, text="File Selection", padding=(10, 5))
        file_selection_frame.pack(fill='x', pady=(0, 15))

        self.file_path_var = tk.StringVar(value="No file selected")
        file_entry_frame = ttk.Frame(file_selection_frame)
        file_entry_frame.pack(fill='x', expand=True, pady=5)

        self.file_entry = ttk.Entry(file_entry_frame, textvariable=self.file_path_var, state='readonly')
        self.file_entry.pack(side='left', fill='x', expand=True, padx=(0, 5))

        browse_button = ttk.Button(file_entry_frame, text=config.BROWSE_BUTTON_TEXT, command=self.browse_for_file)
        browse_button.pack(side='right')

        key_frame = ttk.LabelFrame(self.main_frame, text=config.KEY_PROMPT_TEXT, padding=(config.PADDING, config.PADDING // 2))
        key_frame.pack(fill='x', pady=(0, 15))

        key_entry_frame = ttk.Frame(key_frame)
        key_entry_frame.pack(fill='x', expand=True, pady=5)

        self.key_var = tk.StringVar()
        self.key_entry = ttk.Entry(key_entry_frame, textvariable=self.key_var, width=40)
        self.key_entry.pack(side='left', fill='x', expand=True)

        clear_key_button = ttk.Button(key_entry_frame, text="Clear", command=lambda: self.key_var.set(""), width=8)
        clear_key_button.pack(side='right', padx=(5, 0))

        button_frame = ttk.Frame(self.main_frame)
        button_frame.pack(fill='x', pady=(0, 15))

        spacer = ttk.Frame(button_frame)
        spacer.pack(side='left', fill='x', expand=True)

        encrypt_button = ttk.Button(button_frame, text=config.ENCRYPT_BUTTON_TEXT, style='Accent.TButton', command=self.encrypt_file)
        encrypt_button.pack(side='left', padx=5)

        decrypt_button = ttk.Button(button_frame, text=config.DECRYPT_BUTTON_TEXT, style='Accent.TButton', command=self.decrypt_file)
        decrypt_button.pack(side='left', padx=5)

        status_frame = ttk.Frame(self.main_frame, style='Card.TFrame', padding=(10, 10))
        status_frame.pack(fill='x')

        status_header = ttk.Label(status_frame, text="Status:", style='Header.TLabel')
        status_header.pack(anchor='w')

        self.status_label = ttk.Label(status_frame, text=config.STATUS_READY, wraplength=500, style='Status.TLabel')
        self.status_label.pack(anchor='w', pady=(5, 0))

    def browse_for_file(self):
        file_path = filedialog.askopenfilename(filetypes=config.SUPPORTED_FILE_TYPES)
        if file_path:
            if file_handler.validate_file_access(file_path):
                self.file_path = file_path
                self.file_path_var.set(file_path)
                self.update_status("File selected: " + os.path.basename(file_path))
            else:
                self.show_error_message(config.ERROR_FILE_ACCESS_MESSAGE)

    def encrypt_file(self):
        if not self.file_path:
            self.show_error_message(config.ERROR_NO_FILE_SELECTED_ENCRYPT)
            return

        self.update_status(config.STATUS_ENCRYPTING)
        self.root.update()

        try:
            data = file_handler.read_file_binary(self.file_path)
            encrypted_data, key = crypto_engine.encrypt_data(data)
            if file_handler.write_file_binary(self.file_path, encrypted_data):
                log_manager.log_operation(self.file_path, "encrypt")
                self.update_status(config.STATUS_SUCCESS_ENCRYPT, is_success=True)
                self.display_key(key)
            else:
                self.show_error_message(config.ERROR_WRITE_ENCRYPTED_FILE)
        except Exception as e:
            log_manager.log_error(str(e), "encryption_error")
            self.show_error_message(config.ERROR_ENCRYPTION_FAILED + str(e))

    def decrypt_file(self):
        if not self.file_path:
            self.show_error_message(config.ERROR_NO_FILE_SELECTED_DECRYPT)
            return

        key = self.key_var.get().strip()
        if not key:
            self.show_error_message(config.ERROR_EMPTY_KEY)
            return

        if not crypto_engine.validate_decryption_key(key):
            self.show_error_message(config.ERROR_INVALID_KEY_MESSAGE)
            return

        self.update_status(config.STATUS_DECRYPTING)
        self.root.update()

        try:
            encrypted_data = file_handler.read_file_binary(self.file_path)
            if config.BACKUP_ENABLED:
                backup_path = file_handler.create_backup(self.file_path)
                log_manager.log_operation(backup_path, "backup")

            try:
                decrypted_data = crypto_engine.decrypt_data(encrypted_data, key)
            except ValueError:
                self.show_error_message(config.ERROR_DECRYPTION_HINT)
                return

            if file_handler.write_file_binary(self.file_path, decrypted_data):
                log_manager.log_operation(self.file_path, "decrypt")
                self.update_status(config.STATUS_SUCCESS_DECRYPT, is_success=True)
                self.show_success_message(config.SUCCESS_MESSAGE_DECRYPTED)
                self.key_var.set("")
            else:
                self.show_error_message(config.ERROR_WRITE_DECRYPTED_FILE)
        except Exception as e:
            log_manager.log_error(str(e), "decryption_error")
            self.show_error_message(config.ERROR_DECRYPTION_FAILED + str(e))

    def display_key(self, key):
        key_window = tk.Toplevel(self.root)
        key_window.title("Decryption Key")
        key_window.geometry(config.KEY_POPUP_SIZE)
        key_window.configure(bg=config.POPUP_BG_COLOR)

        key_window.transient(self.root)
        key_window.grab_set()

        main_frame = ttk.Frame(key_window, padding=(20, 20, 20, 20))
        main_frame.pack(fill='both', expand=True)

        title_label = ttk.Label(main_frame, text=config.KEY_POPUP_HEADER, style='Header.TLabel', foreground="red")
        title_label.pack(pady=(0, 15))

        warning_frame = ttk.Frame(main_frame, style='Card.TFrame', padding=(10, 10))
        warning_frame.pack(fill='x', pady=(0, 15))

        warning_label = ttk.Label(warning_frame, text=config.KEY_WARNING_MESSAGE, wraplength=480, justify='center')
        warning_label.pack()

        key_label = ttk.Label(main_frame, text=config.KEY_LABEL_TEXT, style='Header.TLabel')
        key_label.pack(pady=(0, 5))

        key_frame = ttk.Frame(main_frame, padding=(2, 2), style='Card.TFrame')
        key_frame.pack(fill='x', pady=(0, 15))

        key_text = tk.Text(key_frame, height=2, width=60, font=config.FONT_MONO, bd=0)
        key_text.insert("1.0", key)
        key_text.config(bg=config.KEY_BG_COLOR, fg=config.KEY_FG_COLOR)
        key_text.pack(pady=5, padx=5)
        key_text.tag_add("sel", "1.0", "end")
        key_text.focus_set()

        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill='x', pady=(0, 10))

        self.copied = tk.BooleanVar(value=False)

        def copy_to_clipboard():
            self.root.clipboard_clear()
            self.root.clipboard_append(key)
            self.copied.set(True)
            copy_button.config(text=config.COPY_BUTTON_SUCCESS_TEXT)
            key_text.tag_add("sel", "1.0", "end")

        copy_button = ttk.Button(button_frame, text=config.COPY_BUTTON_TEXT, command=copy_to_clipboard, style='Accent.TButton')
        copy_button.pack(side='left', padx=5)

        close_button = ttk.Button(button_frame, text=config.CLOSE_BUTTON_TEXT, command=key_window.destroy)
        close_button.pack(side='right', padx=5)

        timer_var = tk.StringVar(value=f"{config.KEY_TIMEOUT_MSG_PREFIX} {config.KEY_DISPLAY_TIMEOUT_SECONDS} {config.KEY_TIMEOUT_MSG_SUFFIX}")
        timer_label = ttk.Label(main_frame, textvariable=timer_var, style='Status.TLabel')
        timer_label.pack(side='bottom', pady=(10, 0))

        remaining_time = config.KEY_DISPLAY_TIMEOUT_SECONDS

        def update_timer():
            nonlocal remaining_time
            remaining_time -= 1
            if remaining_time <= 0:
                key_window.destroy()
            else:
                timer_var.set(f"{config.KEY_TIMEOUT_MSG_PREFIX} {remaining_time} {config.KEY_TIMEOUT_MSG_SUFFIX}")
                key_window.after(1000, update_timer)

        key_window.after(1000, update_timer)

        def on_close_check():
            if not self.copied.get():
                if messagebox.askyesno("Warning", config.KEY_CLOSE_CONFIRMATION, icon=messagebox.WARNING):
                    key_window.destroy()
            else:
                key_window.destroy()

        key_window.protocol("WM_DELETE_WINDOW", on_close_check)

        key_window.update_idletasks()
        width = key_window.winfo_width()
        height = key_window.winfo_height()
        x = (key_window.winfo_screenwidth() // 2) - (width // 2)
        y = (key_window.winfo_screenheight() // 2) - (height // 2)
        key_window.geometry(f'{width}x{height}+{x}+{y}')

    def show_error_message(self, message):
        messagebox.showerror("Error", message)
        self.update_status(message, is_error=True)

    def show_success_message(self, message):
        messagebox.showinfo("Success", message)
        self.update_status(message, is_success=True)

    def update_status(self, status_text, is_error=False, is_success=False):
        if is_error:
            self.status_label.configure(foreground=config.ERROR_COLOR)
        elif is_success:
            self.status_label.configure(foreground=config.SUCCESS_COLOR)
        else:
            self.status_label.configure(foreground="black")
        self.status_label.configure(text=status_text)


if __name__ == "__main__":
    root = tk.Tk()
    app = EncryptionApp(root)
    root.mainloop()
