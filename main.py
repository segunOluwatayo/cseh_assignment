"""
Main entry point for the Secure File Encryptor application.
This module initializes all components and launches the GUI.
"""

import os
import sys
import traceback
import tkinter as tk
from tkinter import messagebox

# Import application modules
import config
from log_manager import initialize_logger, logger, log_error
from ui_manager import EncryptionApp

def check_environment():
    """
    Performs startup checks to ensure the application can run properly:
    """
    try:
        # Check if log directory exists or create it
        log_dir = os.path.dirname(config.LOG_FILE_PATH)
        if log_dir and not os.path.exists(log_dir):
            os.makedirs(log_dir)
        
        # Verify log file can be written to
        log_file = config.LOG_FILE_PATH
        test_access = os.access(os.path.dirname(log_file), os.W_OK)
        if not test_access:
            print(f"Warning: Cannot write to log directory: {os.path.dirname(log_file)}")
            return False
            
        # Import required modules to ensure they're available
        try:
            from cryptography.fernet import Fernet
        except ImportError:
            print("Error: Required dependency 'cryptography' not found. Please install it with:")
            print("pip install cryptography")
            return False
            
        return True
    except Exception as e:
        print(f"Environment check failed: {str(e)}")
        return False

def handle_exception(exc_type, exc_value, exc_traceback):
    """
    Global exception handler to catch unhandled exceptions
    """
    # Log the exception
    if logger:
        exception_details = ''.join(traceback.format_exception(exc_type, exc_value, exc_traceback))
        log_error(f"Unhandled exception: {exception_details}", "CriticalError")
    
    # Show error message to user if GUI is available
    try:
        messagebox.showerror(
            "Application Error",
            "An unexpected error occurred. Please check the logs for details."
        )
    except:
        # If messagebox fails, fall back to console
        print("Critical Error: Application encountered an unhandled exception.")
        print(f"Error details: {exc_value}")
    
    sys.exit(1)

def initialize_application():
    """
    Sets up the application
    """
    # Initialize logging first
    initialize_logger()
    logger.info("Application starting...")
    
    # Create and configure the root window
    root = tk.Tk()
    root.title(config.APP_TITLE)
    root.geometry(f"{config.WINDOW_SIZE[0]}x{config.WINDOW_SIZE[1]}")
    root.configure(bg=config.THEME_COLOR)
    
    # Create icon if available
    try:
        icon_path = os.path.join(os.path.dirname(__file__), "assets", "icon")
        if os.path.exists(icon_path):
            root.iconbitmap(icon_path)
        pass
    except Exception as e:
        logger.warning(f"Could not set application icon: {e}")
    
    # Create the application instance
    app = EncryptionApp(root)
    
    # Set up the window close handler
    def on_closing():
        logger.info("Application shutting down...")
        root.destroy()
    
    root.protocol("WM_DELETE_WINDOW", on_closing)
    
    return root, app

def main():
    """
    Main entry point for the application.
    Initializes all components and starts the main event loop.
    """
    # Register the global exception handler
    sys.excepthook = handle_exception
    
    # Perform environment checks
    if not check_environment():
        messagebox.showerror(
            "Startup Error",
            "The application could not start due to environment configuration issues.\n"
            "Please check that you have the required permissions and dependencies."
        )
        return 1
    
    try:
        # Initialize the application
        root, app = initialize_application()
        
        # Log startup success
        logger.info(f"Application initialized successfully. Version: {getattr(config, 'APP_VERSION', 'Unknown')}")
        
        # Start the main loop
        root.mainloop()
        
        return 0
    except Exception as e:
        if 'logger' in globals() and logger:
            log_error(f"Failed to initialize application: {str(e)}", "StartupError")
        
        # Show error and exit if initialization fails
        messagebox.showerror(
            "Startup Error",
            f"The application failed to start: {str(e)}"
        )
        return 1

if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code)