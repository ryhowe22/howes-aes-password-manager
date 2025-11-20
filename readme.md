Howe’s AES Password Manager

A local desktop password manager built with Python, Tkinter, and AES-256 encryption. The application stores login credentials in an encrypted vault file, protected with a master password. It is intended as a demonstration of secure application architecture and local-only credential storage.

Overview

This application provides a graphical interface for securely storing passwords using modern encryption techniques. Credentials are stored in a JSON structure that is fully encrypted before being written to disk. Decryption requires the user’s master password.

The interface is implemented with Tkinter and kept intentionally simple. The program is packaged into a single-file Windows executable using PyInstaller, with full support for loading external PNG resources (such as the window icon) in both development and packaged environments.

Encryption Details

The security model uses the following components:

AES-256 in CBC mode for all vault encryption

PBKDF2-HMAC-SHA256 to derive an encryption key from the master password

A random 16-byte salt stored in a configuration file

A random IV generated for each encryption session

All sensitive data is stored exclusively in encrypted form in the vault file

This ensures no plaintext passwords are ever written to disk.

Features

Master-password-protected vault

Add, view, delete, and save entries

Encrypted vault stored locally as vault.enc

Dark-theme Tkinter interface

Window icon loaded from PNG using a PyInstaller-safe resource method

Packaged into a single executable with no console window

Installation and Setup

Install Python 3.

Install dependencies using pip:
pip install pycryptodome

Place the following files in the same directory:

password_manager_gui.py

password_manager.py

icon_32.png

Running the Application

To run from source:
python password_manager_gui.py

The program will prompt for the master password before loading the vault.

Building the Windows Executable

To build the single-file executable with PyInstaller and ensure the PNG icon is included:

pyinstaller --onefile --noconsole --add-data "icon_32.png;." password_manager_gui.py

The executable will be created in the dist directory.

Project Structure

password-manager/
• password_manager_gui.py
• password_manager.py
• icon_32.png
• vault.enc (generated at runtime)
• config.json (generated at runtime)
• README.md