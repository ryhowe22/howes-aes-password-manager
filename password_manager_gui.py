"""
Howe's AES Password Manager (GUI)
Clean, stable, professional version

- Uses AES/PBKDF2 vault logic from password_manager.py
- Uses PNG icon (icon_32.png) for window icon
- resource_path() ensures icon loads in Python + PyInstaller EXE
- Simple, reliable dialogs
"""

import sys
import os
import tkinter as tk
from tkinter import messagebox, simpledialog

from password_manager import load_config, derive_key, load_vault, save_vault


# ---------- PyInstaller-safe resource loader ----------

def resource_path(relative_path: str) -> str:
    """
    Get absolute path to resource (PNG icon, etc.)
    Works for development and PyInstaller (onefile & onedir).
    """
    try:
        # When running inside a PyInstaller EXE
        base_path = sys._MEIPASS
    except Exception:
        # When running from source .py
        base_path = os.path.dirname(os.path.abspath(__file__))

    return os.path.join(base_path, relative_path)


# ---------- Colors (Dark Spartan Theme) ----------

BG_MAIN = "#1b1a17"
BG_PANEL = "#24211c"
BG_BUTTON = "#3b362e"
BG_BUTTON_ACTIVE = "#4a4135"
FG_TEXT = "#e8e1c4"
ACCENT = "#b08d57"
LIST_BG = "#1f1c18"
LIST_FG = FG_TEXT


class PasswordManagerGUI:
    def __init__(self):
        # Main window
        self.root = tk.Tk()
        self.root.title("Howe's AES Password Manager")
        self.root.geometry("500x400")
        self.root.configure(bg=BG_MAIN)

        # ---------- LOAD PNG WINDOW ICON ----------
        icon_path = resource_path("icon_32.png")
        try:
            self.app_icon = tk.PhotoImage(file=icon_path)
            self.root.iconphoto(True, self.app_icon)
            print("Loaded icon:", icon_path)
        except Exception as e:
            print("Icon load failed:", e)
            print("Tried:", icon_path)

        # ---------- Crypto State ----------
        self.salt = load_config()
        self.key = None
        self.vault = {}

        # Build UI
        self.create_widgets()
        self.prompt_master_password()

    # ---------- UI Creation ----------

    def create_widgets(self):
        frame = tk.Frame(self.root, bg=BG_PANEL)
        frame.pack(fill="both", expand=True, padx=10, pady=10)

        self.entry_listbox = tk.Listbox(
            frame,
            height=15,
            bg=LIST_BG,
            fg=LIST_FG,
            selectbackground=ACCENT,
            selectforeground=BG_MAIN,
            borderwidth=0,
            highlightthickness=0
        )
        self.entry_listbox.pack(fill="both", expand=True, side="left")

        scrollbar = tk.Scrollbar(frame, command=self.entry_listbox.yview)
        scrollbar.pack(fill="y", side="right")
        self.entry_listbox.config(yscrollcommand=scrollbar.set)

        button_frame = tk.Frame(self.root, bg=BG_MAIN)
        button_frame.pack(fill="x", pady=10)

        def make_button(text, cmd):
            return tk.Button(
                button_frame,
                text=text,
                command=cmd,
                bg=BG_BUTTON,
                fg=FG_TEXT,
                activebackground=BG_BUTTON_ACTIVE,
                activeforeground=FG_TEXT,
                relief="raised",
                bd=1,
                padx=10,
                pady=5
            )

        make_button("Add Entry", self.add_entry).pack(side="left", padx=5)
        make_button("View Entry", self.view_entry).pack(side="left", padx=5)
        make_button("Delete Entry", self.delete_entry).pack(side="left", padx=5)
        make_button("Save Vault", self.save_vault_gui).pack(side="left", padx=5)
        make_button("Exit", self.root.quit).pack(side="left", padx=5)

    # ---------- Master Password Prompt ----------

    def prompt_master_password(self):
        while True:
            self.root.lift()
            self.root.focus_force()

            password = simpledialog.askstring(
                "Master Password",
                "Enter your master password:",
                show="*",
                parent=self.root
            )

            if password is None:
                self.root.destroy()
                return

            self.key = derive_key(password, self.salt)

            try:
                self.vault = load_vault(self.key)
                break
            except Exception:
                messagebox.showerror(
                    "Error",
                    "Incorrect password or corrupted vault. Try again.",
                    parent=self.root
                )

        self.update_listbox()

    # ---------- Vault Operations ----------

    def update_listbox(self):
        self.entry_listbox.delete(0, tk.END)
        for name in self.vault.keys():
            self.entry_listbox.insert(tk.END, name)

    def add_entry(self):
        name = simpledialog.askstring("New Entry", "Entry name:", parent=self.root)
        if not name:
            return

        username = simpledialog.askstring("New Entry", "Username:", parent=self.root)
        if username is None:
            return

        password = simpledialog.askstring("New Entry", "Password:", parent=self.root)
        if password is None:
            return

        self.vault[name] = {"username": username, "password": password}
        self.update_listbox()
        messagebox.showinfo("Success", f"Entry '{name}' added.", parent=self.root)

    def view_entry(self):
        sel = self.entry_listbox.curselection()
        if not sel:
            messagebox.showwarning("Warning", "No entry selected.", parent=self.root)
            return

        name = self.entry_listbox.get(sel[0])
        entry = self.vault.get(name, {})
        username = entry.get("username", "")
        password = entry.get("password", "")

        messagebox.showinfo(
            name,
            f"Username: {username}\nPassword: {password}",
            parent=self.root
        )

    def delete_entry(self):
        sel = self.entry_listbox.curselection()
        if not sel:
            messagebox.showwarning("Warning", "No entry selected.", parent=self.root)
            return

        name = self.entry_listbox.get(sel[0])

        confirm = messagebox.askyesno(
            "Confirm Delete",
            f"Delete entry '{name}'?",
            parent=self.root
        )
        if not confirm:
            return

        del self.vault[name]
        self.update_listbox()
        messagebox.showinfo("Deleted", f"Entry '{name}' deleted.", parent=self.root)

    def save_vault_gui(self):
        if self.key is None:
            messagebox.showerror(
                "Error", "No master key set. Restart the app.", parent=self.root
            )
            return

        save_vault(self.key, self.vault)
        messagebox.showinfo(
            "Saved", "Vault encrypted and saved successfully.", parent=self.root
        )


# ---------- Entry Point ----------

if __name__ == "__main__":
    app = PasswordManagerGUI()
    app.root.mainloop()
