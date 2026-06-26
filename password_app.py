import os
import re
import json
import time
import sqlite3
import tkinter as tk
from tkinter import messagebox, ttk

import pyotp
from argon2 import PasswordHasher
from argon2.low_level import hash_secret_raw, Type
from argon2.exceptions import VerifyMismatchError, VerificationError
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


DB_FILE = "authenticator.db"
LOCK_TIMEOUT_MS = 5 * 60 * 1000

ph = PasswordHasher()


# ---------- DATABASE ----------

def db_connect():
    return sqlite3.connect(DB_FILE)


def init_db():
    conn = db_connect()
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS vault_meta (
            key TEXT PRIMARY KEY,
            value BLOB NOT NULL
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS vault_entries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nonce BLOB NOT NULL,
            ciphertext BLOB NOT NULL
        )
    """)

    conn.commit()
    conn.close()


def meta_get(key):
    conn = db_connect()
    cur = conn.cursor()
    cur.execute("SELECT value FROM vault_meta WHERE key = ?", (key,))
    row = cur.fetchone()
    conn.close()
    return row[0] if row else None


def meta_set(key, value):
    conn = db_connect()
    cur = conn.cursor()

    cur.execute("""
        INSERT OR REPLACE INTO vault_meta (key, value)
        VALUES (?, ?)
    """, (key, value))

    conn.commit()
    conn.close()


# ---------- CRYPTO ----------

def derive_key(master_password, salt):
    return hash_secret_raw(
        secret=master_password.encode(),
        salt=salt,
        time_cost=3,
        memory_cost=65536,
        parallelism=2,
        hash_len=32,
        type=Type.ID
    )


def encrypt_bytes(key, plaintext_bytes):
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext_bytes, None)
    return nonce, ciphertext


def decrypt_bytes(key, nonce, ciphertext):
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None)


def encrypt_record(dek, data):
    plaintext = json.dumps(data).encode()
    return encrypt_bytes(dek, plaintext)


def decrypt_record(dek, nonce, ciphertext):
    plaintext = decrypt_bytes(dek, nonce, ciphertext)
    return json.loads(plaintext.decode())


# ---------- MASTER PASSWORD POLICY ----------

def validate_master_password(password):
    if len(password) < 12:
        return False, "Master password must be at least 12 characters long."

    if not re.search(r"[A-Z]", password):
        return False, "Master password must contain at least one uppercase letter."

    if not re.search(r"[a-z]", password):
        return False, "Master password must contain at least one lowercase letter."

    if not re.search(r"\d", password):
        return False, "Master password must contain at least one number."

    if not re.search(r"[!@#$%^&*()_\-+=\[\]{};:'\",.<>/?\\|`~]", password):
        return False, "Master password must contain at least one special character."

    return True, ""


# ---------- VAULT ----------

def vault_exists():
    return meta_get("master_hash") is not None


def create_vault(master_password):
    valid, message = validate_master_password(master_password)

    if not valid:
        raise ValueError(message)

    master_hash = ph.hash(master_password)
    kdf_salt = os.urandom(16)

    kek = derive_key(master_password, kdf_salt)
    dek = os.urandom(32)

    dek_nonce, encrypted_dek = encrypt_bytes(kek, dek)

    meta_set("master_hash", master_hash.encode())
    meta_set("kdf_salt", kdf_salt)
    meta_set("dek_nonce", dek_nonce)
    meta_set("encrypted_dek", encrypted_dek)


def unlock_vault(master_password):
    master_hash = meta_get("master_hash")

    if not master_hash:
        return None

    try:
        ph.verify(master_hash.decode(), master_password)
    except (VerifyMismatchError, VerificationError):
        return None

    kdf_salt = meta_get("kdf_salt")
    dek_nonce = meta_get("dek_nonce")
    encrypted_dek = meta_get("encrypted_dek")

    kek = derive_key(master_password, kdf_salt)

    try:
        return decrypt_bytes(kek, dek_nonce, encrypted_dek)
    except Exception:
        return None


# ---------- VAULT ENTRIES ----------

def add_vault_entry(service, username, password, secret, dek):
    data = {
        "service": service,
        "username": username,
        "password": password,
        "secret": secret
    }

    nonce, ciphertext = encrypt_record(dek, data)

    conn = db_connect()
    cur = conn.cursor()

    cur.execute("""
        INSERT INTO vault_entries
        (nonce, ciphertext)
        VALUES (?, ?)
    """, (nonce, ciphertext))

    conn.commit()
    conn.close()


def get_vault_entries():
    conn = db_connect()
    cur = conn.cursor()

    cur.execute("""
        SELECT id, nonce, ciphertext
        FROM vault_entries
        ORDER BY id
    """)

    rows = cur.fetchall()
    conn.close()
    return rows


def delete_vault_entry(entry_id):
    conn = db_connect()
    cur = conn.cursor()

    cur.execute("DELETE FROM vault_entries WHERE id = ?", (entry_id,))

    conn.commit()
    conn.close()


# ---------- MAIN WINDOW ----------

def open_main_window(dek):
    main = tk.Tk()
    main.title("Secure Password and Authenticator Vault")
    main.geometry("950x550")

    lock_timer = None
    decrypted_cache = {}

    def lock_app():
        messagebox.showinfo("Locked", "Vault locked due to inactivity.")
        decrypted_cache.clear()
        main.destroy()

    def reset_lock_timer(event=None):
        nonlocal lock_timer

        if lock_timer:
            main.after_cancel(lock_timer)

        lock_timer = main.after(LOCK_TIMEOUT_MS, lock_app)

    main.bind_all("<Key>", reset_lock_timer)
    main.bind_all("<Button>", reset_lock_timer)

    tk.Label(
        main,
        text="Secure Password and Authenticator Vault",
        font=("Arial", 18)
    ).pack(pady=15)

    tree = ttk.Treeview(
        main,
        columns=("service", "username", "password", "code", "expires"),
        show="headings",
        height=15
    )

    tree.heading("service", text="Service")
    tree.heading("username", text="Username")
    tree.heading("password", text="Password")
    tree.heading("code", text="Authenticator Code")
    tree.heading("expires", text="Expires")

    tree.column("service", width=200)
    tree.column("username", width=250)
    tree.column("password", width=120, anchor="center")
    tree.column("code", width=150, anchor="center")
    tree.column("expires", width=80, anchor="center")

    tree.pack(fill="both", expand=True, padx=10, pady=10)

    status_label = tk.Label(main, text="Ready", anchor="w")
    status_label.pack(fill="x", padx=10, pady=5)

    def refresh_codes():
        remaining = 30 - (int(time.time()) % 30)
        current_ids = set()
        entries = []

        for entry_id, nonce, ciphertext in get_vault_entries():
            item_id = str(entry_id)
            current_ids.add(item_id)

            try:
                data = decrypt_record(dek, nonce, ciphertext)
                decrypted_cache[item_id] = data

                service = data.get("service", "")
                username = data.get("username", "")
                password = data.get("password", "")
                secret = data.get("secret", "")

                code = "------"

                if secret:
                    totp = pyotp.TOTP(secret)
                    raw_code = totp.now()
                    code = f"{raw_code[:3]} {raw_code[3:]}"

                password_display = "Saved" if password else "None"

                values = (
                    service,
                    username,
                    password_display,
                    code,
                    f"{remaining}s"
                )

                entries.append((item_id, values))

            except Exception:
                values = (
                    "Unable to decrypt",
                    "",
                    "Unknown",
                    "------",
                    ""
                )
                entries.append((item_id, values))

        entries.sort(key=lambda item: str(item[1][0]).lower())

        existing_ids = set(tree.get_children())

        for item_id, values in entries:
            if tree.exists(item_id):
                tree.item(item_id, values=values)
            else:
                tree.insert("", "end", iid=item_id, values=values)

        for item_id in existing_ids:
            if item_id not in current_ids:
                tree.delete(item_id)
                decrypted_cache.pop(item_id, None)

        main.after(1000, refresh_codes)

    def get_selected_item():
        selected = tree.selection()

        if not selected:
            messagebox.showerror("Error", "Please select an entry.")
            return None

        return selected[0]

    def copy_selected_username():
        item_id = get_selected_item()
        if not item_id:
            return

        data = decrypted_cache.get(item_id)

        if not data:
            messagebox.showerror("Error", "Username is not available.")
            return

        username = data.get("username", "")

        if not username:
            messagebox.showerror("Error", "No username saved for this entry.")
            return

        main.clipboard_clear()
        main.clipboard_append(username)
        main.update()

        status_label.config(text=f"Copied username: {username}")

    def copy_selected_password():
        item_id = get_selected_item()
        if not item_id:
            return

        data = decrypted_cache.get(item_id)

        if not data:
            messagebox.showerror("Error", "Password is not available.")
            return

        password = data.get("password", "")

        if not password:
            messagebox.showerror("Error", "No password saved for this entry.")
            return

        main.clipboard_clear()
        main.clipboard_append(password)
        main.update()

        status_label.config(text="Copied password to clipboard.")

    def copy_selected_code():
        item_id = get_selected_item()
        if not item_id:
            return

        data = decrypted_cache.get(item_id)

        if not data:
            messagebox.showerror("Error", "Authenticator code is not available.")
            return

        secret = data.get("secret", "")

        if not secret:
            messagebox.showerror("Error", "No authenticator secret saved for this entry.")
            return

        try:
            code = pyotp.TOTP(secret).now()
        except Exception:
            messagebox.showerror("Error", "Invalid authenticator secret.")
            return

        main.clipboard_clear()
        main.clipboard_append(code)
        main.update()

        status_label.config(text=f"Copied code: {code}")

    tree.bind("<Double-1>", lambda event: copy_selected_code())

    def add_entry_window():
        win = tk.Toplevel(main)
        win.title("Add Vault Entry")
        win.geometry("420x400")
        win.resizable(False, False)

        tk.Label(win, text="Service").pack(pady=5)
        service_entry = tk.Entry(win, width=42)
        service_entry.pack()

        tk.Label(win, text="Username / Email").pack(pady=5)
        username_entry = tk.Entry(win, width=42)
        username_entry.pack()

        tk.Label(win, text="Password").pack(pady=5)
        password_entry = tk.Entry(win, show="*", width=42)
        password_entry.pack()

        tk.Label(win, text="Authenticator Secret Key").pack(pady=5)
        secret_entry = tk.Entry(win, show="*", width=42)
        secret_entry.pack()

        def save():
            service = service_entry.get().strip()
            username = username_entry.get().strip()
            password = password_entry.get()
            secret = secret_entry.get().replace(" ", "").strip()

            if not service:
                messagebox.showerror("Error", "Service is required.")
                return

            if not username:
                messagebox.showerror("Error", "Username is required.")
                return

            if not password and not secret:
                messagebox.showerror(
                    "Error",
                    "Enter a password, an authenticator secret, or both."
                )
                return

            if secret:
                try:
                    pyotp.TOTP(secret).now()
                except Exception:
                    messagebox.showerror("Error", "Invalid authenticator secret.")
                    return

            add_vault_entry(service, username, password, secret, dek)

            messagebox.showinfo("Saved", "Entry encrypted and saved.")
            win.destroy()
            refresh_codes()

        tk.Button(win, text="Save", width=15, command=save).pack(pady=20)

    def delete_selected():
        item_id = get_selected_item()
        if not item_id:
            return

        confirm = messagebox.askyesno(
            "Confirm Delete",
            "Delete the selected entry?"
        )

        if not confirm:
            return

        delete_vault_entry(item_id)
        decrypted_cache.pop(item_id, None)
        status_label.config(text="Entry deleted.")
        refresh_codes()

    button_frame = tk.Frame(main)
    button_frame.pack(pady=10)

    tk.Button(button_frame, text="Add", width=15, command=add_entry_window).grid(row=0, column=0, padx=5)
    tk.Button(button_frame, text="Copy Username", width=15, command=copy_selected_username).grid(row=0, column=1, padx=5)
    tk.Button(button_frame, text="Copy Password", width=15, command=copy_selected_password).grid(row=0, column=2, padx=5)
    tk.Button(button_frame, text="Copy Code", width=15, command=copy_selected_code).grid(row=0, column=3, padx=5)
    tk.Button(button_frame, text="Delete", width=15, command=delete_selected).grid(row=0, column=4, padx=5)
    tk.Button(button_frame, text="Lock Vault", width=15, command=main.destroy).grid(row=0, column=5, padx=5)

    refresh_codes()
    reset_lock_timer()
    main.mainloop()


# ---------- LOGIN WINDOW ----------

def start_login_window():
    root = tk.Tk()
    root.title("Vault Login")
    root.geometry("390x390")
    root.resizable(False, False)

    if not vault_exists():
        tk.Label(root, text="Create Master Password", font=("Arial", 14)).pack(pady=10)

        tk.Label(
            root,
            text=(
                "Password requirements:\n"
                "• At least 12 characters\n"
                "• At least one uppercase letter\n"
                "• At least one lowercase letter\n"
                "• At least one number\n"
                "• At least one special character"
            ),
            justify="left",
            fg="green"
        ).pack(pady=5)

        tk.Label(root, text="Password").pack()
        password_entry = tk.Entry(root, show="*", width=35)
        password_entry.pack(pady=5)

        tk.Label(root, text="Confirm Password").pack()
        confirm_entry = tk.Entry(root, show="*", width=35)
        confirm_entry.pack(pady=5)

        def create():
            password = password_entry.get()
            confirm = confirm_entry.get()

            if password != confirm:
                messagebox.showerror("Error", "Passwords do not match.")
                return

            try:
                create_vault(password)
                dek = unlock_vault(password)

                messagebox.showinfo("Success", "Vault created.")
                root.destroy()
                open_main_window(dek)

            except ValueError as error:
                messagebox.showerror("Weak Password", str(error))

        tk.Button(root, text="Create Vault", command=create).pack(pady=20)

    else:
        tk.Label(root, text="Enter Master Password", font=("Arial", 14)).pack(pady=20)

        tk.Label(root, text="Password").pack()
        password_entry = tk.Entry(root, show="*", width=35)
        password_entry.pack(pady=5)

        def login():
            password = password_entry.get()
            dek = unlock_vault(password)

            if dek:
                messagebox.showinfo("Success", "Vault unlocked.")
                root.destroy()
                open_main_window(dek)
            else:
                messagebox.showerror("Error", "Wrong master password.")

        tk.Button(root, text="Unlock Vault", command=login).pack(pady=20)

    root.mainloop()


# ---------- START ----------

init_db()
start_login_window()
