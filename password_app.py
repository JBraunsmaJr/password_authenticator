import os
import json
import time
import tkinter as tk
from tkinter import messagebox, ttk, filedialog, simpledialog

import pyotp
import qrcode
from PIL import Image, ImageTk

from lib.crypto import encrypt_bytes, decrypt_bytes, decrypt_record
from lib.vault import Vault

DB_FILE = "authenticator.db"
LOGO_FILE = "NxTPass-Logo.png"

LOCK_TIMEOUT_MS = 15 * 60 * 1000
CLIPBOARD_CLEAR_MS = 30 * 1000

MAX_LOGIN_ATTEMPTS = 5
LOGIN_LOCKOUT_SECONDS = 10 * 60


def load_logo(width=100):
    if not os.path.exists(LOGO_FILE):
        return None

    image = Image.open(LOGO_FILE)
    image.thumbnail((width, width))
    return ImageTk.PhotoImage(image)


def export_encrypted_backup():
    backup_password = simpledialog.askstring(
        "Backup Password",
        "Enter a password to encrypt the backup:",
        show="*"
    )

    if not backup_password:
        return

    file_path = filedialog.asksaveasfilename(
        title="Save Encrypted Backup",
        defaultextension=".vaultbak",
        filetypes=[("Vault Backup", "*.vaultbak")]
    )

    if not file_path:
        return

    with open(DB_FILE, "rb") as f:
        db_bytes = f.read()

    salt = os.urandom(16)
    time_cost = 3
    memory_cost = 262144
    parallelism = 4
    key = Vault.derive_backup_key(backup_password, salt, time_cost, memory_cost, parallelism)
    nonce, ciphertext = encrypt_bytes(key, db_bytes)

    backup_data = {
        "version": 1,
        "salt": salt.hex(),
        "nonce": nonce.hex(),
        "ciphertext": ciphertext.hex(),
        "argon2_time": time_cost,
        "argon2_mem": memory_cost,
        "argon2_par": parallelism
    }

    with open(file_path, "w") as f:
        json.dump(backup_data, f)

    messagebox.showinfo("Backup Saved", "Encrypted backup created successfully.")


def import_encrypted_backup():
    confirm = messagebox.askyesno(
        "Restore Backup",
        "Restoring a backup will replace the current vault database. Continue?"
    )

    if not confirm:
        return

    file_path = filedialog.askopenfilename(
        title="Open Encrypted Backup",
        filetypes=[("Vault Backup", "*.vaultbak")]
    )

    if not file_path:
        return

    backup_password = simpledialog.askstring(
        "Backup Password",
        "Enter the backup password:",
        show="*"
    )

    if not backup_password:
        return

    try:
        with open(file_path, "r") as f:
            backup_data = json.load(f)

        salt = bytes.fromhex(backup_data["salt"])
        nonce = bytes.fromhex(backup_data["nonce"])
        ciphertext = bytes.fromhex(backup_data["ciphertext"])

        # Load Argon2 parameters from backup, with defaults for older backups
        time_cost = int(backup_data.get("argon2_time", 3))
        memory_cost = int(backup_data.get("argon2_mem", 65536))
        parallelism = int(backup_data.get("argon2_par", 2))

        key = Vault.derive_backup_key(backup_password, salt, time_cost, memory_cost, parallelism)
        db_bytes = decrypt_bytes(key, nonce, ciphertext)

        with open(DB_FILE, "wb") as f:
            f.write(db_bytes)

        messagebox.showinfo(
            "Backup Restored",
            "Backup restored successfully. Restart the app before unlocking."
        )

    except Exception:
        messagebox.showerror(
            "Error",
            "Could not restore backup. Wrong password or damaged backup file."
        )


def open_main_window(dek):
    main = tk.Tk()
    main.title("NxTPass Secure Password and Authenticator Vault")
    main.geometry("1050x660")

    lock_timer = None
    clipboard_timer = None
    refresh_timer = None
    decrypted_cache = {}

    logo_photo = load_logo(80)

    if logo_photo:
        main.logo_photo = logo_photo
        tk.Label(main, image=logo_photo).pack(pady=5)

    def cleanup_and_close():
        nonlocal lock_timer, clipboard_timer, refresh_timer

        decrypted_cache.clear()

        for timer in (lock_timer, clipboard_timer, refresh_timer):
            if timer is not None:
                try:
                    main.after_cancel(timer)
                except tk.TclError:
                    pass

        main.destroy()

    def lock_app():
        messagebox.showinfo("Locked", "Vault locked due to inactivity.")
        cleanup_and_close()

    def reset_lock_timer(event=None):
        nonlocal lock_timer

        if lock_timer:
            try:
                main.after_cancel(lock_timer)
            except tk.TclError:
                pass

        lock_timer = main.after(LOCK_TIMEOUT_MS, lock_app)

    def clear_clipboard():
        try:
            main.clipboard_clear()
            main.update()
            status_label.config(text="Clipboard cleared.")
        except tk.TclError:
            pass

    def copy_to_clipboard(value, message):
        nonlocal clipboard_timer

        main.clipboard_clear()
        main.clipboard_append(value)
        main.update()

        if clipboard_timer:
            try:
                main.after_cancel(clipboard_timer)
            except tk.TclError:
                pass

        clipboard_timer = main.after(CLIPBOARD_CLEAR_MS, clear_clipboard)
        status_label.config(text=message + " Clipboard will clear in 30 seconds.")

    main.protocol("WM_DELETE_WINDOW", cleanup_and_close)
    main.bind_all("<Key>", reset_lock_timer)
    main.bind_all("<Button>", reset_lock_timer)

    tk.Label(
        main,
        text="NxTPass Secure Password and Authenticator Vault",
        font=("Arial", 18)
    ).pack(pady=10)

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

    tree.column("service", width=220)
    tree.column("username", width=270)
    tree.column("password", width=120, anchor="center")
    tree.column("code", width=160, anchor="center")
    tree.column("expires", width=80, anchor="center")

    tree.pack(fill="both", expand=True, padx=10, pady=10)

    status_label = tk.Label(main, text="Ready", anchor="w")
    status_label.pack(fill="x", padx=10, pady=5)

    def refresh_codes():
        nonlocal refresh_timer

        try:
            remaining = 30 - (int(time.time()) % 30)
            current_ids = set()
            entries = []

            for entry in vault.get_vault_entries():
                item_id = str(entry.id)
                current_ids.add(item_id)

                try:
                    data = decrypt_record(dek, entry.nonce, entry.ciphertext)
                    if not data:
                        continue

                    decrypted_cache[item_id] = data

                    service = data.service
                    username = data.username
                    password = data.password
                    secret = data.secret

                    code = "------"

                    if secret:
                        raw_code = pyotp.TOTP(secret).now()
                        code = f"{raw_code[:3]} {raw_code[3:]}"

                    password_display = "Saved" if password else "None"

                    entries.append((
                        item_id,
                        (
                            service,
                            username,
                            password_display,
                            code,
                            f"{remaining}s"
                        )
                    ))

                except Exception:
                    entries.append((
                        item_id,
                        (
                            "Unable to decrypt",
                            "",
                            "Unknown",
                            "------",
                            ""
                        )
                    ))

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

            refresh_timer = main.after(1000, refresh_codes)

        except tk.TclError:
            return

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
        username = data.username if data else ""

        if not username:
            messagebox.showerror("Error", "No username saved for this entry.")
            return

        copy_to_clipboard(username, f"Copied username: {username}")

    def copy_selected_password():
        item_id = get_selected_item()
        if not item_id:
            return

        data = decrypted_cache.get(item_id)
        password = data.password if data else ""

        if not password:
            messagebox.showerror("Error", "No password saved for this entry.")
            return

        copy_to_clipboard(password, "Copied password.")

    def copy_selected_code():
        item_id = get_selected_item()
        if not item_id:
            return

        data = decrypted_cache.get(item_id)
        secret = data.secret if data else ""

        if not secret:
            messagebox.showerror("Error", "No authenticator secret saved for this entry.")
            return

        try:
            code = pyotp.TOTP(secret).now()
        except Exception:
            messagebox.showerror("Error", "Invalid authenticator secret.")
            return

        copy_to_clipboard(code, f"Copied code: {code}")

    tree.bind("<Double-1>", lambda event: copy_selected_code())

    def entry_window(mode="add"):
        editing = mode == "edit"
        item_id = None
        existing = {}

        if editing:
            item_id = get_selected_item()
            if not item_id:
                return

            existing = decrypted_cache.get(item_id)

            if not existing:
                messagebox.showerror("Error", "Could not decrypt selected entry.")
                return

        win = tk.Toplevel(main)
        win.title("Edit Vault Entry" if editing else "Add Vault Entry")
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

        if editing:
            service_entry.insert(0, existing.service)
            username_entry.insert(0, existing.username)
            password_entry.insert(0, existing.password)
            secret_entry.insert(0, existing.secret)

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

            if editing:
                vault.update_vault_entry(item_id, service, username, password, secret, dek)
                status_label.config(text="Entry updated and re-encrypted.")
            else:
                vault.add_vault_entry(service, username, password, secret, dek)
                status_label.config(text="Entry encrypted and saved.")

            win.destroy()
            refresh_codes()

        tk.Button(
            win,
            text="Save Changes" if editing else "Save",
            width=15,
            command=save
        ).pack(pady=20)

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

        vault.delete_vault_entry(item_id)
        decrypted_cache.pop(item_id, None)
        status_label.config(text="Entry deleted.")
        refresh_codes()

    button_frame = tk.Frame(main)
    button_frame.pack(pady=10)

    tk.Button(button_frame, text="Copy Username", width=16, command=copy_selected_username).grid(row=0, column=0,
                                                                                                 padx=5, pady=5)
    tk.Button(button_frame, text="Copy Password", width=16, command=copy_selected_password).grid(row=0, column=1,
                                                                                                 padx=5, pady=5)
    tk.Button(button_frame, text="Copy Code", width=16, command=copy_selected_code).grid(row=0, column=2, padx=5,
                                                                                         pady=5)
    tk.Button(button_frame, text="Lock Vault", width=16, command=cleanup_and_close).grid(row=0, column=3, padx=5,
                                                                                         pady=5)

    tk.Button(button_frame, text="Add", width=16, command=lambda: entry_window("add")).grid(row=1, column=0, padx=5,
                                                                                            pady=5)
    tk.Button(button_frame, text="Edit", width=16, command=lambda: entry_window("edit")).grid(row=1, column=1, padx=5,
                                                                                              pady=5)
    tk.Button(button_frame, text="Delete", width=16, command=delete_selected).grid(row=1, column=2, padx=5, pady=5)
    tk.Button(button_frame, text="Backup Vault", width=16, command=export_encrypted_backup).grid(row=1, column=3,
                                                                                                 padx=5, pady=5)
    tk.Button(button_frame, text="Restore Vault", width=16, command=import_encrypted_backup).grid(row=1, column=4,
                                                                                                  padx=5, pady=5)

    refresh_codes()
    reset_lock_timer()
    main.mainloop()


def start_login_window():
    root = tk.Tk()
    root.title("NxTPass Vault Login")
    root.resizable(False, False)

    login_window_active = True
    lockout_timer = None

    def close_login_window():
        nonlocal login_window_active, lockout_timer

        login_window_active = False

        if lockout_timer is not None:
            try:
                root.after_cancel(lockout_timer)
            except tk.TclError:
                pass

        root.destroy()

    root.protocol("WM_DELETE_WINDOW", close_login_window)

    if not vault.vault_exists():
        root.geometry("470x900")

        twofa_secret = pyotp.random_base32()

        setup_uri = pyotp.TOTP(twofa_secret).provisioning_uri(
            name="NxTPass Vault Login",
            issuer_name="NxTPass Password Vault"
        )

        qr_image = qrcode.make(setup_uri)
        qr_image = qr_image.resize((190, 190))
        qr_photo = ImageTk.PhotoImage(qr_image)

        tk.Label(root, text="Create NxTPass Master Vault", font=("Arial", 14)).pack(pady=10)

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
            fg="darkgreen"
        ).pack(pady=5)

        tk.Label(root, text="Password").pack()
        password_entry = tk.Entry(root, show="*", width=35)
        password_entry.pack(pady=5)

        tk.Label(root, text="Confirm Password").pack()
        confirm_entry = tk.Entry(root, show="*", width=35)
        confirm_entry.pack(pady=5)

        tk.Label(
            root,
            text=(
                "Required 2FA Setup:\n"
                "Scan this QR code with your authenticator app."
            ),
            justify="center"
        ).pack(pady=10)

        qr_label = tk.Label(root, image=qr_photo)
        qr_label.image = qr_photo
        qr_label.pack(pady=5)

        tk.Label(root, text="Manual setup key:").pack(pady=(10, 0))

        secret_text = tk.Text(root, height=2, width=45)
        secret_text.insert("1.0", twofa_secret)
        secret_text.config(state="disabled")
        secret_text.pack(pady=5)

        tk.Label(root, text="Enter 6-digit 2FA code").pack()
        twofa_entry = tk.Entry(root, width=20)
        twofa_entry.pack(pady=5)

        def create():
            password = password_entry.get()
            confirm = confirm_entry.get()
            twofa_code = twofa_entry.get().strip()

            if password != confirm:
                messagebox.showerror("Error", "Passwords do not match.")
                return

            if not pyotp.TOTP(twofa_secret).verify(twofa_code, valid_window=1):
                messagebox.showerror("Error", "Invalid 2FA code.")
                return

            try:
                valid, message = Vault.validate_master_password(password)
                if not valid:
                    raise ValueError(message)

                vault.create_vault(password, twofa_secret)
                dek = vault.unlock_vault(password, twofa_code)

                if not dek:
                    messagebox.showerror("Error", "Vault created, but unlock failed.")
                    return

                messagebox.showinfo("Success", "Vault created with 2FA enabled.")
                close_login_window()
                open_main_window(dek)

            except ValueError as error:
                messagebox.showerror("Weak Password", str(error))

        tk.Button(
            root,
            text="Create Vault",
            width=22,
            height=2,
            command=create
        ).pack(pady=(20, 10))

        logo_photo = load_logo(150)

        if logo_photo:
            root.logo_photo = logo_photo
            tk.Label(
                root,
                image=logo_photo,
                borderwidth=0,
                highlightthickness=0
            ).pack(pady=(5, 15))

    else:
        root.geometry("370x560")

        tk.Label(root, text="Enter Master Password", font=("Arial", 14, "bold")).pack(pady=(20, 10))

        logo_photo = load_logo(100)

        if logo_photo:
            root.logo_photo = logo_photo
            tk.Label(root, image=logo_photo, borderwidth=0).pack(pady=(0, 15))

        lockout_status = tk.Label(root, text="", fg="red")
        lockout_status.pack(pady=5)

        tk.Label(root, text="Password").pack()
        password_entry = tk.Entry(root, show="*", width=35)
        password_entry.pack(pady=5)

        tk.Label(root, text="2FA Code").pack()
        twofa_entry = tk.Entry(root, width=20)
        twofa_entry.pack(pady=5)

        def update_lockout_label():
            nonlocal lockout_timer, login_window_active

            if not login_window_active:
                return

            try:
                if not root.winfo_exists():
                    return

                if vault.is_login_locked():
                    seconds = vault.login_lock_remaining()
                    minutes = seconds // 60
                    remainder = seconds % 60
                    lockout_status.config(
                        text=f"Locked. Try again in {minutes}:{remainder:02d}"
                    )
                else:
                    attempts = vault.get_failed_attempts()
                    if attempts:
                        lockout_status.config(
                            text=f"Failed attempts: {attempts}/{MAX_LOGIN_ATTEMPTS}"
                        )
                    else:
                        lockout_status.config(text="")

                lockout_timer = root.after(1000, update_lockout_label)

            except tk.TclError:
                return

        def login():
            if vault.is_login_locked():
                messagebox.showerror(
                    "Locked",
                    f"Too many failed attempts. Try again in {vault.login_lock_remaining()} seconds."
                )
                return

            password = password_entry.get()
            twofa_code = twofa_entry.get().strip()

            dek = vault.unlock_vault(password, twofa_code)

            if dek:
                vault.reset_failed_logins()
                messagebox.showinfo("Success", "Vault unlocked.")
                close_login_window()
                open_main_window(dek)
            else:
                vault.record_failed_login(MAX_LOGIN_ATTEMPTS, LOGIN_LOCKOUT_SECONDS)

                if vault.is_login_locked():
                    messagebox.showerror(
                        "Locked",
                        "Too many failed attempts. Login locked for 10 minutes."
                    )
                else:
                    messagebox.showerror("Error", "Wrong master password or 2FA code.")

        tk.Button(root, text="Unlock Vault", command=login).pack(pady=15)
        tk.Button(root, text="Import Backup", command=import_encrypted_backup).pack(pady=5)

        update_lockout_label()

    root.mainloop()


if __name__ == "__main__":
    with Vault(DB_FILE) as vault:
        start_login_window()
