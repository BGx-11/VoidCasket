import customtkinter as ctk
from PIL import Image
import qrcode
import threading
import time
import sys
import os

# Import your existing logic
from casket_logic import crypto, auth, database

# --- THEME CONFIGURATION ---
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("dark-blue")

# --- PALETTE (Professional "Void" Theme) ---
COLOR_BG = "#0d0d0d"       # Deepest Black (Void)
COLOR_SIDEBAR = "#111111"  # Sidebar Background
COLOR_PANEL = "#1a1a1a"    # Content Panels
COLOR_ACCENT = "#00E5FF"   # Void Cyan (High Visibility)
COLOR_ACCENT_HOVER = "#00B8D4"
COLOR_TEXT_MAIN = "#e1e1e1"
COLOR_TEXT_DIM = "#888888"
COLOR_DANGER = "#cf3030"   # Red for Lock/Delete
COLOR_SUCCESS = "#2CC985"  # Green for Copied/Success

def resource_path(relative_path):
    """ Get absolute path to resource, works for dev and for PyInstaller """
    try:
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)

class VoidCasketApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        # Window Config
        self.title("VOID CASKET // ENCRYPTED VAULT")
        self.geometry("1100x700")
        self.minsize(900, 600)
        
        # --- ICON SETUP ---
        # Checks for 'logo.ico' in the same folder. If not found, ignores it.
        try:
            icon_path = resource_path("logo.ico")
            if os.path.exists(icon_path):
                self.iconbitmap(icon_path)
        except Exception:
            pass
        
        # Grid Layout
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # Session State
        self.vault_data = None
        self.password = None

        # --- INITIALIZATION ---
        if database.load_vault():
            self.show_login_interface()
        else:
            self.show_setup_interface()

    def clear_main_area(self):
        """Helper to clear widgets before switching screens"""
        for widget in self.winfo_children():
            widget.destroy()
        self.unbind('<Return>')

    # ==========================================================
    # 1. SETUP INTERFACE
    # ==========================================================
    def show_setup_interface(self):
        self.clear_main_area()
        self.configure(fg_color=COLOR_BG)

        center_frame = ctk.CTkFrame(self, fg_color=COLOR_PANEL, corner_radius=0)
        center_frame.place(relx=0.5, rely=0.5, anchor="center", relwidth=0.4, relheight=0.85)

        ctk.CTkLabel(center_frame, text="SYSTEM INITIALIZATION", font=("Impact", 28), text_color=COLOR_ACCENT).pack(pady=(50, 10))
        ctk.CTkLabel(center_frame, text="Generate your Master Identity", font=("Roboto", 12), text_color=COLOR_TEXT_DIM).pack(pady=(0, 40))

        self.entry_setup_pwd = ctk.CTkEntry(center_frame, placeholder_text="Create Master Password", show="*", 
                                            height=50, font=("Roboto", 14), border_color=COLOR_SIDEBAR)
        self.entry_setup_pwd.pack(pady=10, padx=40, fill="x")
        
        self.entry_setup_confirm = ctk.CTkEntry(center_frame, placeholder_text="Confirm Master Password", show="*", 
                                                height=50, font=("Roboto", 14), border_color=COLOR_SIDEBAR)
        self.entry_setup_confirm.pack(pady=10, padx=40, fill="x")

        # Navigation
        self.entry_setup_pwd.bind('<Return>', lambda event: self.entry_setup_confirm.focus())
        self.entry_setup_confirm.bind('<Return>', lambda event: self.process_setup_step1())

        self.lbl_setup_status = ctk.CTkLabel(center_frame, text="", text_color=COLOR_DANGER)
        self.lbl_setup_status.pack(pady=10)

        ctk.CTkButton(center_frame, text="PROCEED TO 2FA >", height=50, fg_color=COLOR_ACCENT, hover_color=COLOR_ACCENT_HOVER,
                      text_color="black", font=("Roboto", 12, "bold"), command=self.process_setup_step1).pack(pady=30, padx=40, fill="x")

    def process_setup_step1(self):
        p1 = self.entry_setup_pwd.get()
        p2 = self.entry_setup_confirm.get()
        if not p1 or p1 != p2:
            self.lbl_setup_status.configure(text="ERROR: Passwords do not match.")
            return
        self.setup_password_cache = p1
        self.show_setup_2fa_interface()

    def show_setup_2fa_interface(self):
        self.clear_main_area()
        self.configure(fg_color=COLOR_BG)
        self.bind('<Return>', lambda event: self.finalize_setup())

        center_frame = ctk.CTkFrame(self, fg_color=COLOR_PANEL, corner_radius=0)
        center_frame.place(relx=0.5, rely=0.5, anchor="center", relwidth=0.5, relheight=0.9)

        ctk.CTkLabel(center_frame, text="TWO-FACTOR AUTH", font=("Impact", 28), text_color=COLOR_ACCENT).pack(pady=(40, 5))
        ctk.CTkLabel(center_frame, text="Scan with Google Authenticator", font=("Roboto", 12), text_color=COLOR_TEXT_DIM).pack(pady=(0, 20))

        self.temp_secret = auth.generate_totp_secret()
        uri = auth.get_totp_uri(self.temp_secret)
        
        # QR Code Display
        qr_img = qrcode.make(uri).get_image()
        qr_ctk = ctk.CTkImage(light_image=qr_img, dark_image=qr_img, size=(220, 220))
        ctk.CTkLabel(center_frame, image=qr_ctk, text="").pack(pady=10)

        ctk.CTkLabel(center_frame, text="Enter the code from the authenticator:", font=("Roboto", 12), text_color="gray").pack(pady=(20, 5))

        self.entry_setup_code = ctk.CTkEntry(center_frame, placeholder_text="000 000", height=50, width=200, justify="center",
                                             font=("Consolas", 18, "bold"), border_color=COLOR_SIDEBAR)
        self.entry_setup_code.pack(pady=(5, 20))

        ctk.CTkButton(center_frame, text="FINALIZE ENCRYPTION", height=50, fg_color=COLOR_ACCENT, hover_color=COLOR_ACCENT_HOVER,
                      text_color="black", font=("Roboto", 12, "bold"), command=self.finalize_setup).pack(pady=10, padx=80, fill="x")

        self.lbl_setup_error = ctk.CTkLabel(center_frame, text="", text_color=COLOR_DANGER)
        self.lbl_setup_error.pack()

    def finalize_setup(self):
        code = self.entry_setup_code.get().replace(" ", "")
        if not auth.verify_totp(self.temp_secret, code):
            self.lbl_setup_error.configure(text="Invalid Code.")
            return

        pwd = self.setup_password_cache
        pwd_hash = auth.hash_master_password(pwd)
        totp_header = crypto.encrypt_casket({"secret": self.temp_secret}, pwd)
        empty_vault = crypto.encrypt_casket({"passwords": []}, pwd)

        database.save_vault({"pwd_hash": pwd_hash, "totp_blob": totp_header}, empty_vault)
        self.show_login_interface()

    # ==========================================================
    # 2. LOGIN INTERFACE
    # ==========================================================
    def show_login_interface(self):
        self.clear_main_area()
        self.configure(fg_color=COLOR_BG)
        self.bind('<Return>', lambda event: self.process_login())

        # Layout
        logo_frame = ctk.CTkFrame(self, fg_color=COLOR_BG, corner_radius=0)
        logo_frame.place(relx=0.0, rely=0.0, relwidth=0.4, relheight=1.0)
        
        ctk.CTkLabel(logo_frame, text="VOID\nCASKET", font=("Impact", 60), text_color=COLOR_ACCENT).place(relx=0.5, rely=0.4, anchor="center")
        ctk.CTkLabel(logo_frame, text="v1.0.0 // ENCRYPTED", font=("Consolas", 14), text_color=COLOR_TEXT_DIM).place(relx=0.5, rely=0.55, anchor="center")

        login_frame = ctk.CTkFrame(self, fg_color=COLOR_PANEL, corner_radius=0)
        login_frame.place(relx=0.4, rely=0.0, relwidth=0.6, relheight=1.0)

        container = ctk.CTkFrame(login_frame, fg_color="transparent")
        container.place(relx=0.5, rely=0.5, anchor="center", relwidth=0.6)

        ctk.CTkLabel(container, text="AUTHENTICATE", font=("Roboto Medium", 24), text_color="white", anchor="w").pack(fill="x", pady=(0, 30))

        self.entry_login_pwd = ctk.CTkEntry(container, placeholder_text="Master Password", show="*", height=50, 
                                            font=("Roboto", 14), border_width=0, fg_color="#222222")
        self.entry_login_pwd.pack(fill="x", pady=10)
        self.entry_login_pwd.bind("<Return>", lambda e: self.entry_login_2fa.focus())

        self.entry_login_2fa = ctk.CTkEntry(container, placeholder_text="2FA Code", height=50, 
                                            font=("Roboto", 14), border_width=0, fg_color="#222222")
        self.entry_login_2fa.pack(fill="x", pady=10)

        ctk.CTkButton(container, text="UNLOCK VAULT", height=50, fg_color=COLOR_ACCENT, hover_color=COLOR_ACCENT_HOVER,
                      text_color="black", font=("Roboto", 12, "bold"), command=self.process_login).pack(fill="x", pady=30)
        
        self.lbl_login_status = ctk.CTkLabel(container, text="", text_color=COLOR_DANGER, anchor="w")
        self.lbl_login_status.pack(fill="x")

    def process_login(self):
        pwd = self.entry_login_pwd.get()
        code = self.entry_login_2fa.get()
        data = database.load_vault()
        
        if not data:
             self.lbl_login_status.configure(text="> DATABASE ERROR")
             return

        if not auth.verify_master_password(data['header']['pwd_hash'], pwd):
            self.lbl_login_status.configure(text="> ACCESS DENIED: PASSWORD INVALID")
            return

        totp_data = crypto.decrypt_casket(data['header']['totp_blob'], pwd)
        if not totp_data:
            self.lbl_login_status.configure(text="> CRITICAL: KEY MISMATCH")
            return
            
        if not auth.verify_totp(totp_data['secret'], code):
            self.lbl_login_status.configure(text="> ACCESS DENIED: INVALID 2FA")
            return

        self.password = pwd
        self.vault_data = crypto.decrypt_casket(data['vault'], pwd)
        
        if self.vault_data:
            self.show_dashboard_interface()
        else:
            self.lbl_login_status.configure(text="> DATABASE CORRUPTED")

    # ==========================================================
    # 3. DASHBOARD INTERFACE
    # ==========================================================
    def show_dashboard_interface(self):
        self.clear_main_area()
        self.configure(fg_color=COLOR_BG)
        self.unbind('<Return>')

        # Sidebar
        self.sidebar = ctk.CTkFrame(self, width=220, corner_radius=0, fg_color=COLOR_SIDEBAR)
        self.sidebar.grid(row=0, column=0, sticky="nsew")
        self.sidebar.grid_rowconfigure(4, weight=1)

        ctk.CTkLabel(self.sidebar, text="VOID\nCASKET", font=("Impact", 28), text_color=COLOR_ACCENT).grid(row=0, column=0, padx=20, pady=(30, 20), sticky="w")
        ctk.CTkLabel(self.sidebar, text="SECURE STORAGE", font=("Consolas", 10), text_color="gray").grid(row=1, column=0, padx=20, sticky="w")

        btn_vault = ctk.CTkButton(self.sidebar, text="  :: VAULT", height=40, anchor="w", fg_color="#1f1f1f", text_color=COLOR_ACCENT, font=("Consolas", 12, "bold"))
        btn_vault.grid(row=2, column=0, padx=10, pady=(30, 5), sticky="ew")

        btn_lock = ctk.CTkButton(self.sidebar, text="  [X] LOCK SYSTEM", height=40, anchor="w", fg_color="transparent", 
                                 text_color=COLOR_DANGER, hover_color="#220000", font=("Consolas", 12), command=self.lock_vault)
        btn_lock.grid(row=5, column=0, padx=10, pady=20, sticky="ew")

        # Main Panel
        self.main_panel = ctk.CTkFrame(self, corner_radius=0, fg_color=COLOR_PANEL)
        self.main_panel.grid(row=0, column=1, sticky="nsew")
        self.main_panel.grid_rowconfigure(2, weight=1)
        self.main_panel.grid_columnconfigure(0, weight=1)

        header_frame = ctk.CTkFrame(self.main_panel, height=60, fg_color="transparent")
        header_frame.grid(row=0, column=0, sticky="ew", padx=20, pady=10)

        self.search_var = ctk.StringVar()
        self.search_var.trace("w", self.filter_list)
        
        search_entry = ctk.CTkEntry(header_frame, textvariable=self.search_var, placeholder_text="// Search Database...", 
                                    width=400, height=40, font=("Consolas", 12), border_width=1, border_color="#333", fg_color="#0d0d0d")
        search_entry.pack(side="left")

        add_btn = ctk.CTkButton(header_frame, text="+ NEW ENTRY", width=120, height=40, fg_color=COLOR_ACCENT, 
                                text_color="black", font=("Roboto", 12, "bold"), command=self.open_add_dialog)
        add_btn.pack(side="right")

        self.scroll_frame = ctk.CTkScrollableFrame(self.main_panel, fg_color="#141414")
        self.scroll_frame.grid(row=2, column=0, sticky="nsew", padx=20, pady=(0, 20))

        self.status_bar = ctk.CTkLabel(self.main_panel, text="> SYSTEM READY. WAITING FOR INPUT.", 
                                       anchor="w", font=("Consolas", 11), text_color="gray", fg_color="#0d0d0d", height=30)
        self.status_bar.grid(row=3, column=0, sticky="ew", padx=0, pady=0)
        self.status_bar.configure(padx=15)

        self.refresh_password_list()

    # --- LOGIC & HELPERS ---
    def lock_vault(self):
        self.vault_data = None
        self.password = None
        self.show_login_interface()

    def set_status(self, text, type="info"):
        color = COLOR_DANGER if type == "error" else COLOR_SUCCESS if type == "success" else "gray"
        self.status_bar.configure(text=f"> {text.upper()}", text_color=color)

    def filter_list(self, *args):
        query = self.search_var.get()
        self.refresh_password_list(query)

    def refresh_password_list(self, query=""):
        for widget in self.scroll_frame.winfo_children():
            widget.destroy()

        query = query.lower()
        passwords = self.vault_data.get("passwords", [])
        
        count = 0
        for i, entry in enumerate(passwords):
            if query in entry['service'].lower() or query in entry['username'].lower():
                self.create_entry_row(entry, i)
                count += 1
        
        if count == 0:
            ctk.CTkLabel(self.scroll_frame, text="NO ENTRIES FOUND", font=("Consolas", 14), text_color="gray").pack(pady=40)

    def create_entry_row(self, entry, index):
        row = ctk.CTkFrame(self.scroll_frame, fg_color="#1f1f1f", corner_radius=5, height=50)
        row.pack(fill="x", pady=2, padx=5)

        # Labels
        ctk.CTkLabel(row, text=entry['service'], font=("Roboto Medium", 14), width=180, anchor="w", text_color="white").pack(side="left", padx=15, pady=10)
        ctk.CTkLabel(row, text=entry['username'], font=("Consolas", 12), text_color="gray", width=200, anchor="w").pack(side="left", padx=5)

        # BUTTONS (Delete | User | Pass)
        # Delete Button (Red Trash Icon style)
        btn_del = ctk.CTkButton(row, text="DEL", width=40, height=25, fg_color="#440000", hover_color="#880000", text_color="red",
                                font=("Consolas", 10, "bold"), command=lambda: self.delete_entry(index))
        btn_del.pack(side="right", padx=(5, 15))

        # Copy Password
        btn_pass = ctk.CTkButton(row, text="PASS", width=50, height=25, fg_color="#333", hover_color="#444", 
                                 font=("Consolas", 10, "bold"), command=lambda: self.copy_to_clip(entry['service'], entry['password'], "Password"))
        btn_pass.pack(side="right", padx=2)

        # Copy User
        btn_user = ctk.CTkButton(row, text="USER", width=50, height=25, fg_color="#222", hover_color="#333", 
                                 font=("Consolas", 10, "bold"), command=lambda: self.copy_to_clip(entry['service'], entry['username'], "Username"))
        btn_user.pack(side="right", padx=2)

    def delete_entry(self, index):
        # Remove item at index
        removed = self.vault_data['passwords'].pop(index)
        
        # Save changes
        new_blob = crypto.encrypt_casket(self.vault_data, self.password)
        old_header = database.load_vault()['header']
        database.save_vault(old_header, new_blob)
        
        self.refresh_password_list(self.search_var.get())
        self.set_status(f"ENTRY DELETED: {removed['service']}", "error")

    def copy_to_clip(self, service, text, data_type):
        self.clipboard_clear()
        self.clipboard_append(text)
        self.update()
        
        self.set_status(f"{data_type} for {service} COPIED (Autoclear in 10s)", "success")
        
        # Security: Clear clipboard after 10 seconds
        self.after(10000, lambda: self.clear_clipboard_securely())

    def clear_clipboard_securely(self):
        self.clipboard_clear()
        self.update()
        # Only update status if it hasn't changed to something else important
        if "COPIED" in self.status_bar.cget("text"):
            self.set_status("CLIPBOARD CLEARED FOR SECURITY", "info")

    def open_add_dialog(self):
        dialog = ctk.CTkToplevel(self)
        dialog.title("ADD ENTRY")
        dialog.geometry("400x400")
        dialog.configure(fg_color=COLOR_PANEL)
        dialog.attributes("-topmost", True)
        
        ctk.CTkLabel(dialog, text="NEW CREDENTIAL", font=("Impact", 24), text_color=COLOR_ACCENT).pack(pady=(20, 20))

        e_service = ctk.CTkEntry(dialog, placeholder_text="Service (e.g. Gmail)", width=300, height=40, font=("Roboto", 12))
        e_service.pack(pady=10)
        e_user = ctk.CTkEntry(dialog, placeholder_text="Username / Email", width=300, height=40, font=("Roboto", 12))
        e_user.pack(pady=10)
        e_pass = ctk.CTkEntry(dialog, placeholder_text="Password", width=300, height=40, font=("Roboto", 12))
        e_pass.pack(pady=10)

        def save(event=None):
            new_entry = {
                "service": e_service.get(),
                "username": e_user.get(),
                "password": e_pass.get()
            }
            if new_entry['service'] and new_entry['password']:
                self.vault_data['passwords'].append(new_entry)
                new_blob = crypto.encrypt_casket(self.vault_data, self.password)
                old_header = database.load_vault()['header']
                database.save_vault(old_header, new_blob)
                
                self.refresh_password_list()
                self.set_status("NEW ENTRY ENCRYPTED AND SAVED", "success")
                dialog.destroy()

        dialog.bind('<Return>', save)
        ctk.CTkButton(dialog, text="SAVE TO VAULT", width=300, height=45, fg_color=COLOR_ACCENT, text_color="black", 
                      font=("Roboto", 12, "bold"), command=save).pack(pady=30)

if __name__ == "__main__":
    app = VoidCasketApp()
    app.mainloop()