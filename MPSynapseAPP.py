import os
import shutil
import zipfile
import base64
import hashlib
import tempfile
import platform
import subprocess
from cryptography.fernet import Fernet
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

# Configuration constants
BG_COLOR = "#f0f0f0"
ACCENT_COLOR = "#2c3e50"
BUTTON_COLOR = "#3498db"
LOCK_COLOR = "#e74c3c"
UNLOCK_COLOR = "#2ecc71"

def derive_key(password):
    return base64.urlsafe_b64encode(hashlib.sha256(password.encode()).digest())

class MPSynapseApp:
    def __init__(self, root):
        self.root = root
        self.temp_dir = None
        self.current_mode = tk.StringVar(value="lock")
        self.style = ttk.Style()
        self.style.theme_use('clam')
        self.configure_styles()
        
        self.setup_ui()

    def configure_styles(self):
        self.style.configure('TFrame', background=BG_COLOR)
        self.style.configure('TLabel', background=BG_COLOR, font=('Helvetica', 10))
        self.style.configure('TButton', font=('Helvetica', 10))
        self.style.configure('ModeSwitch.TButton', font=('Helvetica', 10, 'bold'), padding=10)
        self.style.configure('Treeview', font=('Helvetica', 10), rowheight=25)
        self.style.configure('Treeview.Heading', font=('Helvetica', 11, 'bold'))
        self.style.configure('TEntry', font=('Helvetica', 10))
        self.style.configure('Lock.TButton', background=LOCK_COLOR, foreground='white')
        self.style.configure('Unlock.TButton', background=UNLOCK_COLOR, foreground='white')

    def setup_ui(self):
        self.root.title("MPSynapse Technologies - Secure File Manager")
        self.root.geometry("800x650")
        self.root.configure(bg=BG_COLOR)
        self.root.resizable(True, True)
        header_frame = ttk.Frame(self.root)
        header_frame.pack(fill='x', pady=10, padx=20)
        
        ttk.Label(header_frame, text="🔒 MPSynapse Technologies", 
                 font=('Helvetica', 16, 'bold'), foreground=ACCENT_COLOR).pack(side='left')

        self.mode_switch = ttk.Button(header_frame, text="Switch to Unlock Mode", 
                                    command=self.toggle_mode, style='ModeSwitch.TButton')
        self.mode_switch.pack(side='right', padx=10)
        self.update_mode_style()

        self.lock_frame = ttk.Frame(self.root)
        self.unlock_frame = ttk.Frame(self.root)
        self.create_lock_ui()
        self.create_unlock_ui()
        self.show_current_mode()

    def toggle_mode(self):
        self.current_mode.set("unlock" if self.current_mode.get() == "lock" else "lock")
        self.update_mode_style()
        self.show_current_mode()
        self.cleanup_temp()

    def update_mode_style(self):
        if self.current_mode.get() == "lock":
            self.mode_switch.configure(text="Switch to Unlock Mode", style='Lock.TButton')
        else:
            self.mode_switch.configure(text="Switch to Lock Mode", style='Unlock.TButton')

        self.style.configure('Lock.TButton', background=LOCK_COLOR, foreground='white')
        self.style.configure('Unlock.TButton', background=UNLOCK_COLOR, foreground='white')

    def show_current_mode(self):
        if self.current_mode.get() == "lock":
            self.unlock_frame.pack_forget()
            self.lock_frame.pack(fill='both', expand=True, padx=20, pady=10)
        else:
            self.lock_frame.pack_forget()
            self.unlock_frame.pack(fill='both', expand=True, padx=20, pady=10)

    def create_lock_ui(self):
        folder_frame = ttk.Frame(self.lock_frame)
        folder_frame.pack(fill='x', pady=10)
        ttk.Label(folder_frame, text="Select Folder:").pack(side='left', padx=(0, 10))
        self.lock_folder_entry = ttk.Entry(folder_frame, width=50)
        self.lock_folder_entry.pack(side='left', expand=True, fill='x', padx=(0, 5))
        ttk.Button(folder_frame, text="Browse", command=self.browse_lock_folder).pack(side='left')

        pass_frame = ttk.Frame(self.lock_frame)
        pass_frame.pack(fill='x', pady=10)
        ttk.Label(pass_frame, text="Enter Password:").pack(side='left', padx=(0, 10))
        self.lock_password_entry = ttk.Entry(pass_frame, width=50, show="*")
        self.lock_password_entry.pack(side='left', expand=True, fill='x')

        btn_frame = ttk.Frame(self.lock_frame)
        btn_frame.pack(pady=15)
        self.lock_btn = ttk.Button(btn_frame, text="LOCK FOLDER", command=self.lock_action, 
                                 style='Lock.TButton')
        self.lock_btn.pack(pady=10, ipadx=20)

    def create_unlock_ui(self):
        file_frame = ttk.Frame(self.unlock_frame)
        file_frame.pack(fill='x', pady=10)
        ttk.Label(file_frame, text="Select .safe File:").grid(row=0, column=0, sticky='w')
        self.unlock_file_entry = ttk.Entry(file_frame, width=50)
        self.unlock_file_entry.grid(row=1, column=0, padx=(0, 10))
        ttk.Button(file_frame, text="Browse", command=self.browse_unlock_file).grid(row=1, column=1)

        pass_frame = ttk.Frame(self.unlock_frame)
        pass_frame.pack(fill='x', pady=10)
        ttk.Label(pass_frame, text="Enter Password:").grid(row=0, column=0, sticky='w')
        self.unlock_password_entry = ttk.Entry(pass_frame, width=50, show="•")
        self.unlock_password_entry.grid(row=1, column=0, padx=(0, 10))

        btn_frame = ttk.Frame(self.unlock_frame)
        btn_frame.pack(pady=15)
        self.unlock_btn = ttk.Button(btn_frame, text="UNLOCK & VIEW", command=self.unlock_action,
                                    style='Unlock.TButton')
        self.unlock_btn.pack(pady=10, ipadx=20)

        tree_frame = ttk.Frame(self.unlock_frame)
        tree_frame.pack(fill='both', expand=True)
        
        self.tree = ttk.Treeview(tree_frame, columns=('path'), show='tree')
        self.tree.heading('#0', text='File Structure', anchor='w')
        
        vsb = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree.yview)
        hsb = ttk.Scrollbar(tree_frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        
        self.tree.grid(row=0, column=0, sticky='nsew')
        vsb.grid(row=0, column=1, sticky='ns')
        hsb.grid(row=1, column=0, sticky='ew')
        
        tree_frame.grid_columnconfigure(0, weight=1)
        tree_frame.grid_rowconfigure(0, weight=1)
        
        self.tree.bind("<Double-1>", self.open_file)

    def browse_lock_folder(self):
        folder = filedialog.askdirectory()
        if folder:
            self.lock_folder_entry.delete(0, tk.END)
            self.lock_folder_entry.insert(0, folder)

    def browse_unlock_file(self):
        file_path = filedialog.askopenfilename(filetypes=[("Safe Files", "*.safe")])
        if file_path:
            self.unlock_file_entry.delete(0, tk.END)
            self.unlock_file_entry.insert(0, file_path)

    def lock_action(self):
        folder = self.lock_folder_entry.get()
        password = self.lock_password_entry.get()
        if not folder or not password:
            messagebox.showwarning("Input Required", "Please select a folder and enter a password.")
            return

        try:
            zip_path = folder + ".zip"
            safe_path = folder + ".safe"

            shutil.make_archive(zip_path.replace(".zip", ""), 'zip', folder)

            key = derive_key(password)
            with open(zip_path, 'rb') as f:
                data = f.read()
            fernet = Fernet(key)
            encrypted = fernet.encrypt(data)
            with open(safe_path, 'wb') as f:
                f.write(encrypted)

            os.remove(zip_path)
            shutil.rmtree(folder)

            messagebox.showinfo("Success", f"🔒 Folder locked and saved as:\n{safe_path}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to lock folder:\n{str(e)}")

    def unlock_action(self):
        file_path = self.unlock_file_entry.get()
        password = self.unlock_password_entry.get()
        
        if not file_path or not password:
            messagebox.showwarning("Input Required", "Please select a .safe file and enter password.")
            return

        try:
            key = derive_key(password)
            with open(file_path, 'rb') as f:
                encrypted = f.read()
            fernet = Fernet(key)
            decrypted_data = fernet.decrypt(encrypted)
        except Exception as e:
            messagebox.showerror("Decryption Failed", "❌ Incorrect password or corrupted file.")
            return

        self.cleanup_temp()
        self.temp_dir = tempfile.mkdtemp()

        try:
            temp_zip = os.path.join(self.temp_dir, "temp.zip")
            with open(temp_zip, 'wb') as f:
                f.write(decrypted_data)

            with zipfile.ZipFile(temp_zip, 'r') as zip_ref:
                zip_ref.extractall(self.temp_dir)

            os.remove(temp_zip)
            
            for item in self.tree.get_children():
                self.tree.delete(item)
                
            self.populate_tree("", self.temp_dir)
            messagebox.showinfo("Success", "🔓 Folder unlocked successfully!")
        except zipfile.BadZipFile:
            messagebox.showerror("Error", "The decrypted file is not a valid ZIP archive")
            self.cleanup_temp()

    def populate_tree(self, parent, path):
        try:
            for item in sorted(os.listdir(path)):
                abs_path = os.path.join(path, item)
                is_dir = os.path.isdir(abs_path)
                icon = '📁' if is_dir else '📄'
                node = self.tree.insert(parent, "end", text=f" {icon} {item}", 
                                      values=[abs_path], open=False)
                if is_dir:
                    self.populate_tree(node, abs_path)
        except PermissionError:
            messagebox.showwarning("Access Denied", f"Permission denied for: {abs_path}")

    def open_file(self, event):
        selected = self.tree.focus()
        if not selected:
            return
        path = self.tree.item(selected, "values")[0]
        if os.path.isfile(path):
            try:
                if platform.system() == 'Windows':
                    os.startfile(path)
                elif platform.system() == 'Darwin':
                    subprocess.call(['open', path])
                else:
                    subprocess.call(['xdg-open', path])
            except Exception as e:
                messagebox.showerror("Open Failed", f"Cannot open file: {str(e)}")

    def cleanup_temp(self):
        if self.temp_dir and os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir, ignore_errors=True)

    def on_closing(self):
        self.cleanup_temp()
        self.root.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    app = MPSynapseApp(root)
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    root.mainloop()