# 🔐 MPSynapse Folder Locker

A sleek and secure Python-based folder locker and unlocker built with `Tkinter` and `cryptography`. Encrypt and compress your folders into `.safe` files, and decrypt them back with ease.

![App Screenshot](https://github.com/Itz-Shashwat/MPSynapse-Folder-Locker/assets/your_screenshot_path) <!-- Optional: replace with a screenshot of your app -->

---

## 🚀 Features

- **Lock Folders:** Compress and encrypt folders into a `.safe` file using password-based encryption.
- **Unlock Files:** Decrypt `.safe` files using your password and view the file structure.
- **Explore Files:** Double-click to open files directly from the unlocked view.
- **Password-Based Encryption:** Uses secure SHA-256 and Fernet encryption for safety.
- **Cross-platform UI:** Built with `Tkinter` for a native look across operating systems.
- **Switch Modes Easily:** One-click toggle between Lock and Unlock interfaces.

---

## 🖥️ Download

👉 [Click here to download the latest `.exe` (Windows)](https://github.com/Itz-Shashwat/MPSynapse-Folder-Locker/blob/main/MySynapse%20Folder%20Locker.exe?raw=true)

> ⚠️ This is a Windows executable. For other platforms, clone the repo and run the Python script.

---

## 📦 How to Use

### 🔒 Lock a Folder

1. Launch the app.
2. Select a folder using the **Browse** button.
3. Enter a password.
4. Click **LOCK FOLDER**.
5. The original folder will be converted into an encrypted `.safe` file and deleted from disk.

### 🔓 Unlock a File

1. Switch to Unlock Mode using the toggle button.
2. Select a `.safe` file using **Browse**.
3. Enter the correct password.
4. Click **UNLOCK & VIEW**.
5. Decrypted contents will be shown in a file tree.
6. Double-click any file to open it.

---

## ⚙️ Tech Stack

- `Python 3`
- `Tkinter` - GUI
- `cryptography` - Encryption/Decryption
- `zipfile`, `shutil`, `os`, `tempfile` - File handling
- `Fernet` for AES-based symmetric encryption

---

## 🛡️ Security Note

This app uses strong symmetric encryption with keys derived using SHA-256. However, **always remember your password**—there is no way to recover data without it.

---

## 📁 Run from Source (For Developers)

```bash
git clone https://github.com/Itz-Shashwat/MPSynapse-Folder-Locker.git
cd MPSynapse-Folder-Locker
pip install -r requirements.txt
python app.py
