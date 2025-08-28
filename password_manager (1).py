import os
import json
import hashlib
import base64
import random
import string
import getpass
from cryptography.fernet import Fernet

# --------------------------
# File paths
# --------------------------
MASTER_FILE = "master.json"
KEY_FILE = "secret.key"
DATA_FILE = "passwords.txt"

# --------------------------
# Helper Functions
# --------------------------
def generate_key():
    return Fernet.generate_key()

def load_key():
    if not os.path.exists(KEY_FILE):
        key = generate_key()
        with open(KEY_FILE, "wb") as f:
            f.write(key)
    else:
        with open(KEY_FILE, "rb") as f:
            key = f.read()
    return key

def get_fernet():
    return Fernet(load_key())

def hash_password(password, salt=None):
    if salt is None:
        salt = os.urandom(16)
    hashed = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100000)
    return base64.b64encode(salt + hashed).decode()

def verify_password(password, stored_hash):
    decoded = base64.b64decode(stored_hash.encode())
    salt, stored = decoded[:16], decoded[16:]
    hashed = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100000)
    return hashed == stored

def ensure_master():
    if not os.path.exists(MASTER_FILE):
        print("🔑 No master password set. Create one now.")
        pwd = getpass.getpass("Set master password: ")
        hashed = hash_password(pwd)
        with open(MASTER_FILE, "w") as f:
            json.dump({"hash": hashed}, f)
        print("✅ Master password set successfully.")
    else:
        with open(MASTER_FILE, "r") as f:
            data = json.load(f)
        attempts = 3
        while attempts > 0:
            pwd = getpass.getpass("Enter master password: ")
            if verify_password(pwd, data["hash"]):
                print("✅ Access granted.")
                return
            attempts -= 1
            print(f"❌ Incorrect. {attempts} tries left.")
        print("⚠️ Too many failed attempts. Resetting system...")
        reset_system()

def reset_system():
    for f in [MASTER_FILE, KEY_FILE, DATA_FILE]:
        if os.path.exists(f):
            os.remove(f)
    print("🔄 System reset. Please restart the program to set a new master password.")
    exit()

def encrypt_password(password):
    return get_fernet().encrypt(password.encode()).decode()

def decrypt_password(enc_password):
    return get_fernet().decrypt(enc_password.encode()).decode()

def save_entry(name, username, password):
    enc_pwd = encrypt_password(password)
    with open(DATA_FILE, "a") as f:
        f.write(f"{name}|{username}|{enc_pwd}\n")
    print(f"✅ Saved {name}")

def list_entries():
    if not os.path.exists(DATA_FILE):
        print("📂 No entries found.")
        return
    with open(DATA_FILE, "r") as f:
        for line in f:
            name, username, enc_pwd = line.strip().split("|")
            print(f"📌 {name} (user: {username})")

def view_entry(name):
    if not os.path.exists(DATA_FILE):
        print("📂 No entries found.")
        return
    with open(DATA_FILE, "r") as f:
        for line in f:
            n, username, enc_pwd = line.strip().split("|")
            if n == name:
                print(f"🔑 {name} -> {decrypt_password(enc_pwd)}")
                return
    print("❌ Not found.")

def generate_password(length=12):
    chars = string.ascii_letters + string.digits + string.punctuation
    return "".join(random.choice(chars) for _ in range(length))

# --------------------------
# Main Menu
# --------------------------
def main():
    ensure_master()
    while True:
        print("\n=== Password Manager ===")
        print("1. Add entry")
        print("2. List entries")
        print("3. View entry")
        print("4. Generate strong password")
        print("5. Reset system")
        print("6. Exit")
        choice = input("Choose: ")

        if choice == "1":
            name = input("Service name: ")
            username = input("Username: ")
            pwd = getpass.getpass("Password (leave blank to auto-generate): ")
            if not pwd:
                pwd = generate_password()
                print(f"🔑 Generated: {pwd}")
            save_entry(name, username, pwd)
        elif choice == "2":
            list_entries()
        elif choice == "3":
            name = input("Service name: ")
            view_entry(name)
        elif choice == "4":
            length = int(input("Length of password: "))
            print(f"🔑 {generate_password(length)}")
        elif choice == "5":
            confirm = input("Type RESET to confirm: ")
            if confirm == "RESET":
                reset_system()
        elif choice == "6":
            print("👋 Goodbye")
            break
        else:
            print("❌ Invalid choice")

if __name__ == "__main__":
    main()
