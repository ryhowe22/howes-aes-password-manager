import os
import json
import base64
from getpass import getpass
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import hmac
SALT_SIZE = 16
KEY_SIZE = 32
IV_SIZE = 16
PBKDF2_ITERATIONS = 200_000
VAULT_FILE = "vault.enc"
CONFIG_FILE = "config.json"

# Beginning of the configuration loader function
def load_config():
    if not os.path.exists(CONFIG_FILE):
        salt = os.urandom(SALT_SIZE)
        config_data = {"salt": base64.b64encode(salt).decode()}
        with open(CONFIG_FILE, "w") as f:
            json.dump(config_data, f)
        return salt 
    else:
        with open(CONFIG_FILE, "r") as f:
            config = json.load(f)
            salt = base64.b64decode(config["salt"])
        return salt
def derive_key(password: str, salt: bytes) -> bytes:
    password_bytes = password.encode()
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
        )
    key = kdf.derive(password_bytes)
    return key
def encrypt_data(key: bytes, plaintext: bytes) -> tuple[bytes, bytes]:
    padder = padding.PKCS7(128).padder()
    padded_plaintext = padder.update(plaintext) + padder.finalize()
    iv = os.urandom(IV_SIZE)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
    return iv, ciphertext
def decrypt_data(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
    return plaintext
def load_vault(key: bytes) -> dict:
    if not os.path.exists(VAULT_FILE):
        return {}
    with open(VAULT_FILE, "r") as f:
        data = json.load(f)
    iv = base64.b64decode(data["iv"])
    ciphertext = base64.b64decode(data["ciphertext"])
    plaintext = decrypt_data(key, iv, ciphertext)
    vault = json.loads(plaintext.decode())
    return vault
def save_vault(key:bytes, vault: dict) -> None:
    plaintext = json.dumps(vault).encode()
    iv, ciphertext = encrypt_data(key, plaintext)
    data_to_store = {
        "iv": base64.b64encode(iv).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode()
    }
    with open(VAULT_FILE, "w") as f:
        json.dump(data_to_store, f)
    print("\nVault saved to", VAULT_FILE)
def get_master_key() -> bytes:
    """
    Ask the user for their master password and derive the AES key.
    """
    salt = load_config()
    password = getpass("Enter your master password: ")
    key = derive_key(password, salt)
    return key
def main():
    print("=== Howe's AES Password Manager ===")
    key = get_master_key()
    vault = load_vault(key)
    while True:  
        print("\nMenu:")
        print("1) List entries")
        print("2) Add entry")
        print("3) Delete entry")
        print("4) Save and exit ")
        choice = input("Choose an option: ").strip()
        if choice == "1":
            if not vault:
                print("\nVault is empty.")
            else:
                print("\nStored entries:")
                for name, entry in vault.items():
                    print(f" - {name}: {entry}")
        elif choice == "2":
            name = input("Entry name (e.g., gmail): ").strip()
            username = input("Username: ").strip()
            password = input("Password: ").strip()
            vault[name] = {"username": username, "password": password}
            print(f"Added entry '{name}'.")
        elif choice == "3":
            name = input("Entry name to delete: ").strip()
            if name in vault:
                del vault[name]
                print(f"Deleted entry '{name}'.")
            else:
                print(f"No entry fnamed '{name}'.")
        elif choice == "4":
            save_vault(key, vault)
            break
        else:
            print("Invalid option. Please try again.")
if __name__ == "__main__":
    main()