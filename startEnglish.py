#!/usr/bin/env python3
import os
import sys
import base64
from getpass import getpass
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

# Parameters (adjustable, but do not reduce security)
SALT_SIZE = 16        # 128-bit salt
NONCE_SIZE = 12       # GCM standard
KEY_SIZE = 32         # AES-256
PBKDF2_ITERATIONS = 600000  # Sufficiently slow to resist brute-force (~0.1~0.5 seconds)

def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return kdf.derive(password.encode('utf-8'))

def encrypt(plaintext: str, password: str) -> str:
    salt = os.urandom(SALT_SIZE)
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    nonce = os.urandom(NONCE_SIZE)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode('utf-8'), None)

    combined = salt + nonce + ciphertext
    return base64.b64encode(combined).decode('utf-8')

def decrypt(b64_ciphertext: str, password: str) -> str:
    data = base64.b64decode(b64_ciphertext)
    if len(data) < SALT_SIZE + NONCE_SIZE:
        raise ValueError("Ciphertext too short; possibly corrupted")
    
    salt = data[:SALT_SIZE]
    nonce = data[SALT_SIZE:SALT_SIZE + NONCE_SIZE]
    ciphertext = data[SALT_SIZE + NONCE_SIZE:]
    
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    return plaintext.decode('utf-8')

def main():
    print("🔐 AES-GCM Encryption/Decryption Tool (for sensitive data)")
    print("⚠️  Please use a strong password (recommended: 12+ characters with uppercase, lowercase, digits, and symbols)")
    print("1. Encrypt text")
    print("2. Decrypt text")
    
    choice = input("Select an option (1/2): ").strip()
    
    password = getpass("Enter a strong password (input is hidden): ")
    if not password:
        print("❌ Password cannot be empty")
        return

    if choice == '1':
        text = input("Enter the text to encrypt: ")
        if not text:
            print("❌ Text cannot be empty")
            return
        try:
            encrypted = encrypt(text, password)
            print("\n🔒 Encryption successful! Save the following string (you can store it in notes/cloud storage):")
            print(encrypted)
            print("\n💡 Tip: Use the same password to decrypt later")
        except Exception as e:
            print(f"❌ Encryption failed: {e}")
            
    elif choice == '2':
        b64_text = input("Enter the Base64-encoded encrypted string: ")
        if not b64_text:
            print("❌ Ciphertext cannot be empty")
            return
        try:
            decrypted = decrypt(b64_text, password)
            print("\n🔓 Decryption successful:")
            print(decrypted)
        except Exception as e:
            print(f"❌ Decryption failed (incorrect password or corrupted data): {e}")
    else:
        print("❌ Invalid selection")

if __name__ == "__main__":
    main()
