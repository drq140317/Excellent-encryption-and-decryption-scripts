#!/usr/bin/env python3
import os
import sys
import base64
from getpass import getpass
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

# 参数（可调，但不要降低安全性）
SALT_SIZE = 16        # 128-bit salt
NONCE_SIZE = 12       # GCM standard
KEY_SIZE = 32         # AES-256
PBKDF2_ITERATIONS = 600000  # 足够慢以抗暴力破解（约0.1~0.5秒）

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
        raise ValueError("密文太短，可能已损坏")
    
    salt = data[:SALT_SIZE]
    nonce = data[SALT_SIZE:SALT_SIZE + NONCE_SIZE]
    ciphertext = data[SALT_SIZE + NONCE_SIZE:]
    
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    return plaintext.decode('utf-8')

def main():
    print("🔐 AES-GCM 加解密工具（支持敏感数据）")
    print("⚠️  请使用高强度密码（建议12位以上，含大小写字母、数字、符号）")
    print("1. 加密文本")
    print("2. 解密文本")
    
    choice = input("请选择 (1/2): ").strip()
    
    password = getpass("请输入高强度密码（输入时不可见）: ")
    if not password:
        print("❌ 密码不能为空")
        return

    if choice == '1':
        text = input("请输入要加密的文本: ")
        if not text:
            print("❌ 文本不能为空")
            return
        try:
            encrypted = encrypt(text, password)
            print("\n🔒 加密成功！保存以下字符串（可存入笔记/云盘）:")
            print(encrypted)
            print("\n💡 提示：解密时需用相同密码")
        except Exception as e:
            print(f"❌ 加密失败: {e}")
            
    elif choice == '2':
        b64_text = input("请输入加密后的 Base64 字符串: ")
        if not b64_text:
            print("❌ 密文不能为空")
            return
        try:
            decrypted = decrypt(b64_text, password)
            print("\n🔓 解密成功:")
            print(decrypted)
        except Exception as e:
            print(f"❌ 解密失败（密码错误或数据损坏）: {e}")
    else:
        print("❌ 无效选择")

if __name__ == "__main__":
    main()
