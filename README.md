# secure-aes-crypt

一个本地使用的 AES-256-GCM 加解密工具，适用于加密 GitHub Token、API 密钥等敏感数据。

> ⚠️ **这不是“防破解”玩具，而是生产级安全工具——但前提是正确使用！**

## 🔐 安全特性
- 使用 PBKDF2 + 600,000 次迭代派生密钥（抗暴力破解）
- 每次加密生成随机 Salt 和 Nonce
- AES-256-GCM 提供保密性 + 完整性认证
- 密码输入隐藏（`getpass`）
- 输出为 Base64 字符串（便于存储）

## 🛑 重要警告
1. **推荐使用高强度密码**（≥12位，含大小写字母、数字、符号）
   - ❌ 禁止使用生日、手机号、姓名、常见单词
   - ✅ 推荐用 [Bitwarden](https) 或 `openssl rand -base64 24` 生成
2. **不要将加密后的字符串与密码存放在同一位置**
3. **本工具仅用于本地，不提供网络传输安全**


# secure-aes-crypt

A locally used AES-256-GCM encryption and decryption tool, suitable for encrypting sensitive data such as GitHub Tokens and API keys.

> ⚠️ ** this is not a "crack prevention" toy, but a production-level security tool - but only if used correctly! **

## 🔐 safety features
- Use PBKDF2 + 600,000 iterations to derive the key (resistant to brute-force cracking)
Each encryption generates a random Salt and Nonce
-AES-256-GCM provides confidentiality and integrity authentication
- Password input hidden (' getpass ')
Output as a Base64 string (for easy storage)

Important Warnings: 🛑
1. ** It is recommended to use a strong password ** (≥12 characters, including both upper and lower case letters, numbers, and symbols)
- ❌ do not use birthdays, mobile phone numbers, names, common words
- ✅ is recommended to be generated using [Bitwarden](https) or 'openssl rand-base64 24'
2. Do not store the encrypted string in the same location as the password
3. This tool is only for local use and does not provide network transmission security