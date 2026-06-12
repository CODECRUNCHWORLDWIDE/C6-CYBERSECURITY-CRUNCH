# Cybersecurity Hashing & Encryption Demos

## Overview
This repository contains hands-on demonstrations of cryptographic hashing (MD5, SHA-256) and encryption using OpenSSL.

---

## 📌 Hashing Algorithms

### **MD5 Hashing Example**
MD5 generates a **128-bit hash (32 characters)**. It is **fast** but **insecure** due to collision vulnerabilities.

#### **Linux Command:**
```bash
echo -n "mypassword" | md5sum
```
📌 **Example Output:**
```
34819d7beeabb9260a5c854bc85b3e44  -
```
⚠️ **Warning:** MD5 is outdated and should NOT be used for passwords.

### **SHA-256 Hashing Example**
SHA-256 generates a **256-bit hash (64 characters)** and is highly secure.

#### **Linux Command:**
```bash
echo -n "mypassword" | sha256sum
```
📌 **Example Output:**
```
b109f3bbbc244eb82441917ed06d618b9008dd09c84d28e93b8b1b8691cde1a1  -
```
✅ **Use SHA-256 for security applications.**

---

## 🔐 OpenSSL Encryption

### **Generating an RSA Key Pair**
```bash
openssl genpkey -algorithm RSA -out private_key.pem
openssl rsa -pubout -in private_key.pem -out public_key.pem
```
Generates a **private key** and extracts the **public key**.

### **Encrypting a Message Using RSA**
```bash
echo "Hello, World!" > message.txt
openssl rsautl -encrypt -pubin -inkey public_key.pem -in message.txt -out encrypted_msg.bin
```

### **Decrypting the Message**
```bash
openssl rsautl -decrypt -inkey private_key.pem -in encrypted_msg.bin
```
📌 **RSA is widely used for secure data transmission.**

---

---

## 💡 Additional Learning
- **MD5 vs SHA-256:** [Read More](https://en.wikipedia.org/wiki/Cryptographic_hash_function)
- **OpenSSL Documentation:** [OpenSSL.org](https://www.openssl.org/docs/)

