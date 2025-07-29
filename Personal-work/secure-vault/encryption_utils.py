from Crypto.Cipher import AES, DES, DES3, Blowfish
from Crypto.Util.Padding import pad, unpad
from base64 import b64encode, b64decode
from cryptography.fernet import Fernet
import hashlib

# AES encryption/decryption with CBC mode and PKCS7 padding
def aes_encrypt(data, key):
    key_bytes = hashlib.sha256(key.encode()).digest()
    cipher = AES.new(key_bytes, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(data, AES.block_size))
    return cipher.iv + ct_bytes  # prepend iv

def aes_decrypt(data, key):
    key_bytes = hashlib.sha256(key.encode()).digest()
    iv = data[:16]      
    ct = data[16:]
    cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct), AES.block_size)  
    return pt

# DES encryption/decryption
def des_encrypt(data, key):
    key_bytes = hashlib.md5(key.encode()).digest()[:8]
    cipher = DES.new(key_bytes, DES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(data, DES.block_size))
    return cipher.iv + ct_bytes

def des_decrypt(data, key):
    key_bytes = hashlib.md5(key.encode()).digest()[:8]
    iv = data[:8]
    ct = data[8:]
    cipher = DES.new(key_bytes, DES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct), DES.block_size)
    return pt

# Triple DES (3DES)
def tdes_encrypt(data, key):
    key_bytes = hashlib.md5(key.encode()).digest() + hashlib.md5(key.encode()).digest()[:8]
    cipher = DES3.new(key_bytes, DES3.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(data, DES3.block_size))
    return cipher.iv + ct_bytes

def tdes_decrypt(data, key):
    key_bytes = hashlib.md5(key.encode()).digest() + hashlib.md5(key.encode()).digest()[:8]
    iv = data[:8]
    ct = data[8:]
    cipher = DES3.new(key_bytes, DES3.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct), DES3.block_size)
    return pt

# Fernet encryption/decryption (key must be 32 url-safe base64-encoded bytes)
def fernet_encrypt(data, key):
    f = Fernet(key)
    return f.encrypt(data)

def fernet_decrypt(data, key):
    f = Fernet(key)
    return f.decrypt(data)

# Base64 encode/decode (not encryption but encoding)
def base64_encode(data):
    return b64encode(data)

def base64_decode(data):
    return b64decode(data)

# Blowfish encryption/decryption
def blowfish_encrypt(data, key):
    key_bytes = hashlib.sha256(key.encode()).digest()
    cipher = Blowfish.new(key_bytes[:16], Blowfish.MODE_CBC)
    plen = Blowfish.block_size - len(data) % Blowfish.block_size
    padding = bytes([plen]) * plen
    data_padded = data + padding
    ct = cipher.iv + cipher.encrypt(data_padded)
    return ct

def blowfish_decrypt(data, key):
    key_bytes = hashlib.sha256(key.encode()).digest()
    iv = data[:8]
    ct = data[8:]
    cipher = Blowfish.new(key_bytes[:16], Blowfish.MODE_CBC, iv)
    pt_padded = cipher.decrypt(ct)
    plen = pt_padded[-1]
    return pt_padded[:-plen]

# RC4 encryption/decryption (symmetric)
def rc4_encrypt(data, key):
    return rc4_crypt(data, key)

def rc4_decrypt(data, key):
    return rc4_crypt(data, key)

def rc4_crypt(data, key):
    S = list(range(256))
    j = 0
    out = bytearray()

    key_bytes = key.encode()
    for i in range(256):
        j = (j + S[i] + key_bytes[i % len(key_bytes)]) % 256
        S[i], S[j] = S[j], S[i]

    i = j = 0
    for byte in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        out.append(byte ^ S[(S[i] + S[j]) % 256])

    return bytes(out)
