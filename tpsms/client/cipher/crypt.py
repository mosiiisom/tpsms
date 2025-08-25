from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

def crypt(cipher, buffer):
    return cipher.encrypt(pad(buffer, AES.block_size)) if hasattr(cipher, "encrypt") else cipher.decrypt(buffer)

def encrypt(buffer, algo="aes-128-cbc", key=None, iv=None):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return crypt(cipher, buffer)

def decrypt(buffer, algo="aes-128-cbc", key=None, iv=None):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(buffer), AES.block_size)