import hashlib

def hash_md5(buffer):
    if isinstance(buffer, str):
        buffer = buffer.encode("utf-8")
    return hashlib.md5(buffer).digest()