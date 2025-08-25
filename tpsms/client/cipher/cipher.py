from Crypto.Cipher import AES, PKCS1_v1_5
from Crypto.PublicKey import RSA
from .crypt import encrypt as aes_encrypt, decrypt as aes_decrypt
from .rsa_pub_key import create_rsa_public_key_from_components
import time
import random


def tp_link_aes_keygen():
    return f"{int(time.time())}{int(1e9 * random.random())}"[:16].encode("utf-8")


def tp_link_rsa_chunk_padding(buffer, size):
    if len(buffer) >= size:
        return buffer
    return buffer + b"\x00" * (size - len(buffer))


def create_cipher(modulus, exponent, algo="aes-128-cbc", key=None, iv=None):
    if key is None:
        key = tp_link_aes_keygen()
    if iv is None:
        iv = tp_link_aes_keygen()

    rsa_pub_key = create_rsa_public_key_from_components(modulus, exponent)
    rsa_chunk_size = len(modulus)

    def rsa_encrypt(buffer):
        # Convert buffer to integer
        m = int.from_bytes(buffer, byteorder='big')
        # Perform raw RSA encryption: c = m^e mod n
        c = pow(m, rsa_pub_key.e, rsa_pub_key.n)
        # Convert result back to bytes, ensuring it matches the modulus size
        encrypted = c.to_bytes(rsa_chunk_size, byteorder='big')

        # Process in chunks if buffer is larger than chunk_size
        chunk_count = (len(buffer) + rsa_chunk_size - 1) // rsa_chunk_size
        encrypted_chunks = []
        for offset in range(0, chunk_count * rsa_chunk_size, rsa_chunk_size):
            chunk = tp_link_rsa_chunk_padding(
                buffer[offset:offset + rsa_chunk_size], rsa_chunk_size
            )
            # Convert chunk to integer and encrypt
            m = int.from_bytes(chunk, byteorder='big')
            c = pow(m, rsa_pub_key.e, rsa_pub_key.n)
            encrypted_chunks.append(c.to_bytes(rsa_chunk_size, byteorder='big'))

        return b"".join(encrypted_chunks)

    return {
        "key": key,
        "iv": iv,
        "aes_encrypt": lambda buffer: aes_encrypt(buffer, algo=algo, key=key, iv=iv),
        "aes_decrypt": lambda buffer: aes_decrypt(buffer, algo=algo, key=key, iv=iv),
        "rsa_encrypt": rsa_encrypt,
    }