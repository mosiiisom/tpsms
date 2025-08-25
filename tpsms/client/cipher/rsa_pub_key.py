from Crypto.PublicKey import RSA

def length(n):
    if n < 0x80:
        return [n]
    elif n < 0x100:
        return [0x81, n]
    elif n < 0x10000:
        return [0x82, n >> 8, n & 255]
    elif n < 0x1000000:
        return [0x83, n >> 16, (n >> 8) & 255, n & 255]
    raise ValueError("too big")

def create_rsa_public_key_from_components(modulus, exponent):
    # Ensure modulus and exponent are bytes
    if isinstance(modulus, bytearray):
        modulus = bytes(modulus)
    if isinstance(exponent, bytearray):
        exponent = bytes(exponent)

    # Encode modulus and exponent as ASN.1 INTEGERs
    # Prepend 0x00 if the most significant bit is set to ensure positive integers
    if modulus[0] >= 0x80:
        modulus = b"\x00" + modulus
    if exponent[0] >= 0x80:
        exponent = b"\x00" + exponent

    modulus_bytes = bytes([0x02] + length(len(modulus)) + list(modulus))
    exponent_bytes = bytes([0x02] + length(len(exponent)) + list(exponent))

    # Create the inner SEQUENCE for the PKCS#1 RSAPublicKey
    pkcs1_sequence = bytes([0x30] + length(len(modulus_bytes) + len(exponent_bytes)) + list(modulus_bytes) + list(exponent_bytes))

    # Wrap in SubjectPublicKeyInfo structure
    # AlgorithmIdentifier for RSA: 1.2.840.113549.1.1.1 (rsaEncryption) with NULL parameters
    algorithm_id = bytes.fromhex("300d06092a864886f70d0101010500")  # OID for rsaEncryption + NULL
    # BIT STRING: 0x00 (unused bits) + PKCS#1 sequence
    bit_string = bytes([0x00] + list(pkcs1_sequence))
    bit_string_field = bytes([0x03] + length(len(bit_string)) + list(bit_string))
    public_key_info = bytes([0x30] + length(len(algorithm_id) + len(bit_string_field)) + list(algorithm_id) + list(bit_string_field))

    # # Debug prints
    # print("Modulus bytes:", modulus_bytes.hex())
    # print("Exponent bytes:", exponent_bytes.hex())
    # print("PKCS#1 sequence:", pkcs1_sequence.hex())
    # print("BIT STRING:", bit_string.hex())
    # print("Public key info:", public_key_info.hex())

    return RSA.import_key(public_key_info)