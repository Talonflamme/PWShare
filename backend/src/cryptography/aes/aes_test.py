from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import time


def generate_encrypt_case(f, i, bit_len):
    f.write(f"COUNT = {i}\n")

    key = get_random_bytes(bit_len // 8)
    plaintext = get_random_bytes(16)

    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext = cipher.encrypt(plaintext)

    f.write(f"KEY = {key.hex()}\n")
    f.write(f"PLAINTEXT = {plaintext.hex()}\n")
    f.write(f"CIPHERTEXT = {ciphertext.hex()}\n\n")


def generate_decrypt_case(f, i, bit_len):
    f.write(f"COUNT = {i}\n")

    key = get_random_bytes(bit_len // 8)
    ciphertext = get_random_bytes(16)

    cipher = AES.new(key, AES.MODE_ECB)
    plaintext = cipher.decrypt(ciphertext)

    f.write(f"KEY = {key.hex()}\n")
    f.write(f"CIPHERTEXT = {ciphertext.hex()}\n")
    f.write(f"PLAINTEXT = {plaintext.hex()}\n\n")


def generate_file(path, bit_len):
    with open(path, "w") as f:
        f.write(f"""# CAVS 11.1
# Config info for aes_values
# AESVS GFSbox test data for ECB
# State : Encrypt and Decrypt
# Key Length : {bit_len}
# Generated on {time.strftime('%a %b %d %H:%M:%S %Y')}

[ENCRYPT]

""")
        for i in range(10):
            generate_encrypt_case(f, i, bit_len)

        f.write("[DECRYPT]\n\n")

        for i in range(10):
            generate_decrypt_case(f, i, bit_len)


generate_file("../../../test_vectors/test192.rsp", 192)
print()
