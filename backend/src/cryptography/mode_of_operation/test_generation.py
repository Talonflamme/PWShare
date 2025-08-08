from Crypto.Cipher import AES
import random


def get_random_bytes(n):
    return bytes(random.getrandbits(8) for _ in range(n))


def new_ecb(key):
    return AES.new(key, AES.MODE_ECB), "ECB"


def new_cbc(key):
    iv = get_random_bytes(16)
    return AES.new(key, AES.MODE_CBC, iv=iv), "CBC { iv: 0x%s }" % iv.hex()


def new_ctr(key):
    # as the test block size is 8 (2**3), the nonce can take up to 13 bytes
    # nonce_len = random.randint(0, 13)  # inclusive
    nonce_len = 15
    nonce = get_random_bytes(nonce_len)
    return AES.new(key, AES.MODE_CTR, nonce=nonce), "CTR { nonce: vec![%s] }" % ", ".join(f"0x{x}" for x in nonce.hex(sep=",").split(","))


def generate_encrypt(key_len, mode):
    key = get_random_bytes(key_len)

    plaintext = get_random_bytes(16 * 8)  # 8 blocks
    print(plaintext.hex())

    cipher, mode_struct = globals()[f"new_{mode.lower()}"](key)

    ciphertext = cipher.encrypt(plaintext)

    print(
        f"test_encrypt::<AESKey{key_len * 8}, {mode}>(\n\t\"{key.hex()}\",\n\t\"{plaintext.hex()}\",\n\t\"{ciphertext.hex()}\",\n\t{mode_struct}\n);")


def generate_decrypt(key_len, mode):
    key = get_random_bytes(key_len)

    ciphertext = get_random_bytes(16 * 8)  # 8 blocks

    cipher, mode_struct = globals()[f"new_{mode.lower()}"](key)

    plaintext = cipher.decrypt(ciphertext)

    print(
        f"test_decrypt::<AESKey{key_len * 8}, {mode}>(\n\t\"{key.hex()}\",\n\t\"{ciphertext.hex()}\",\n\t\"{plaintext.hex()}\",\n\t{mode_struct}\n);")


def generate_multiple(key_len, mode: str, is_encrypt: bool, amount_of_tests: int):
    print("#[test]")
    print(f"fn {mode.lower()}_{'encrypt' if is_encrypt else 'decrypt'}_{key_len * 8}() {{")

    for i in range(amount_of_tests):
        if is_encrypt:
            generate_encrypt(key_len, mode)
        else:
            generate_decrypt(key_len, mode)

    print("}\n")


def main():
    random.seed(44)
    generate_multiple(16, "CTR", True, 3)
    generate_multiple(16, "CTR", False, 3)
    generate_multiple(24, "CTR", True, 3)
    generate_multiple(24, "CTR", False, 3)
    generate_multiple(32, "CTR", True, 3)
    generate_multiple(32, "CTR", False, 3)


if __name__ == '__main__':
    main()
