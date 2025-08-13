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
    # as the test block size is 8 (1 byte), the nonce can take up to 15 bytes
    nonce_len = random.randint(0, 13)  # inclusive
    nonce = get_random_bytes(nonce_len)
    return AES.new(key, AES.MODE_CTR, nonce=nonce), "CTR { nonce: vec![%s] }" % ", ".join(
        f"0x{x}" for x in nonce.hex(sep=",").split(","))


def generate_encrypt(key_len, mode):
    key = get_random_bytes(key_len)

    plaintext = get_random_bytes(16 * 8)  # 8 blocks

    cipher, mode_struct = globals()[f"new_{mode.lower()}"](key)

    ciphertext = cipher.encrypt(plaintext)

    print(
        f"test_encrypt::<AESKey{key_len * 8}, {mode}>(\n\t\"{key.hex()}\",\n\t\"{plaintext.hex()}\",\n\t\"{ciphertext.hex()}\",\n\t{mode_struct}\n);")


def generate_encrypt_gcm(key_len):
    key = get_random_bytes(key_len)

    plaintext = get_random_bytes(16 * 8)
    nonce_len = random.randint(1, 16)  # inclusive
    nonce = get_random_bytes(nonce_len)

    aad_len = random.randint(0, 3)  # inclusive
    aad = get_random_bytes(aad_len * 16)

    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    cipher.update(aad)

    ciphertext, tag = cipher.encrypt_and_digest(plaintext)

    print(f"test_encrypt_aead::<AESKey{key_len * 8}, GCM>(")
    print(f"\"{key.hex()}\",")
    print(f"\"{plaintext.hex()}\",")
    print("None," if aad_len == 0 else f"Some(\"{aad.hex()}\"),")
    print(f"\"{ciphertext.hex()}\",")
    print(f"\"{tag.hex()}\",")
    print("GCM::new(vec![%s])" % ", ".join(f"0x{x}" for x in nonce.hex(sep=",").split(",")))
    print(");")


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


def generate_gcm(key_len, is_encrypt: bool, amount_of_tests):
    print("#[test]")
    print(f"fn gcm_{'encrypt' if is_encrypt else 'decrypt'}_{key_len * 8}() {{")

    for i in range(amount_of_tests):
        if is_encrypt:
            generate_encrypt_gcm(key_len)
        # else:
        #     generate_decrypt_gcm(key_len)

    print("}\n")


def main():
    random.seed(69)
    # generate_multiple(16, "GCM", True, 3)
    # generate_multiple(16, "GCM", False, 3)
    # generate_multiple(24, "GCM", True, 3)
    # generate_multiple(24, "GCM", False, 3)
    # generate_multiple(32, "GCM", True, 3)
    # generate_multiple(32, "GCM", False, 3)
    generate_gcm(16, True, 3)
    generate_gcm(24, True, 3)
    generate_gcm(32, True, 3)


if __name__ == '__main__':
    main()
