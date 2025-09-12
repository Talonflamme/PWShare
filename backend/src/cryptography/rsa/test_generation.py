from Crypto.PublicKey.RSA import generate
import random

random.seed(42)


def generate_encrypt(length_bytes):
    key = generate(length_bytes * 8, randfunc=random.randbytes)
    print("\tlet key = PrivateKey::new(")
    print(f"\t\tBigUint::from_str_radix(\"{key.n:x}\", 16).unwrap(),")
    print(f"\t\tBigUint::from_str_radix(\"{key.d:x}\", 16).unwrap(),")
    print(f"\t\tBigUint::from_str_radix(\"{key.e:x}\", 16).unwrap(),")
    print(f"\t\tBigUint::from_str_radix(\"{key.p:x}\", 16).unwrap(),")
    print(f"\t\tBigUint::from_str_radix(\"{key.q:x}\", 16).unwrap()")
    print("\t);\n\n")

    message = random.randbytes(length_bytes - 1)

    print(f"\tlet m = BigUint::from_str_radix(\"{message.hex()}\", 16).unwrap();\n")
    print(f"\tassert_eq!(\n\t\tkey.public().encode(m).hex(),")

    ciphertext = key._encrypt(int.from_bytes(message, 'big'))

    print(f"\t\t\"{ciphertext:x}\"\n\t);")


def generate_decrypt(length_bytes):
    key = generate(length_bytes * 8, randfunc=random.randbytes)
    print("\tlet key = PrivateKey::new(")
    print(f"\t\tBigUint::from_str_radix(\"{key.n:x}\", 16).unwrap(),")
    print(f"\t\tBigUint::from_str_radix(\"{key.d:x}\", 16).unwrap(),")
    print(f"\t\tBigUint::from_str_radix(\"{key.e:x}\", 16).unwrap(),")
    print(f"\t\tBigUint::from_str_radix(\"{key.p:x}\", 16).unwrap(),")
    print(f"\t\tBigUint::from_str_radix(\"{key.q:x}\", 16).unwrap()")
    print("\t);\n\n")

    message = random.randbytes(length_bytes - 1)

    print(f"\tlet c = BigUint::from_str_radix(\"{message.hex()}\", 16).unwrap();\n")
    print(f"\tassert_eq!(\n\t\tkey.decode(c).hex(),")

    ciphertext = key._decrypt(int.from_bytes(message, 'big'))

    print(f"\t\t\"{ciphertext:x}\"\n\t);")


def main():
    generate_encrypt(2048 // 8)
    generate_decrypt(2048 // 8)


if __name__ == '__main__':
    main()
