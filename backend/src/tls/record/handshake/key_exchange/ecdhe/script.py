from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey


def to_u32_words_le(p):
    m = 2 ** 32

    rems = []

    while p > 0:
        rem = p % m
        p //= m
        rems.append(rem)

    return rems

key = X25519PrivateKey.generate()
