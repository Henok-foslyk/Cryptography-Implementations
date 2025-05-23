from natasha import ENC, RF, DEC
from tqdm import tqdm

def sha_hash_24(text):
    val_map = dict()
    L_orig, R_orig = text[:20], text[20:]
    for k in tqdm(range(2**24)):
        key = k.to_bytes(3, byteorder="big")
        k0, k1,k2 = key[0:1], key[1:2], key[2:3]
        R, L = RF(L_orig, R_orig, k0)
        R, L = RF(L, R, k1)
        R, _ = RF(L, R, k2)
        val_map[R] = key
    return val_map

def sha_hash_16(cipher_text_in_bytes):
    val_maps = dict()
    R_orig, L_orig = cipher_text_in_bytes[:20], cipher_text_in_bytes[20:]
    for k in range(2**16):
        key = k.to_bytes(2, byteorder="big")
        k4, k5 = key[0:1], key[1:2]
        R, L = RF(R_orig, L_orig, k5)
        R, _ = RF(L, R, k4)
        val_maps[R] = key
    return val_maps


def brute_force(first, second):
    for keys in second:
        if keys in first:
            k012 = first[keys]
            k45 = second[keys]

    for k in range(2**8):
        k3 = k.to_bytes(1, byteorder="big")
        key = k012 + k3 + k45
        if ENC(byte_input, key) == byte_ciph:
            return key
    
if __name__ == "__main__":
    plaintext = 'Meet_NataSHA_which_is_not_a_SHA_although'
    full_cipher = "ae055b48d8fa60bc337ff846ee88fe33c7e026a5ea54dbb59814c68265540cef1c183ef7465536868c4febe7e2f0a6d43110d37576535b8518eaa4b7ce3ac3722816062755aa8b5ed82eadf76e8af6f5"
    ciphertext_hex = full_cipher[:80]
    second_block_cipher = full_cipher[80:]

    byte_input = bytes(plaintext, "utf-8")
    byte_ciph = bytes.fromhex(ciphertext_hex)

    l1_map = sha_hash_24(byte_input)
    l2_map = sha_hash_16(byte_ciph)

    byte_key = brute_force(l1_map, l2_map)

    sec_cipher = bytes.fromhex(second_block_cipher)
    solution = DEC(sec_cipher, byte_key)
    print(solution.decode('utf-8'))