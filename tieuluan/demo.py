import os
import random
import sys


# Bảng S-Box chuẩn của AES (dùng cho bước SubBytes)
S_BOX = [
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
]

# Bảng nghịch đảo S-Box (dùng cho InvSubBytes)
INV_S_BOX = [
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D,
]

# Hằng số Rcon dùng trong Key Expansion (AES-128 dùng từ Rcon[1] đến Rcon[10])
RCON = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]


def bytes_to_state(block: bytes):
    """
    Chuyển 16 byte thành state 4x4 theo dạng cột của AES.
    Mỗi cột có 4 byte.
    """
    return [list(block[i:i + 4]) for i in range(0, 16, 4)]


def state_to_bytes(state):
    """Chuyển state 4x4 về lại mảng byte 16 byte."""
    result = []
    for column in state:
        result.extend(column)
    return bytes(result)


def add_round_key(state, round_key):
    """XOR state với round key."""
    for c in range(4):
        for r in range(4):
            state[c][r] ^= round_key[c][r]


def sub_bytes(state):
    """Thay thế từng byte trong state bằng S-Box."""
    for c in range(4):
        for r in range(4):
            state[c][r] = S_BOX[state[c][r]]


def inv_sub_bytes(state):
    """Bước ngược lại của SubBytes, dùng bảng Inv S-Box."""
    for c in range(4):
        for r in range(4):
            state[c][r] = INV_S_BOX[state[c][r]]


def shift_rows(state):
    """Dịch vòng trái từng hàng: hàng 0 giữ nguyên, hàng 1 dịch 1, hàng 2 dịch 2, hàng 3 dịch 3."""
    for row in range(1, 4):
        row_values = [state[col][row] for col in range(4)]
        row_values = row_values[row:] + row_values[:row]
        for col in range(4):
            state[col][row] = row_values[col]


def inv_shift_rows(state):
    """Dịch vòng phải từng hàng để đảo ngược ShiftRows."""
    for row in range(1, 4):
        row_values = [state[col][row] for col in range(4)]
        row_values = row_values[-row:] + row_values[:-row]
        for col in range(4):
            state[col][row] = row_values[col]


def gmul(a, b):
    """
    Nhân hai phần tử trong trường GF(2^8), dùng cho MixColumns.
    """
    product = 0
    for _ in range(8):
        if b & 1:
            product ^= a
        high_bit = a & 0x80
        a = (a << 1) & 0xFF
        if high_bit:
            a ^= 0x1B
        b >>= 1
    return product


def mix_columns(state):
    """Trộn từng cột theo ma trận cố định của AES."""
    for c in range(4):
        a0, a1, a2, a3 = state[c]
        state[c][0] = gmul(a0, 2) ^ gmul(a1, 3) ^ a2 ^ a3
        state[c][1] = a0 ^ gmul(a1, 2) ^ gmul(a2, 3) ^ a3
        state[c][2] = a0 ^ a1 ^ gmul(a2, 2) ^ gmul(a3, 3)
        state[c][3] = gmul(a0, 3) ^ a1 ^ a2 ^ gmul(a3, 2)


def inv_mix_columns(state):
    """Bước ngược lại của MixColumns."""
    for c in range(4):
        a0, a1, a2, a3 = state[c]
        state[c][0] = gmul(a0, 14) ^ gmul(a1, 11) ^ gmul(a2, 13) ^ gmul(a3, 9)
        state[c][1] = gmul(a0, 9) ^ gmul(a1, 14) ^ gmul(a2, 11) ^ gmul(a3, 13)
        state[c][2] = gmul(a0, 13) ^ gmul(a1, 9) ^ gmul(a2, 14) ^ gmul(a3, 11)
        state[c][3] = gmul(a0, 11) ^ gmul(a1, 13) ^ gmul(a2, 9) ^ gmul(a3, 14)


def rot_word(word):
    """Dịch vòng trái 1 byte cho 1 word (4 byte)."""
    return word[1:] + word[:1]


def sub_word(word):
    """Thay thế từng byte của word qua S-Box."""
    return [S_BOX[b] for b in word]


def key_expansion(key):
    """
    Mở rộng khóa 16 byte thành 11 round key (mỗi round key 16 byte).
    Tổng cộng tạo 44 word, mỗi word 4 byte.
    """
    words = [list(key[i:i + 4]) for i in range(0, 16, 4)]

    for i in range(4, 44):
        temp = words[i - 1][:]
        if i % 4 == 0:
            temp = sub_word(rot_word(temp))
            temp[0] ^= RCON[i // 4]
        words.append([words[i - 4][j] ^ temp[j] for j in range(4)])

    round_keys = []
    for round_index in range(11):
        round_keys.append([words[round_index * 4 + c][:] for c in range(4)])
    return round_keys


def encrypt_block(block, round_keys):
    """
    Mã hóa 1 khối 16 byte theo AES-128 (10 vòng).
    """
    state = bytes_to_state(block)

    add_round_key(state, round_keys[0])
    for round_index in range(1, 10):
        sub_bytes(state)
        shift_rows(state)
        mix_columns(state)
        add_round_key(state, round_keys[round_index])

    sub_bytes(state)
    shift_rows(state)
    add_round_key(state, round_keys[10])
    return state_to_bytes(state)


def decrypt_block(block, round_keys):
    """
    Giải mã 1 khối 16 byte theo AES-128 (đúng thứ tự các bước ngược).
    """
    state = bytes_to_state(block)

    add_round_key(state, round_keys[10])
    for round_index in range(9, 0, -1):
        inv_shift_rows(state)
        inv_sub_bytes(state)
        add_round_key(state, round_keys[round_index])
        inv_mix_columns(state)

    inv_shift_rows(state)
    inv_sub_bytes(state)
    add_round_key(state, round_keys[0])
    return state_to_bytes(state)


def simple_padding(data, block_size=16):
    """
    Padding đơn giản kiểu PKCS#7:
    thêm n byte có giá trị n để đủ bội số block_size.
    """
    pad_len = block_size - (len(data) % block_size)
    if pad_len == 0:
        pad_len = block_size
    return data + bytes([pad_len] * pad_len)


def remove_padding(data):
    """Bỏ phần padding PKCS#7 sau khi giải mã."""
    if not data or len(data) % 16 != 0:
        raise ValueError("Dữ liệu không hợp lệ để bỏ padding.")
    pad_len = data[-1]
    if pad_len < 1 or pad_len > 16:
        raise ValueError("Padding không hợp lệ.")
    if data[-pad_len:] != bytes([pad_len] * pad_len):
        raise ValueError("Padding không hợp lệ.")
    return data[:-pad_len]


def xor_bytes(left_bytes, right_bytes):
    """
    XOR hai day byte co cung do dai.
    """
    if len(left_bytes) != len(right_bytes):
        raise ValueError("Hai day byte XOR phai co cung do dai.")
    return bytes(a ^ b for a, b in zip(left_bytes, right_bytes))


def aes128_encrypt_cbc(plaintext, key_text):
    """
    Ma hoa AES-128 theo che do CBC.
    - Tao IV ngau nhien 16 byte.
    - Block dau XOR voi IV, cac block sau XOR voi block ma truoc do.
    """
    key_bytes = key_text.encode("utf-8")
    if len(key_bytes) != 16:
        raise ValueError("Khoa AES-128 phai dung 16 byte.")

    round_keys = key_expansion(key_bytes)
    plaintext_bytes = plaintext.encode("utf-8")
    padded = simple_padding(plaintext_bytes, 16)

    iv = os.urandom(16)
    previous_block = iv
    ciphertext_blocks = []

    for i in range(0, len(padded), 16):
        block = padded[i:i + 16]
        xored_block = xor_bytes(block, previous_block)
        encrypted_block = encrypt_block(xored_block, round_keys)
        ciphertext_blocks.append(encrypted_block)
        previous_block = encrypted_block

    return iv, b"".join(ciphertext_blocks)


def aes128_decrypt_cbc(ciphertext, key_text, iv):
    """
    Giai ma AES-128 theo che do CBC.
    - Giai ma tung block roi XOR voi IV hoac block ma truoc do.
    - Bo padding PKCS#7 va chuyen lai UTF-8.
    """
    key_bytes = key_text.encode("utf-8")
    if len(key_bytes) != 16:
        raise ValueError("Khoa AES-128 phai dung 16 byte.")
    if len(iv) != 16:
        raise ValueError("IV phai dung 16 byte.")
    if len(ciphertext) % 16 != 0:
        raise ValueError("Ciphertext phai la boi so cua 16 byte.")

    round_keys = key_expansion(key_bytes)
    previous_block = iv
    plaintext_blocks = []

    for i in range(0, len(ciphertext), 16):
        cipher_block = ciphertext[i:i + 16]
        decrypted_block = decrypt_block(cipher_block, round_keys)
        plain_block = xor_bytes(decrypted_block, previous_block)
        plaintext_blocks.append(plain_block)
        previous_block = cipher_block

    plaintext_padded = b"".join(plaintext_blocks)
    plaintext_bytes = remove_padding(plaintext_padded)
    return plaintext_bytes.decode("utf-8")


def aes_demo(plaintext, key):
    """
    Demo AES-128 CBC, giu nguyen loi AES co san.
    """
    print("===== 1. AES-128 CBC =====")
    plaintext_bytes = plaintext.encode("utf-8")
    key_bytes = key.encode("utf-8")

    iv, ciphertext = aes128_encrypt_cbc(plaintext, key)
    decrypted_text = aes128_decrypt_cbc(ciphertext, key, iv)

    print(f"Plaintext ban dau: {plaintext}")
    print(f"Do dai plaintext theo byte: {len(plaintext_bytes)} byte")
    print(f"Khoa AES-128: {key}")
    print(f"Do dai khoa theo byte: {len(key_bytes)} byte")
    print(f"IV (hex): {iv.hex()}")
    print(f"Ciphertext (hex): {ciphertext.hex()}")
    print(f"Plaintext sau giai ma: {decrypted_text}")
    print(f"Ket qua kiem tra: {'DUNG' if decrypted_text == plaintext else 'SAI'}")
    print()

def gcd(a, b):
    """Ước số chung lớn nhất bằng thuật toán Euclid."""
    while b != 0:
        a, b = b, a % b
    return a


def extended_gcd(a, b):
    """
    Thuật toán Euclid mở rộng.
    Trả về (g, x, y) sao cho a*x + b*y = g = gcd(a, b).
    """
    if b == 0:
        return a, 1, 0
    g, x1, y1 = extended_gcd(b, a % b)
    x = y1
    y = x1 - (a // b) * y1
    return g, x, y


def mod_inverse(a, m):
    """Tính nghịch đảo modulo: a^(-1) mod m."""
    g, x, _ = extended_gcd(a, m)
    if g != 1:
        raise ValueError(f"Không tồn tại nghịch đảo modulo cho a={a}, m={m}.")
    return x % m


def is_prime(n):
    """
    Kiểm tra số nguyên tố đơn giản (trial division).
    Đủ dùng cho mô phỏng học thuật với số cỡ nhỏ/vừa.
    """
    if n < 2:
        return False
    if n in (2, 3):
        return True
    if n % 2 == 0:
        return False
    i = 3
    while i * i <= n:
        if n % i == 0:
            return False
        i += 2
    return True


def generate_prime(start=20000, end=60000):
    """Sinh ngẫu nhiên một số nguyên tố trong đoạn [start, end]."""
    if start < 2:
        start = 2

    candidate = random.randint(start, end)
    if candidate % 2 == 0:
        candidate += 1

    while candidate <= end:
        if is_prime(candidate):
            return candidate
        candidate += 2

    # Nếu chạy đến đây thì quét lại từ đầu đoạn.
    candidate = start + (1 if start % 2 == 0 else 0)
    while candidate <= end:
        if is_prime(candidate):
            return candidate
        candidate += 2

    raise ValueError("Không tìm thấy số nguyên tố trong đoạn đã cho.")


def rsa_generate_keys():
    """
    Sinh khóa RSA cho demo:
    - Chọn p, q nguyên tố
    - n = p*q, phi = (p-1)*(q-1)
    - Chọn e và tính d = e^(-1) mod phi
    """
    p = generate_prime()
    q = generate_prime()
    while q == p:
        q = generate_prime()

    n = p * q
    phi_n = (p - 1) * (q - 1)

    # Ưu tiên e = 65537 (thực tế hay dùng), nếu không phù hợp thì tìm e khác.
    e = 65537
    if gcd(e, phi_n) != 1:
        e = 3
        while e < phi_n and gcd(e, phi_n) != 1:
            e += 2

    d = mod_inverse(e, phi_n)
    return (p, q, n, phi_n, e, d)


def rsa_encrypt_text(plaintext, e, n):
    """
    Mã hóa RSA theo từng ký tự Unicode:
    c = m^e mod n, với m = ord(ký tự).
    """
    return [pow(ord(ch), e, n) for ch in plaintext]


def rsa_decrypt_text(cipher_list, d, n):
    """Giải mã RSA theo từng phần tử ciphertext."""
    chars = []
    for c in cipher_list:
        m = pow(c, d, n)
        chars.append(chr(m))
    return "".join(chars)


def rsa_demo(plaintext):
    print("===== 2. RSA =====")
    p, q, n, phi_n, e, d = rsa_generate_keys()
    ciphertext = rsa_encrypt_text(plaintext, e, n)
    decrypted_text = rsa_decrypt_text(ciphertext, d, n)

    print(f"Plaintext ban dau: {plaintext}")
    print(f"p = {p}")
    print(f"q = {q}")
    print(f"n = p * q = {n}")
    print(f"phi(n) = (p - 1) * (q - 1) = {phi_n}")
    print(f"e = {e}")
    print(f"d = {d}")
    print(f"Ciphertext (danh sach so nguyen): {ciphertext}")
    print(f"Plaintext sau giai ma: {decrypted_text}")
    print(f"Ket qua kiem tra: {'DUNG' if decrypted_text == plaintext else 'SAI'}")
    print()


# 64 hằng số K của SHA-256
SHA256_K = [
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
    0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3, 0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
    0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
    0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13, 0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
    0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
    0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208, 0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
]


def rotr(x, n):
    """Rotate right 32-bit."""
    return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF


def sha256(message):
    """
    Cài đặt SHA-256 thuần Python:
    1) Tiền xử lý
    2) Chia block 512-bit
    3) Mở rộng 64 word
    4) 64 vòng nén
    5) Ghép kết quả 256-bit
    """
    msg = bytearray(message.encode("utf-8"))
    bit_length = len(msg) * 8

    # Thêm bit '1' (0x80) và các bit '0' cho đến khi còn 64 bit cuối chứa độ dài.
    msg.append(0x80)
    while (len(msg) % 64) != 56:
        msg.append(0x00)

    # Thêm độ dài ban đầu của thông điệp (64 bit, big-endian).
    msg += bit_length.to_bytes(8, byteorder="big")

    # Giá trị băm khởi tạo (IV) của SHA-256.
    h0 = 0x6A09E667
    h1 = 0xBB67AE85
    h2 = 0x3C6EF372
    h3 = 0xA54FF53A
    h4 = 0x510E527F
    h5 = 0x9B05688C
    h6 = 0x1F83D9AB
    h7 = 0x5BE0CD19

    for chunk_start in range(0, len(msg), 64):
        chunk = msg[chunk_start:chunk_start + 64]

        # Mở rộng message schedule W[0..63]
        w = [0] * 64
        for i in range(16):
            w[i] = int.from_bytes(chunk[i * 4:(i + 1) * 4], byteorder="big")
        for i in range(16, 64):
            s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3)
            s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10)
            w[i] = (w[i - 16] + s0 + w[i - 7] + s1) & 0xFFFFFFFF

        # Khởi tạo biến làm việc.
        a, b, c, d = h0, h1, h2, h3
        e, f, g, h = h4, h5, h6, h7

        # 64 vòng nén.
        for i in range(64):
            big_sigma1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)
            ch = (e & f) ^ ((~e) & g)
            temp1 = (h + big_sigma1 + ch + SHA256_K[i] + w[i]) & 0xFFFFFFFF

            big_sigma0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)
            maj = (a & b) ^ (a & c) ^ (b & c)
            temp2 = (big_sigma0 + maj) & 0xFFFFFFFF

            h = g
            g = f
            f = e
            e = (d + temp1) & 0xFFFFFFFF
            d = c
            c = b
            b = a
            a = (temp1 + temp2) & 0xFFFFFFFF

        # Cộng dồn vào giá trị băm.
        h0 = (h0 + a) & 0xFFFFFFFF
        h1 = (h1 + b) & 0xFFFFFFFF
        h2 = (h2 + c) & 0xFFFFFFFF
        h3 = (h3 + d) & 0xFFFFFFFF
        h4 = (h4 + e) & 0xFFFFFFFF
        h5 = (h5 + f) & 0xFFFFFFFF
        h6 = (h6 + g) & 0xFFFFFFFF
        h7 = (h7 + h) & 0xFFFFFFFF

    digest = (
        f"{h0:08x}{h1:08x}{h2:08x}{h3:08x}"
        f"{h4:08x}{h5:08x}{h6:08x}{h7:08x}"
    )
    return digest


def sha256_demo(plaintext):
    print("===== 3. SHA-256 =====")
    hash_hex = sha256(plaintext)
    print(f"Plaintext ban dau: {plaintext}")
    print(f"Gia tri bam SHA-256 (hex): {hash_hex}")
    print()


def generate_dsa_params():
    """
    Sinh tham số DSA nhỏ cho mục đích demo:
    - Chọn q là số nguyên tố nhỏ
    - Tìm p sao cho p = k*q + 1 và p là nguyên tố
    - Tìm g = h^((p-1)/q) mod p > 1
    """
    q = 233  # số nguyên tố nhỏ, thuận tiện cho mô phỏng học thuật

    k = 2
    p = None
    while k < 10000:
        candidate = k * q + 1
        if is_prime(candidate):
            p = candidate
            break
        k += 1

    if p is None:
        raise ValueError("Không sinh được tham số p phù hợp cho DSA.")

    h = 2
    exponent = (p - 1) // q
    g = pow(h, exponent, p)
    while g <= 1:
        h += 1
        g = pow(h, exponent, p)

    return p, q, g


def dsa_keygen():
    """Sinh khóa DSA: khóa bí mật x, khóa công khai y = g^x mod p."""
    p, q, g = generate_dsa_params()
    x = random.randint(1, q - 1)   # private key
    y = pow(g, x, p)               # public key
    return (p, q, g, x, y)


def dsa_sign(message, p, q, g, x):
    """
    Ký DSA:
    r = (g^k mod p) mod q
    s = k^-1 * (H(m) + x*r) mod q
    """
    hash_hex = sha256(message)
    z = int(hash_hex, 16) % q

    while True:
        k = random.randint(1, q - 1)
        if gcd(k, q) != 1:
            continue

        r = pow(g, k, p) % q
        if r == 0:
            continue

        k_inv = mod_inverse(k, q)
        s = (k_inv * (z + x * r)) % q
        if s == 0:
            continue

        return (r, s)


def dsa_verify(message, signature, p, q, g, y):
    """Xác minh chữ ký DSA theo công thức chuẩn."""
    r, s = signature
    if not (0 < r < q and 0 < s < q):
        return False

    hash_hex = sha256(message)
    z = int(hash_hex, 16) % q

    w = mod_inverse(s, q)
    u1 = (z * w) % q
    u2 = (r * w) % q
    v = ((pow(g, u1, p) * pow(y, u2, p)) % p) % q
    return v == r


def dsa_demo(plaintext):
    print("===== 4. DSA =====")
    p, q, g, x, y = dsa_keygen()
    signature = dsa_sign(plaintext, p, q, g, x)
    is_valid = dsa_verify(plaintext, signature, p, q, g, y)

    print(f"Plaintext ban dau: {plaintext}")
    print(f"Tham so cong khai (p, q, g) = ({p}, {q}, {g})")
    print(f"Khoa cong khai y = {y}")
    print(f"Chu ky so (r, s) = {signature}")
    print(f"Ket qua xac minh chu ky: {'HOP LE' if is_valid else 'KHONG HOP LE'}")
    print()


def configure_console_utf8():
    """Giúp terminal Windows hiển thị tiếng Việt ổn định hơn."""
    if os.name == "nt":
        os.system("chcp 65001 > nul")
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    if hasattr(sys.stdin, "reconfigure"):
        sys.stdin.reconfigure(encoding="utf-8")


def print_system_info(plaintext, aes_key):
    """
    In thong tin dau vao dung chung cho toan bo chuong trinh.
    """
    print("===== TH\u00d4NG TIN \u0110\u1ea6U V\u00c0O H\u1ec6 TH\u1ed0NG =====")
    print(f"Plaintext dung chung: {plaintext}")
    print(f"Do dai plaintext theo byte: {len(plaintext.encode('utf-8'))} byte")
    print(f"Khoa AES nhap vao: {aes_key}")
    print(f"Do dai khoa AES theo byte: {len(aes_key.encode('utf-8'))} byte")
    print()


def read_demo_inputs():
    """
    Nhap plaintext va khoa AES tu nguoi dung.
    Neu bam Enter thi dung gia tri mac dinh.
    """
    default_plaintext = "\u0110\u1ea0I H\u1eccC GIAO TH\u00d4NG V\u1eacN T\u1ea2I TPHCM"
    default_key = "NGO THANH PHU123"

    print("===== NH\u1eacP D\u1eee LI\u1ec6U DEMO =====")
    plaintext_input = input("Nhap plaintext dung chung (Enter de dung mac dinh): ").strip().lstrip("\ufeff")
    plaintext = plaintext_input if plaintext_input else default_plaintext

    while True:
        key_input = input("Nhap khoa AES-128 (16 byte, Enter de dung mac dinh): ").strip().lstrip("\ufeff")
        aes_key = key_input if key_input else default_key

        key_len = len(aes_key.encode("utf-8"))
        if key_len == 16:
            break

        print(f"Loi: khoa hien tai co {key_len} byte, AES-128 yeu cau dung 16 byte. Vui long nhap lai.")

    print()
    return plaintext, aes_key


def main():
    configure_console_utf8()

    plaintext, aes_key = read_demo_inputs()
    print_system_info(plaintext, aes_key)

    print("===== DEMO 4 K\u1ef8 THU\u1eacT M\u1eacT M\u00c3 C\u01a0 B\u1ea2N =====")
    print()

    aes_demo(plaintext, aes_key)
    rsa_demo(plaintext)
    sha256_demo(plaintext)
    dsa_demo(plaintext)


if __name__ == "__main__":
    main()
