###############################
# Nguyen Anh Tuan 23521717
# DES_crypto.py
# repo: https://github.com/blastvious/NT101
###############################
import base64
import os
import random
# =========================
#  Helper Functions
# =========================

def bytes_to_bitstring(data: bytes):
    return ''.join(f"{byte:08b}" for byte in data)

def bitstring_to_bytes(bitstr: str):
    return bytes(int(bitstr[i:i+8], 2) for i in range(0, len(bitstr), 8))

def hex_to_bitstring(h):
    return ''.join(f"{int(h[i:i+2],16):08b}" for i in range(0, len(h), 2))

def bitstring_to_hex(b):
    return ''.join(f"{int(b[i:i+8],2):02X}" for i in range(0, len(b), 8))

def base64_encode(data: bytes):
    return base64.b64encode(data).decode()

def base64_decode(text: str):
    return base64.b64decode(text)

def permute(block, table):
    return ''.join(block[i-1] for i in table)

def shift_left(k, n):
    return k[n:] + k[:n]


# =========================
# DES Tables
# =========================

# Initial Permutation
IP = [58, 50, 42, 34, 26, 18, 10, 2,
      60, 52, 44, 36, 28, 20, 12, 4,
      62, 54, 46, 38, 30, 22, 14, 6,
      64, 56, 48, 40, 32, 24, 16, 8,
      57, 49, 41, 33, 25, 17, 9, 1,
      59, 51, 43, 35, 27, 19, 11, 3,
      61, 53, 45, 37, 29, 21, 13, 5,
      63, 55, 47, 39, 31, 23, 15, 7]

# Final Permutation
FP = [40, 8, 48, 16, 56, 24, 64, 32,
      39, 7, 47, 15, 55, 23, 63, 31,
      38, 6, 46, 14, 54, 22, 62, 30,
      37, 5, 45, 13, 53, 21, 61, 29,
      36, 4, 44, 12, 52, 20, 60, 28,
      35, 3, 43, 11, 51, 19, 59, 27,
      34, 2, 42, 10, 50, 18, 58, 26,
      33, 1, 41, 9, 49, 17, 57, 25]

# Expansion table
E = [32, 1, 2, 3, 4, 5,
     4, 5, 6, 7, 8, 9,
     8, 9, 10, 11, 12, 13,
     12, 13, 14, 15, 16, 17,
     16, 17, 18, 19, 20, 21,
     20, 21, 22, 23, 24, 25,
     24, 25, 26, 27, 28, 29,
     28, 29, 30, 31, 32, 1]

# S-boxes
SBOX = [
  # S1
  [[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
   [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
   [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
   [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]],

  # S2
  [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
   [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
   [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
   [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]],

  # S3
  [[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
   [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
   [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
   [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]],

  # S4
  [[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
   [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
   [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
   [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]],

  # S5
  [[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
   [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
   [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
   [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]],

  # S6
  [[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
   [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
   [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
   [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]],

  # S7
  [[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
   [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
   [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
   [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]],

  # S8
  [[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
   [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
   [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
   [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]]
]

#I'm Daniel Tuanna create at 8:57 pm 11/28/2025 

# P-Box
P = [16, 7, 20, 21, 29, 12, 28, 17,
     1, 15, 23, 26, 5, 18, 31, 10,
     2, 8, 24, 14, 32, 27, 3, 9,
     19, 13, 30, 6, 22, 11, 4, 25]

# PC1 / PC2 (Key schedule)
PC1 = [57, 49, 41, 33, 25, 17, 9,
       1, 58, 50, 42, 34, 26, 18,
       10, 2, 59, 51, 43, 35, 27,
       19, 11, 3, 60, 52, 44, 36,
       63, 55, 47, 39, 31, 23, 15,
       7, 62, 54, 46, 38, 30, 22,
       14, 6, 61, 53, 45, 37, 29,
       21, 13, 5, 28, 20, 12, 4]


PC2 = [14,17,11,24,1,5,
       3,28,15,6,21,10,
       23,19,12,4,26,8,
       16,7,27,20,13,2,
       41,52,31,37,47,55,
       30,40,51,45,33,48,
       44,49,39,56,34,53,
       46,42,50,36,29,32]

SHIFT = [1, 1, 2, 2, 2, 2, 2, 2,
         1, 2, 2, 2, 2, 2, 2, 1]

# ==================================================
# Generate round keys
# ==================================================

def generate_round_keys(key64_bits):
    key56 = permute(key64_bits, PC1)
    C, D = key56[:28], key56[28:]
    round_keys = []
    for shift in SHIFT:
        C = shift_left(C, shift)
        D = shift_left(D, shift)
        round_keys.append(permute(C + D, PC2))
    return round_keys

def f(right32, key48):
    expanded = permute(right32, E)
    xored = ''.join('1' if expanded[i] != key48[i] else '0' for i in range(48))
    s_out = ""
    for i in range(8):
        block6 = xored[i*6:(i+1)*6]
        row = int(block6[0] + block6[5], 2)
        col = int(block6[1:5], 2)
        s_val = SBOX[i][row][col]
        s_out += f"{s_val:04b}"
    return permute(s_out, P)

def des_block_encrypt(block64, round_keys):
    block = permute(block64, IP)
    L, R = block[:32], block[32:]
    for i in range(16):
        newR = ''.join('1' if L[j] != f(R, round_keys[i])[j] else '0' for j in range(32))
        L = R
        R = newR
    combined = R + L
    return permute(combined, FP)

def des_block_decrypt(block64, round_keys):
    return des_block_encrypt(block64, round_keys[::-1])



# ==================================================
# Padding (PKCS#7)
# ==================================================

def pad(data: bytes, block_size=8):
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)

def unpad(data: bytes):
    if not data:
        raise ValueError("Cannot unpad empty data")
    pad_len = data[-1]
    
    if pad_len == 0 or pad_len > len(data):
        raise ValueError("Invalid padding")


    if all(data[i] == pad_len for i in range(len(data) - pad_len, len(data))):
        return data[:-pad_len]
    else:
        raise ValueError("Invalid padding detected (non-uniform bytes)")

def des_encrypt(plaintext: bytes, key: bytes, mode='ECB', iv=None, output='hex'):
    key_bits = bytes_to_bitstring(key)
    round_keys = generate_round_keys(key_bits)

    # 🎯 START: LOGIC TẠO IV (Thay đổi này)
    # Tạo IV ngẫu nhiên nếu cần
    if mode in ['CBC', 'CFB', 'OFB']:
        if iv is None:
            # os.urandom tạo byte ngẫu nhiên an toàn (8 bytes cho DES)
            iv = os.urandom(8) 
            # Giữ lại biến iv_generated để biết IV có được tạo mới hay không
            iv_generated = True
        else:
            iv_generated = False
    # 🎯 END: LOGIC TẠO IV
    
    pt = pad(plaintext)
    blocks = [pt[i:i+8] for i in range(0, len(pt), 8)]
    result = b''

    if mode == 'ECB':
        # ... (code ECB cũ)
        for b in blocks:
            b_bits = bytes_to_bitstring(b)
            enc = des_block_encrypt(b_bits, round_keys)
            result += bitstring_to_bytes(enc)

    elif mode == 'CBC':
        # BỎ ĐI: if iv is None: raise ValueError("IV is required for CBC")
        prev = iv
        # ... (code CBC cũ)
        for b in blocks:
            x = bytes(a ^ c for a, c in zip(b, prev))
            enc = des_block_encrypt(bytes_to_bitstring(x), round_keys)
            r = bitstring_to_bytes(enc)
            result += r
            prev = r

    elif mode == 'CFB':
        # BỎ ĐI: if iv is None: raise ValueError("IV is required for CFB")
        prev = iv
        # ... (code CFB cũ)
        for b in blocks:
            out = des_block_encrypt(bytes_to_bitstring(prev), round_keys)
            out_bytes = bitstring_to_bytes(out)
            r = bytes(a ^ c for a, c in zip(out_bytes, b))
            result += r
            prev = r

    elif mode == 'OFB':

        prev = iv

        for b in blocks:
            out = des_block_encrypt(bytes_to_bitstring(prev), round_keys)
            out_bytes = bitstring_to_bytes(out)
            r = bytes(a ^ c for a, c in zip(out_bytes, b))
            result += r
            prev = out_bytes

    if output == 'hex':
        ciphertext = result.hex().upper()
    elif output == 'base64':
        ciphertext = base64_encode(result)

    if mode in ['CBC', 'CFB', 'OFB'] and iv_generated:

        return ciphertext, iv 
    else:

        return ciphertext

def des_decrypt(ciphertext: str, key: bytes, mode='ECB', iv=None, input='hex'):
    if input == 'hex':
        data = bytes.fromhex(ciphertext)
    else:
        data = base64_decode(ciphertext)
    if mode in ['CBC', 'CFB', 'OFB'] and iv is None:
        raise ValueError(f"IV là tham số bắt buộc để giải mã trong chế độ {mode}.")
    
    key_bits = bytes_to_bitstring(key)
    round_keys = generate_round_keys(key_bits)

    blocks = [data[i:i+8] for i in range(0, len(data), 8)]
    result = b''

    if mode == 'ECB':
        for b in blocks:
            enc = des_block_decrypt(bytes_to_bitstring(b), round_keys)
            result += bitstring_to_bytes(enc)

    elif mode == 'CBC':
        if iv is None:
            raise ValueError("IV is required for CBC")
        prev = iv
        for b in blocks:
            dec_bits = des_block_decrypt(bytes_to_bitstring(b), round_keys)
            dec = bitstring_to_bytes(dec_bits)
            r = bytes(a ^ c for a, c in zip(dec, prev))
            result += r
            prev = b

    return unpad(result)


pt = b"HELLO WORLD"
key = b"\x13\x34\x57\x79\x9B\xBC\xDF\xF1"
iv  = b"\x01\x23\x45\x67\x89\xAB\xCD\xEF"
try:
    result_tuple = des_encrypt(pt, key, mode='CBC', iv=None, output='hex')
    if isinstance(result_tuple, tuple):
        cipher, new_iv = result_tuple
        print(f"\n--- CBC (IV Tự Động Tạo) ---")
        print(f"Cipher: {cipher}")
        print(f"IV Mới (Bytes): {new_iv}")
        

        plain = des_decrypt(cipher, key, mode='CBC', iv=new_iv, input='hex')
        print(f"Plain: {plain}")
    else:

        cipher = result_tuple
        print(f"Cipher ECB: {cipher}")
        
except ValueError as e:
    print(f"Lỗi: {e}")

cipherA = des_encrypt(pt, key, mode='ECB', iv=None, output='hex') 
print(f"\n--- ECB ---")
print(f"CipherA: {cipherA}")

plainA = des_decrypt(cipherA, key, mode='ECB', iv=None, input='hex')
print(f"PlainA: {plainA}")