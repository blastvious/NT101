###############################
# Nguyen Anh Tuan 23521717
# AES-crypto.py
# repo: https://github.com/blastvious/NT101
###############################
import os
import base64
from typing import Optional, Tuple, Literal

# --- CÁC HẰNG SỐ VÀ BẢNG TRA ---
BLOCK_SIZE = 16 
AES_Mode = Literal['ECB', 'CBC']

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
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
]


INV_S_BOX = [
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6e,
    0x9f, 0xac, 0x7a, 0x69, 0x47, 0x91, 0x4a, 0xbe, 0x19, 0x3a, 0x6b, 0x9e, 0x6c, 0x3b, 0x27, 0xf5,
    0xee, 0x7b, 0x8d, 0x09, 0x34, 0x7a, 0x13, 0x77, 0x62, 0xae, 0x3c, 0x4f, 0x36, 0x71, 0x20, 0x4d,
    0x78, 0x8c, 0x40, 0x3a, 0x05, 0x04, 0x85, 0xe9, 0x45, 0x15, 0x00, 0x3c, 0x92, 0x53, 0x60, 0x7e,
    0x0a, 0x3f, 0x26, 0xaa, 0x2d, 0x57, 0x0f, 0xb6, 0x2c, 0x80, 0x61, 0x37, 0x3e, 0xa5, 0x7f, 0xdc,
    0xca, 0x1a, 0xef, 0x2f, 0xba, 0x81, 0xf4, 0x6a, 0x6f, 0x4b, 0x35, 0x4e, 0xa9, 0xf6, 0x08, 0x6e,
    0x8a, 0x1b, 0xf9, 0x44, 0x53, 0xd4, 0x4a, 0xd5, 0x75, 0xda, 0x99, 0x3d, 0xce, 0x6c, 0x1e, 0x0e,
    0xd3, 0x47, 0x0c, 0x2c, 0x1a, 0x7b, 0xf7, 0x05, 0xd2, 0x61, 0xe1, 0x79, 0x3c, 0x56, 0xa4, 0x8e,
    0x0a, 0x80, 0x7e, 0xf2, 0x72, 0x45, 0x04, 0x56, 0x8d, 0xa0, 0x58, 0x31, 0x81, 0x7d, 0xba, 0x7e
]

RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x56, 0xac]


## --- CÁC HÀM CƠ SỞ CỦA AES ---

# --- PHÉP NHÂN TRONG TRƯỜNG GALOIS GF(2^8) ---
def gmul(a, b):
    """Phép nhân 'a' * 'b' trong trường Galois GF(2^8) (mod x^8 + x^4 + x^3 + x + 1)."""
    p = 0
    # Lặp qua 8 bit của 'b'
    for _ in range(8):
        if b & 1:
            p ^= a
        
        if a & 0x80:
            a = (a << 1) ^ 0x1B 
        else:
            a <<= 1
        a &= 0xFF 
        b >>= 1
    
    return p & 0xFF # Đảm bảo kết quả trả về là 8 bit
def bytes_to_state(data: bytes) -> list[list[int]]:
    """Chuyển 16 bytes thành ma trận trạng thái 4x4 (theo cột)."""
    state = [[0] * 4 for _ in range(4)]
    for i in range(BLOCK_SIZE):
        r = i % 4
        c = i // 4
        state[r][c] = data[i]
    return state

def state_to_bytes(state: list[list[int]]) -> bytes:
    """Chuyển ma trận trạng thái 4x4 thành 16 bytes (theo cột)."""
    output = bytearray(BLOCK_SIZE)
    for i in range(BLOCK_SIZE):
        r = i % 4
        c = i // 4
        output[i] = state[r][c]
    return bytes(output)

# --- KEY EXPANSION (Hỗ trợ 128/192/256) ---

def rot_word(word: bytes) -> bytes:
    """RotWord: Quay trái 1 byte trong 4 bytes (word)."""
    return word[1:] + word[:1]

def sub_word(word: bytes, box: list[int]) -> bytes:
    """SubWord: Thay thế từng byte của word bằng S_BOX."""
    return bytes(box[b] for b in word)

# --- KEY EXPANSION (Hỗ trợ 128/192/256) ---
def key_expansion(key: bytes) -> list[bytes]:
    """Tạo tất cả các khóa vòng dựa trên độ dài khóa."""
    Nk = len(key) // 4      # Số lượng words trong khóa (4, 6, 8)
    if Nk == 4: Nr, total_words = 10, 44  # AES-128
    elif Nk == 6: Nr, total_words = 12, 52 # AES-192
    elif Nk == 8: Nr, total_words = 14, 60 # AES-256
    else: raise ValueError("Khóa phải là 16, 24, hoặc 32 bytes.")

    w = [key[i:i+4] for i in range(0, len(key), 4)]
    
    i = Nk
    while i < total_words:
        temp = w[i-1]
        
        if i % Nk == 0:
            temp = rot_word(temp)
            temp = sub_word(temp, S_BOX)
            
            rcon_val = RCON[i // Nk - 1]
            temp_list = list(temp)
            temp_list[0] ^= rcon_val
            temp = bytes(temp_list)
            
        elif Nk > 6 and i % Nk == 4:
            temp = sub_word(temp, S_BOX)

        w.append(bytes(w[i-Nk][k] ^ temp[k] for k in range(4)))
        i += 1
    round_keys = []
    for j in range(Nr + 1):
        start_index = j * 4
        round_key = b''.join(w[start_index : start_index + 4])
        round_keys.append(round_key)
        
    return round_keys, Nr

# --- CÁC HÀM TRANG THÁI AES (Core functions) ---

def add_round_key(state: list[list[int]], round_key: bytes) -> list[list[int]]:
    """AddRoundKey: XOR trạng thái với khóa vòng."""
    for c in range(4):
        for r in range(4):
            state[r][c] ^= round_key[r + 4 * c]
    return state

def sub_bytes(state: list[list[int]], box: list[int]) -> list[list[int]]:
    """SubBytes / InvSubBytes: Thay thế byte."""
    for r in range(4):
        for c in range(4):
            state[r][c] = box[state[r][c]]
    return state

def shift_rows(state: list[list[int]]) -> list[list[int]]:
    """ShiftRows: Quay trái từng hàng."""
    state[1] = state[1][1:] + state[1][:1]
    state[2] = state[2][2:] + state[2][:2]
    state[3] = state[3][3:] + state[3][:3]
    return state

def inv_shift_rows(state: list[list[int]]) -> list[list[int]]:
    """InvShiftRows: Quay phải từng hàng."""
    state[1] = state[1][-1:] + state[1][:-1]
    state[2] = state[2][-2:] + state[2][:-2]
    state[3] = state[3][-3:] + state[3][:-3]
    return state

def mix_columns(state: list[list[int]]) -> list[list[int]]:
    """MixColumns: Nhân ma trận với [0x02, 0x03, 0x01, 0x01]."""
    new_state = [[0] * 4 for _ in range(4)]
    for c in range(4):
        s = [state[r][c] for r in range(4)] # Lấy cột hiện tại
        new_state[0][c] = gmul(0x02, s[0]) ^ gmul(0x03, s[1]) ^ gmul(0x01, s[2]) ^ gmul(0x01, s[3])
        new_state[1][c] = gmul(0x01, s[0]) ^ gmul(0x02, s[1]) ^ gmul(0x03, s[2]) ^ gmul(0x01, s[3])
        new_state[2][c] = gmul(0x01, s[0]) ^ gmul(0x01, s[1]) ^ gmul(0x02, s[2]) ^ gmul(0x03, s[3])
        new_state[3][c] = gmul(0x03, s[0]) ^ gmul(0x01, s[1]) ^ gmul(0x01, s[2]) ^ gmul(0x02, s[3])
    return new_state

def inv_mix_columns(state: list[list[int]]) -> list[list[int]]:
    """InvMixColumns: Nhân ma trận với [0x0e, 0x0b, 0x0d, 0x09]."""
    new_state = [[0] * 4 for _ in range(4)]
    for c in range(4):
        s = [state[r][c] for r in range(4)] # Lấy cột hiện tại
        new_state[0][c] = gmul(0x0e, s[0]) ^ gmul(0x0b, s[1]) ^ gmul(0x0d, s[2]) ^ gmul(0x09, s[3])
        new_state[1][c] = gmul(0x09, s[0]) ^ gmul(0x0e, s[1]) ^ gmul(0x0b, s[2]) ^ gmul(0x0d, s[3])
        new_state[2][c] = gmul(0x0d, s[0]) ^ gmul(0x09, s[1]) ^ gmul(0x0e, s[2]) ^ gmul(0x0b, s[3])
        new_state[3][c] = gmul(0x0b, s[0]) ^ gmul(0x0d, s[1]) ^ gmul(0x09, s[2]) ^ gmul(0x0e, s[3])
    return new_state


## --- THUẬT TOÁN AES LÕI (BLOCK) ---

def aes_encrypt_block(data: bytes, expanded_keys: list[bytes], Nr: int) -> bytes:
    """Thực hiện Mã hóa AES cho 1 khối 16 byte."""
    state = bytes_to_state(data)
    
    state = add_round_key(state, expanded_keys[0])
    
    for r in range(1, Nr):
        state = sub_bytes(state, S_BOX)
        state = shift_rows(state)
        state = mix_columns(state)
        state = add_round_key(state, expanded_keys[r])
        
    state = sub_bytes(state, S_BOX)
    state = shift_rows(state)
    state = add_round_key(state, expanded_keys[Nr])
    
    return state_to_bytes(state)

def aes_decrypt_block(data: bytes, expanded_keys: list[bytes], Nr: int) -> bytes:
    """Thực hiện Giải mã AES cho 1 khối 16 byte."""
    state = bytes_to_state(data)
    
    state = add_round_key(state, expanded_keys[Nr])
    
    for r in range(Nr - 1, 0, -1):
        state = inv_shift_rows(state)
        state = sub_bytes(state, INV_S_BOX)
        # Thay đổi thứ tự: Đưa InvMixColumns lên trước
        state = inv_mix_columns(state)
        state = add_round_key(state, expanded_keys[r]) 
        
    state = inv_shift_rows(state)
    state = sub_bytes(state, INV_S_BOX)
    state = add_round_key(state, expanded_keys[0])
    
    return state_to_bytes(state)

## --- PADDING VÀ CHẾ ĐỘ HOẠT ĐỘNG ---

def pkcs7_pad(data: bytes) -> bytes:
    """PKCS#7 Padding."""
    padding_len = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
    return data + bytes([padding_len] * padding_len)

def pkcs7_unpad(data: bytes) -> bytes:
    """PKCS#7 Unpadding (Đã sửa)."""
    if not data: 
        return b''
        
    padding_len = data[-1]
    
    if padding_len == 0 or padding_len > BLOCK_SIZE:
          raise ValueError("Padding không hợp lệ: Độ dài không hợp lệ.")
          
    padding_bytes = data[-padding_len:] 
    
    if any(b != padding_len for b in padding_bytes):
        raise ValueError("Padding không hợp lệ: Các byte padding không đồng nhất.")
        
    # 3. Loại bỏ padding
    return data[:-padding_len]
def check_key_length(key: bytes):
    """Kiểm tra độ dài khóa."""
    if len(key) not in [16, 24, 32]:
        raise ValueError(f"Khóa phải là 16 (AES-128), 24 (AES-192), hoặc 32 (AES-256) bytes.")

# --- HÀM MÃ HÓA CHÍNH (encrypt) ---
def encrypt(
    plaintext: bytes, 
    key: bytes, 
    mode: AES_Mode, 
    iv: Optional[bytes] = None
) -> Tuple[str, Optional[bytes]]:
    
    check_key_length(key)
    expanded_keys, Nr = key_expansion(key)
    
    # 1. Padding
    padded_data = pkcs7_pad(plaintext)
    num_blocks = len(padded_data) // BLOCK_SIZE
    ciphertext = bytearray()
    
    # 2. Xử lý IV và CBC
    final_iv = None
    if mode == 'CBC':
        if iv is None:
            # Tự động tạo IV ngẫu nhiên
            final_iv = os.urandom(BLOCK_SIZE)
        else:
            if len(iv) != BLOCK_SIZE:
                raise ValueError("IV phải có độ dài 16 bytes.")
            final_iv = iv
        current_block_iv = final_iv
    elif mode == 'ECB':
        pass # Không dùng IV
    else:
        raise NotImplementedError(f"Chế độ hoạt động '{mode}' chưa được triển khai.")
    
    # 3. Mã hóa từng Block
    for i in range(num_blocks):
        block = padded_data[i*BLOCK_SIZE : (i+1)*BLOCK_SIZE]
        
        if mode == 'CBC':
            # CBC: XOR Plaintext với IV/Ciphertext khối trước đó
            input_block = bytes(b1 ^ b2 for b1, b2 in zip(block, current_block_iv))
            cipher_block = aes_encrypt_block(input_block, expanded_keys, Nr)
            current_block_iv = cipher_block # Cập nhật IV cho khối tiếp theo
        elif mode == 'ECB':
            # ECB: Mã hóa trực tiếp
            cipher_block = aes_encrypt_block(block, expanded_keys, Nr)
            
        ciphertext.extend(cipher_block)

    # Output: Base64 và IV (nếu có)
    return base64.b64encode(ciphertext).decode('utf-8'), final_iv

# --- HÀM GIẢI MÃ CHÍNH (decrypt) ---
def decrypt(
    ciphertext_base64: str, 
    key: bytes, 
    mode: AES_Mode, 
    iv: bytes
) -> bytes:
    
    check_key_length(key)
    expanded_keys, Nr = key_expansion(key)

    # 1. Decode Base64 và Khởi tạo
    ciphertext = base64.b64decode(ciphertext_base64)
    if len(ciphertext) % BLOCK_SIZE != 0:
        raise ValueError("Ciphertext không hợp lệ (không chia hết cho kích thước khối).")
        
    num_blocks = len(ciphertext) // BLOCK_SIZE
    decrypted_data = bytearray()

    # 2. Xử lý IV và CBC
    if mode == 'CBC':
        if iv is None or len(iv) != BLOCK_SIZE:
            raise ValueError("Chế độ CBC bắt buộc phải có IV 16 bytes khi giải mã.")
        current_iv = iv
    elif mode == 'ECB':
        if iv is not None:
             print("Cảnh báo: IV không được sử dụng trong chế độ ECB.")
        current_iv = None # Không dùng IV cho ECB
    else:
        raise NotImplementedError(f"Chế độ hoạt động '{mode}' chưa được triển khai.")

    # 3. Giải mã từng Block
    for i in range(num_blocks):
        cipher_block = ciphertext[i*BLOCK_SIZE : (i+1)*BLOCK_SIZE]
        
        if mode == 'CBC':
            decrypted_block = aes_decrypt_block(cipher_block, expanded_keys, Nr)
            plain_block = bytes(b1 ^ b2 for b1, b2 in zip(decrypted_block, current_iv))
            current_iv = cipher_block # Cập nhật IV cho khối tiếp theo
        elif mode == 'ECB':
            # ECB: Giải mã trực tiếp
            plain_block = aes_decrypt_block(cipher_block, expanded_keys, Nr)
        
        decrypted_data.extend(plain_block)
        
    # 4. Loại bỏ Padding
    return pkcs7_unpad(bytes(decrypted_data))


## --- VÍ DỤ  ---

if __name__ == '__main__':
    print("--- CHƯƠNG TRÌNH MÃ HÓA/GIẢI MÃ AES TỰ CÀI ĐẶT (ECB & CBC) ---")
    
    data_bytes = b"This is the plaintext data for testing AES encryption modes."
    
    aes_key_32 = os.urandom(32) 
    print(f"Key Size: {len(aes_key_32)*8} bits (AES-256)")
    print(f"Key (Hex): {aes_key_32.hex()}")
    print("-" * 70)

    print("### 1. CHẾ ĐỘ: CBC (Yêu cầu IV) ###")
    
    try:
        cipher_text_cbc_b64, iv_cbc = encrypt(data_bytes, aes_key_32, mode='CBC')
        print(f"Plaintext gốc: {data_bytes.decode()}")
        print(f"Ciphertext (Base64): {cipher_text_cbc_b64}")
        print(f"IV được tạo (Hex): {iv_cbc.hex()}")

        decrypted_data_cbc = decrypt(cipher_text_cbc_b64, aes_key_32, mode='CBC', iv=iv_cbc)
        
        print(f"Decrypted: {decrypted_data_cbc.decode()}")
        assert decrypted_data_cbc == data_bytes, "LỖI: Giải mã CBC không khớp."
        print("\n=> CBC TEST: THÀNH CÔNG!")
    except Exception as e:
        print(f"\n=> CBC TEST: THẤT BẠI! Lỗi: {e}")
    print("-" * 70)

    print("### 2. CHẾ ĐỘ: ECB (Không dùng IV) ###")

    try:
        cipher_text_ecb_b64, iv_ecb_out = encrypt(data_bytes, aes_key_32, mode='ECB', iv=None)
        print(f"Ciphertext (Base64): {cipher_text_ecb_b64}")
        print(f"IV trả về: {iv_ecb_out}")

        decrypted_data_ecb = decrypt(cipher_text_ecb_b64, aes_key_32, mode='ECB', iv=None)
        
        print(f"Decrypted: {decrypted_data_ecb.decode()}")
        assert decrypted_data_ecb == data_bytes, "LỖI: Giải mã ECB không khớp."
        print("\n=> ECB TEST: THÀNH CÔNG!")
    except Exception as e:
        print(f"\n=> ECB TEST: THẤT BẠI! Lỗi: {e}")
    print("-" * 70)

    data_test_block = b"test block 12345" # Dữ liệu khớp 1 khối
    
    # CBC: So sánh và Giải mã
    try:
        cipher_text_cbc_b64_2, iv_cbc_2 = encrypt(data_test_block, aes_key_32, mode='CBC')
        cipher_text_cbc_b64_3, iv_cbc_3 = encrypt(data_test_block, aes_key_32, mode='CBC')
        
        # Kiểm tra Giải mã CBC
        decrypted_cbc = decrypt(cipher_text_cbc_b64_2, aes_key_32, mode='CBC', iv=iv_cbc_2)
        assert decrypted_cbc == data_test_block, "LỖI: Giải mã CBC không khớp trong phần so sánh."

        print("\nKiểm tra CBC (2 lần mã hóa cùng dữ liệu):")
        print(f"Lần 1: {cipher_text_cbc_b64_2[:20]}...")
        print(f"Lần 2: {cipher_text_cbc_b64_3[:20]}...")
        print(f"=> Kết quả so sánh: {'KHÁC NHAU (ĐÚNG)' if cipher_text_cbc_b64_2 != cipher_text_cbc_b64_3 else 'GIỐNG NHAU (SAI)'}")
        print("=> Kiểm tra Giải mã CBC: THÀNH CÔNG")
    except Exception as e:
        print(f"\n=> CBC So sánh/Giải mã: THẤT BẠI! Lỗi: {e}")

    print("-" * 70)
    
    # ECB: So sánh và Giải mã
    try:
        cipher_text_ecb_b64_2, _ = encrypt(data_test_block, aes_key_32, mode='ECB')
        cipher_text_ecb_b64_3, _ = encrypt(data_test_block, aes_key_32, mode='ECB')
        
        # Kiểm tra Giải mã ECB
        decrypted_ecb = decrypt(cipher_text_ecb_b64_2, aes_key_32, mode='ECB', iv=None)
        assert decrypted_ecb == data_test_block, "LỖI: Giải mã ECB không khớp trong phần so sánh."

        print("\nKiểm tra ECB (2 lần mã hóa cùng dữ liệu):")
        print(f"Lần 1: {cipher_text_ecb_b64_2[:20]}...")
        print(f"Lần 2: {cipher_text_ecb_b64_3[:20]}...")
        print(f"=> Kết quả so sánh: {'GIỐNG NHAU (ĐÚNG)' if cipher_text_ecb_b64_2 == cipher_text_ecb_b64_3 else 'KHÁC NHAU (SAI)'}")
        print("=> Kiểm tra Giải mã ECB: THÀNH CÔNG")
    except Exception as e:
        print(f"\n=> ECB So sánh/Giải mã: THẤT BẠI! Lỗi: {e}")
    print("-" * 70)