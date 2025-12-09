import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

# --- Khai báo hằng số ---
BLOCK_SIZE = 16  # 128 bit
MODE_ECB = 'ECB'
MODE_CBC = 'CBC'

# --- Hàm hỗ trợ ---
def _validate_key_and_mode(key: bytes, mode: str):
    """Kiểm tra tính hợp lệ của khóa và chế độ."""
    key_len = len(key)
    if key_len not in [16, 24, 32]:
        raise ValueError("Lỗi: Khóa AES phải có độ dài 16 (128-bit), 24 (192-bit), hoặc 32 (256-bit) byte.")

    mode_upper = mode.upper()
    if mode_upper not in [MODE_ECB, MODE_CBC]:
        raise ValueError(f"Lỗi: Chế độ '{mode}' không được hỗ trợ. Chỉ hỗ trợ '{MODE_ECB}' và '{MODE_CBC}'.")
    return mode_upper

# --- Hàm Mã hóa ---
def encrypt(plaintext: bytes, key: bytes, mode: str, iv: bytes = None) -> str:
    """
    Mã hóa dữ liệu bằng thuật toán AES.
    
    Tham số:
        plaintext (bytes): Dữ liệu cần mã hóa.
        key (bytes): Khóa AES.
        mode (str): Chế độ hoạt động ('ECB' hoặc 'CBC').
        iv (bytes, optional): Vector khởi tạo 16 byte. Tự động tạo nếu là CBC và không được cung cấp.
        
    Trả về:
        str: Ciphertext được mã hóa Base64 (bao gồm IV nếu là CBC).
    """
    mode_upper = _validate_key_and_mode(key, mode)

    # 1. Quản lý IV và Padding
    padded_data = pad(plaintext, BLOCK_SIZE, style='pkcs7')

    if mode_upper == MODE_ECB:
        # ECB: Không cần IV
        cipher = AES.new(key, AES.MODE_ECB)
        iv_data = b'' # Không thêm IV vào đầu ra
    
    elif mode_upper == MODE_CBC:
        # CBC: Bắt buộc IV
        if iv is None:
            # Yêu cầu: Nếu IV không được cung cấp, tự động tạo IV ngẫu nhiên
            iv = get_random_bytes(BLOCK_SIZE)
            print(f"Ghi chú: IV ngẫu nhiên đã được tạo cho chế độ {MODE_CBC}.")
        
        if len(iv) != BLOCK_SIZE:
             raise ValueError(f"Lỗi: IV cho chế độ {MODE_CBC} phải có độ dài 16 byte.")
             
        cipher = AES.new(key, AES.MODE_CBC, iv) 
        iv_data = iv # Thêm IV vào đầu ra để phục vụ giải mã

    # 2. Mã hóa
    ciphertext_raw = cipher.encrypt(padded_data)

    # 3. Kết hợp IV và Ciphertext và Base64
    final_output = iv_data + ciphertext_raw
    return base64.b64encode(final_output).decode('utf-8')

# --- Hàm Giải mã ---
def decrypt(ciphertext: str, key: bytes, mode: str, iv: bytes = None) -> bytes:
    """
    Giải mã dữ liệu bằng thuật toán AES.

    Tham số:
        ciphertext (str): Dữ liệu Base64 đã mã hóa.
        key (bytes): Khóa AES.
        mode (str): Chế độ hoạt động ('ECB' hoặc 'CBC').
        iv (bytes, optional): Vector khởi tạo 16 byte (BẮT BUỘC cho CBC).
    
    Trả về:
        bytes: Plaintext gốc sau khi giải mã.
    """
    mode_upper = _validate_key_and_mode(key, mode)

    # 1. Decode Base64
    ciphertext_full_raw = base64.b64decode(ciphertext)
    
    # 2. Tách IV và Ciphertext
    if mode_upper == MODE_ECB:
        ciphertext_raw = ciphertext_full_raw
        iv_used = None
    
    elif mode_upper == MODE_CBC:
        # Trong trường hợp IV không được truyền vào decrypt(), 
        # ta vẫn ưu tiên trích xuất IV từ 16 byte đầu của ciphertext (theo logic encrypt() ở trên).
        if iv is None:
            if len(ciphertext_full_raw) < BLOCK_SIZE:
                raise ValueError("Lỗi: Ciphertext CBC quá ngắn. Không tìm thấy IV 16 byte.")
            iv_used = ciphertext_full_raw[:BLOCK_SIZE]
            ciphertext_raw = ciphertext_full_raw[BLOCK_SIZE:]
            print("Ghi chú: IV được trích xuất tự động từ Ciphertext.")
        else:
            # Nếu IV được truyền vào, ta sử dụng IV đó và coi toàn bộ ciphertext_full_raw là ciphertext thực
            if len(iv) != BLOCK_SIZE:
                 raise ValueError(f"Lỗi: IV được cung cấp cho chế độ {MODE_CBC} phải có độ dài 16 byte.")
            iv_used = iv
            ciphertext_raw = ciphertext_full_raw
            print("Ghi chú: Sử dụng IV được cung cấp.")


    # 3. Khởi tạo đối tượng Cipher
    if mode_upper == MODE_ECB:
        cipher = AES.new(key, AES.MODE_ECB)
    elif mode_upper == MODE_CBC:
        cipher = AES.new(key, AES.MODE_CBC, iv_used) 

    # 4. Giải mã
    padded_plaintext = cipher.decrypt(ciphertext_raw)

    # 5. Loại bỏ Padding (PKCS#7)
    try:
        plaintext = unpad(padded_plaintext, BLOCK_SIZE, style='pkcs7')
    except ValueError as e:
        # Lỗi này thường xảy ra nếu khóa hoặc IV không chính xác
        raise ValueError(f"Lỗi giải mã: Khóa hoặc IV không chính xác. Không thể loại bỏ PKCS#7 Padding. Chi tiết: {e}")

    return plaintext

# --- Ví dụ minh họa ---

## 🧪 Ví dụ 1: CBC - Tự động tạo IV
print("--- Ví dụ 1: CBC với IV Tự động tạo (Key 192-bit) ---")
key_cbc_192 = get_random_bytes(24) # 24 byte (192-bit)
plaintext_cbc = b'This is a secret message that is longer than 16 bytes.'

try:
    # Mã hóa (IV = None, chương trình tự tạo)
    ciphertext_cbc = encrypt(plaintext_cbc, key_cbc_192, MODE_CBC, iv=None)
    print(f"Key (192-bit): {key_cbc_192.hex()}")
    print(f"Ciphertext (Base64): {ciphertext_cbc}")

    # Giải mã (IV = None, chương trình tự trích xuất IV từ ciphertext)
    decrypted_cbc = decrypt(ciphertext_cbc, key_cbc_192, MODE_CBC, iv=None)
    print(f"Decrypted Plaintext: {decrypted_cbc.decode('utf-8')}")
    print(f"Match: {plaintext_cbc == decrypted_cbc}")
except Exception as e:
    print(f"Lỗi: {e}")

print("\n" + "="*50 + "\n")

## 🧪 Ví dụ 2: ECB - Mã hóa/Giải mã
print("--- Ví dụ 2: ECB (Key 128-bit) ---")
key_ecb_128 = get_random_bytes(16)
plaintext_ecb = b'ECB mode requires proper padding.'

try:
    # Mã hóa
    ciphertext_ecb = encrypt(plaintext_ecb, key_ecb_128, MODE_ECB)
    print(f"Key (128-bit): {key_ecb_128.hex()}")
    print(f"Ciphertext (Base64): {ciphertext_ecb}")

    # Giải mã
    decrypted_ecb = decrypt(ciphertext_ecb, key_ecb_128, MODE_ECB)
    print(f"Decrypted Plaintext: {decrypted_ecb.decode('utf-8')}")
    print(f"Match: {plaintext_ecb == decrypted_ecb}")
except Exception as e:
    print(f"Lỗi: {e}")