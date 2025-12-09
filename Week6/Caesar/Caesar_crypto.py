################################################################
# MSSV 23521717
# Nguyen Anh Tuan
# Caesar_Crypto.py
# (Chuyển đổi từ mã C++)
################################################################
import os
from typing import Dict, Optional

BRUTEFORCE_KEY = 26

class CaesarCracker:
    """
    Thực hiện phá mã vét cạn cho mã Caesar.
    """
    def __init__(self, input_file_path: str = "ciphertext.txt"):
        self.ciphertext: str = ""
        # results: map<int, string> -> Dict[int, str]
        self.results: Dict[int, str] = {}
        self.input_file_path = input_file_path
        
        # Gọi hàm đọc file trong constructor, tương tự như C++
        self.get_cipher_text_from_file(self.input_file_path)

    def set_cipher_text(self, str_cipher: str):
        self.ciphertext = str_cipher
        
    def get_cipher_text(self) -> str:
        return self.ciphertext
    
    def get_results(self) -> Dict[int, str]:
        return self.results

    def get_cipher_text_from_file(self, file_path: str) -> bool:
        """Đọc toàn bộ nội dung file và đặt làm ciphertext."""
        self.input_file_path = file_path
        if not os.path.exists(file_path):
            self.set_cipher_text("")
            return False

        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                self.set_cipher_text(f.read())
            return True
        except Exception as e:
            self.set_cipher_text("")
            return False

    def brute_force_decryption(self, cipher: str) -> Dict[int, str]:
        """
        Thực hiện giải mã vét cạn 26 lần dịch chuyển (key 0 đến 25).
        """
        results: Dict[int, str] = {}
        for k in range(BRUTEFORCE_KEY):
            plaintext = []
            for c in cipher:
                if c.isalpha():
                    # Xác định cơ sở (A cho in hoa, a cho in thường)
                    base = ord('A') if c.isupper() else ord('a')
                    
                    # Chuyển thành chỉ số 0-25
                    c_index = ord(c) - base
                    
                    # Công thức giải mã: P = (C - K) mod 26
                    # (c_index - k) % 26
                    dec_index = (c_index - k) % 26
                    
                    # Chuyển lại thành ký tự
                    plaintext.append(chr(dec_index + base))
                else:
                    # Giữ nguyên ký tự không phải chữ cái
                    plaintext.append(c)
            
            results[k] = "".join(plaintext)
        return results

    def set_result(self):
        """Chạy brute force và lưu kết quả vào self.results."""
        if not self.ciphertext:
            print("Cảnh báo: Ciphertext rỗng, không thể phá mã.")
            self.results = {}
            return

        self.results = self.brute_force_decryption(self.ciphertext)

    def print_result(self):
        """In kết quả ra console."""
        for k, p in self.results.items():
            print(f"Key {k}: {p[:50]}...") # Chỉ in 50 ký tự đầu

    def write_plaintext_to_file(self, key: int, output_file_path: str = "result.txt"):
        """Ghi kết quả giải mã cho một Key cụ thể ra file."""
        if key not in self.results:
            print(f"Lỗi: Key {key} không hợp lệ. Vui lòng chạy SetResult() trước.")
            return False

        try:
            with open(output_file_path, 'w', encoding='utf-8') as out:
                out.write(f"Key: {key}\n")
                out.write(f"Plaintext:\n")
                out.write(self.results[key])
            print(f"Plaintext cho Key {key} đã được ghi vào {output_file_path} thành công.")
            return True
        except IOError:
            print(f"Lỗi: Không thể ghi vào file {output_file_path}.")
            return False

# Ví dụ thực thi (tương đương với main() trong C++)
if __name__ == "__main__":
    # Cần có file ciphertext.txt trong cùng thư mục để test
    test = CaesarCracker(input_file_path="ciphertext.txt") 
    test.set_result()
    test.print_result()
    # Key = 4 là ví dụ bạn dùng trong C++
    test.write_plaintext_to_file(4)