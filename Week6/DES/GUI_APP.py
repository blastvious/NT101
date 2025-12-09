################################################################
# MSSV 23521717
# Nguyen Anh Tuan
# GUI_APP.py
################################################################

from tkinter import *
from tkinter import ttk, messagebox
import os
import base64
from typing import Optional


try:
    # Import các hàm chính từ module logic DES
    from Des_Crypto import des_encrypt, des_decrypt
    # DES BLOCK SIZE là 8 bytes
    BLOCK_SIZE = 8 
except ImportError:
    messagebox.showerror("Lỗi Module", "Không tìm thấy file DES_crypto.py. Vui lòng đảm bảo đã tạo file này và chứa logic DES.")
    # Tạo hàm giả để chương trình có thể chạy GUI
    def des_encrypt(p, k, m, iv=None, output='base64'): raise NotImplementedError("Lỗi: Không tìm thấy logic DES.")
    def des_decrypt(c, k, m, iv, input='base64'): raise NotImplementedError("Lỗi: Không tìm thấy logic DES.")
    BLOCK_SIZE = 8
    
# Kích thước khóa DES cố định
KEY_SIZE = 8 


class DES_GUI_App:
    def __init__(self, master):
        self.master = master
        master.title("Mã Hóa & Giải Mã DES (ECB/CBC) - 23521717")
        master.geometry('850x700')
        master.config(padx=20, pady=20)
        
        # --- Variables ---
        self.mode = StringVar(value="CBC")
        self.key_input = StringVar()
        self.iv_input = StringVar()
        
        # --- Setup Main Layout ---
        self.setup_ui_layout()

    def setup_ui_layout(self):
        # Frame 1: Input Control (Key, Mode, IV)
        input_frame = ttk.LabelFrame(self.master, text="Tham Số Mã Hóa DES", padding="10")
        input_frame.pack(fill="x", pady=10)

        # 1. Key Input (Fixed size: 8 bytes / 64 bits)
        ttk.Label(input_frame, text=f"Khóa (Base64/Hex - {KEY_SIZE} bytes):").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.key_entry = ttk.Entry(input_frame, textvariable=self.key_input, width=40)
        self.key_entry.grid(row=0, column=1, columnspan=2, padx=5, pady=5, sticky="ew")
        
        # Nút tạo Khóa ngẫu nhiên
        ttk.Button(input_frame, text="Tạo Khóa ngẫu nhiên", command=self.generate_key).grid(row=0, column=3, padx=5, pady=5)
        
        # 2. Mode
        ttk.Label(input_frame, text="Chế độ hoạt động:").grid(row=1, column=0, padx=5, pady=5, sticky="w")
        mode_options = ['CBC', 'ECB']
        self.mode_combo = ttk.Combobox(input_frame, textvariable=self.mode, values=mode_options, state="readonly", width=10)
        self.mode_combo.grid(row=1, column=1, padx=5, pady=5, sticky="w")
        self.mode_combo.bind("<<ComboboxSelected>>", self.on_mode_change)

        # 3. IV
        ttk.Label(input_frame, text=f"IV (Base64/Hex - {BLOCK_SIZE} bytes):").grid(row=2, column=0, padx=5, pady=5, sticky="w")
        self.iv_entry = ttk.Entry(input_frame, textvariable=self.iv_input, width=40)
        self.iv_entry.grid(row=2, column=1, columnspan=2, padx=5, pady=5, sticky="ew")
        self.iv_entry.config(state=NORMAL)
        ttk.Button(input_frame, text="Tạo IV ngẫu nhiên", command=self.generate_iv).grid(row=2, column=3, padx=5, pady=5)
        
        input_frame.columnconfigure(1, weight=1)

        # Frame 2: Text Areas (Input & Output)
        text_frame = ttk.Frame(self.master)
        text_frame.pack(fill="both", expand=True, pady=10)

        # Plaintext/Input Area
        ttk.Label(text_frame, text="Plaintext (Đầu vào):").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.plaintext_text = Text(text_frame, height=10, width=40)
        self.plaintext_text.grid(row=1, column=0, padx=5, pady=5, sticky="nsew")

        # Ciphertext/Output Area
        ttk.Label(text_frame, text="Ciphertext (Base64):").grid(row=0, column=1, padx=5, pady=5, sticky="w")
        self.ciphertext_text = Text(text_frame, height=10, width=40)
        self.ciphertext_text.grid(row=1, column=1, padx=5, pady=5, sticky="nsew")
        
        text_frame.columnconfigure(0, weight=1)
        text_frame.columnconfigure(1, weight=1)
        text_frame.rowconfigure(1, weight=1)

        # Frame 3: Action Buttons
        button_frame = ttk.Frame(self.master)
        button_frame.pack(fill="x", pady=10)
        
        ttk.Button(button_frame, text="MÃ HÓA (Encrypt)", command=self.handle_encrypt, style='Accent.TButton',).pack(side=LEFT, padx=10, expand=True, fill="x")
        ttk.Button(button_frame, text="GIẢI MÃ (Decrypt)", command=self.handle_decrypt, style='Accent.TButton').pack(side=LEFT, padx=10, expand=True, fill="x")

    # --- Utility Functions ---

    def on_mode_change(self, event):
        """Vô hiệu hóa trường IV khi chọn chế độ ECB."""
        if self.mode.get() == 'ECB':
            self.iv_entry.config(state=DISABLED)
            self.iv_input.set("")
        else:
            self.iv_entry.config(state=NORMAL)

    def generate_iv(self):
        """Tạo IV ngẫu nhiên (8 bytes) và hiển thị Base64."""
        random_iv = os.urandom(BLOCK_SIZE)
        self.iv_input.set(base64.b64encode(random_iv).decode('utf-8'))
        messagebox.showinfo("Thành công", f"Đã tạo IV ngẫu nhiên ({BLOCK_SIZE} bytes).")

    def generate_key(self):
        """Tạo Khóa ngẫu nhiên (8 bytes) và hiển thị Base64."""
        random_key = os.urandom(KEY_SIZE)
        self.key_input.set(base64.b64encode(random_key).decode('utf-8'))
        messagebox.showinfo("Thành công", f"Đã tạo khóa DES ({KEY_SIZE*8} bit) ngẫu nhiên.")
        
    def safe_decode(self, data_str: str, expected_len: int, source: str) -> Optional[bytes]:
        """Giải mã chuỗi Base64 hoặc Hex thành bytes và kiểm tra độ dài."""
        if not data_str: return None
        data_bytes = None
        
        try:
            data_bytes = base64.b64decode(data_str)
            input_type = "Base64"
        except:
            try:
                data_bytes = bytes.fromhex(data_str)
                input_type = "Hex"
            except:
                messagebox.showerror("Lỗi Định dạng", f"Dữ liệu {source} không hợp lệ (không phải Hex hoặc Base64).")
                return None
        
        if len(data_bytes) != expected_len:
            messagebox.showerror("Lỗi Độ dài", f"Dữ liệu {source} phải dài {expected_len} bytes. Hiện tại: {len(data_bytes)} bytes.")
            return None
            
        return data_bytes

    # --- Main Handlers ---

    def handle_encrypt(self):
        try:
            plaintext_str = self.plaintext_text.get("1.0", END).strip()
            key_str = self.key_input.get().strip()
            iv_str = self.iv_input.get().strip()
            mode = self.mode.get()

            if not plaintext_str or not key_str:
                messagebox.showerror("Lỗi", "Plaintext và Key không được để trống.")
                return

            plaintext = plaintext_str.encode('utf-8')
            key = self.safe_decode(key_str, KEY_SIZE, "Key")
            if key is None: return
            
            iv = None
            if mode != 'ECB':
                if iv_str:
                    iv = self.safe_decode(iv_str, BLOCK_SIZE, "IV")
                    if iv is None: return
            
            # GỌI HÀM ENCRYPT TỪ DES_crypto.py
            result = des_encrypt(plaintext, key, mode, iv, output='base64')
            
            if mode == 'ECB' or iv_str:
                ciphertext_b64 = result
                final_iv = None
            else: # CBC và IV được tạo ngẫu nhiên
                ciphertext_b64, final_iv = result
            
            self.ciphertext_text.delete("1.0", END)
            self.ciphertext_text.insert(END, ciphertext_b64)
            
            if final_iv:
                self.iv_input.set(base64.b64encode(final_iv).decode('utf-8'))

            messagebox.showinfo("Thành công", f"Mã hóa DES ({mode}) hoàn tất.")

        except ValueError as e:
            messagebox.showerror("Lỗi Tham số", str(e))
        except Exception as e:
            messagebox.showerror("Lỗi Mã hóa", f"Đã xảy ra lỗi trong quá trình mã hóa: {e}")

    def handle_decrypt(self):
        try:
            
            ciphertext_b64 = self.ciphertext_text.get("1.0", "end-1c").strip()
            key_str = self.key_input.get().strip()
            iv_str = self.iv_input.get().strip()
            mode = self.mode.get()

            if not ciphertext_b64 or not key_str:
                messagebox.showerror("Lỗi", "Ciphertext và Key không được để trống.")
                return
            
            key = self.safe_decode(key_str, KEY_SIZE, "Key")
            if key is None: return

            iv = None
            if mode != 'ECB':
                iv = self.safe_decode(iv_str, BLOCK_SIZE, "IV")
                if iv is None: return
            
            # GỌI HÀM DECRYPT TỪ DES_crypto.py
            decrypted_data = des_decrypt(ciphertext_b64, key, mode, iv, input='base64')
            
            self.plaintext_text.delete("1.0", END)
            self.plaintext_text.insert(END, decrypted_data.decode('utf-8', errors='ignore'))

            messagebox.showinfo("Thành công", f"Giải mã DES ({mode}) hoàn tất.")

        except ValueError as e:
            messagebox.showerror("Lỗi Giải mã", f"Giải mã thất bại (Sai Key/IV/Padding): {e}")
        except Exception as e:
            messagebox.showerror("Lỗi Giải mã", f"Đã xảy ra lỗi trong quá trình giải mã: {e}")


if __name__ == '__main__':
    root = Tk()
    style = ttk.Style()
    # Tùy chỉnh theme cho giao diện đẹp hơn
    style.theme_use('vista') 
    style.configure('Accent.TButton', font=('Arial', 10, 'bold'), foreground='black')
    
    app = DES_GUI_App(root)
    root.mainloop()