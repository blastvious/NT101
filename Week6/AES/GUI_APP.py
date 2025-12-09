##################
# MSSV 23521717
# Nguyen Anh Tuan
# GUI_APP.py 
# repo: https://github.com/blastvious/NT101
##################

from tkinter import *
from tkinter import ttk, messagebox
import os
import base64
from typing import Optional

try:
    from AES_crypto import encrypt, decrypt, check_key_length, BLOCK_SIZE
except ImportError:
    messagebox.showerror("Lỗi Module", "Không tìm thấy file AES-crypto.py. Vui lòng đảm bảo đã tạo file này và chứa logic AES.")
    def encrypt(p, k, m, iv=None): raise NotImplementedError("Lỗi: Không tìm thấy logic AES.")
    def decrypt(c, k, m, iv): raise NotImplementedError("Lỗi: Không tìm thấy logic AES.")
    def check_key_length(k): pass
    BLOCK_SIZE = 16


class AES_GUI_App:
    def __init__(self, master):
        self.master = master
        master.title("Mã Hóa & Giải Mã AES (ECB/CBC) - 23521717")
        master.geometry('850x700')
        master.config(padx=20, pady=20)
        
        # --- Variables ---
        self.mode = StringVar(value="CBC")
        self.key_input = StringVar()
        self.iv_input = StringVar()
        self.key_length = StringVar(value="16") 

        # --- Setup Main Layout ---
        self.setup_ui_layout()

    def setup_ui_layout(self):
        input_frame = ttk.LabelFrame(self.master, text="Tham Số Mã Hóa", padding="10")
        input_frame.pack(fill="x", pady=10)

        ttk.Label(input_frame, text="Độ dài Khóa (bytes):").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        key_len_options = ['16', '24', '32'] # Tương ứng 128, 192, 256 bit
        self.key_len_combo = ttk.Combobox(input_frame, textvariable=self.key_length, values=key_len_options, state="readonly", width=5)
        self.key_len_combo.grid(row=0, column=1, padx=5, pady=5, sticky="w")
        
        ttk.Label(input_frame, text="Khóa (Base64/Hex):").grid(row=1, column=0, padx=5, pady=5, sticky="w")
        self.key_entry = ttk.Entry(input_frame, textvariable=self.key_input, width=40)
        self.key_entry.grid(row=1, column=1, columnspan=2, padx=5, pady=5, sticky="ew")
        
        ttk.Button(input_frame, text="Tạo Khóa ngẫu nhiên", command=self.generate_key).grid(row=1, column=3, padx=5, pady=5)
        
        ttk.Label(input_frame, text="Chế độ hoạt động:").grid(row=2, column=0, padx=5, pady=5, sticky="w")
        mode_options = ['CBC', 'ECB']
        self.mode_combo = ttk.Combobox(input_frame, textvariable=self.mode, values=mode_options, state="readonly", width=10)
        self.mode_combo.grid(row=2, column=1, padx=5, pady=5, sticky="w")
        self.mode_combo.bind("<<ComboboxSelected>>", self.on_mode_change)

        ttk.Label(input_frame, text="IV (Base64/Hex):").grid(row=3, column=0, padx=5, pady=5, sticky="w")
        self.iv_entry = ttk.Entry(input_frame, textvariable=self.iv_input, width=40)
        self.iv_entry.grid(row=3, column=1, columnspan=2, padx=5, pady=5, sticky="ew")
        self.iv_entry.config(state=NORMAL)
        ttk.Button(input_frame, text="Tạo IV ngẫu nhiên", command=self.generate_iv).grid(row=3, column=3, padx=5, pady=5)
        
        input_frame.columnconfigure(1, weight=1)

        text_frame = ttk.Frame(self.master)
        text_frame.pack(fill="both", expand=True, pady=10)

        ttk.Label(text_frame, text="Plaintext (Đầu vào):").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.plaintext_text = Text(text_frame, height=10, width=40)
        self.plaintext_text.grid(row=1, column=0, padx=5, pady=5, sticky="nsew")

        ttk.Label(text_frame, text="Ciphertext (Base64):").grid(row=0, column=1, padx=5, pady=5, sticky="w")
        self.ciphertext_text = Text(text_frame, height=10, width=40)
        self.ciphertext_text.grid(row=1, column=1, padx=5, pady=5, sticky="nsew")
        
        text_frame.columnconfigure(0, weight=1)
        text_frame.columnconfigure(1, weight=1)
        text_frame.rowconfigure(1, weight=1)

        button_frame = ttk.Frame(self.master)
        button_frame.pack(fill="x", pady=10)
        
        ttk.Button(button_frame, text="MÃ HÓA (Encrypt)", command=self.handle_encrypt, style='Accent.TButton',).pack(side=LEFT, padx=10, expand=True, fill="x")
        ttk.Button(button_frame, text="GIẢI MÃ (Decrypt)", command=self.handle_decrypt, style='Accent.TButton').pack(side=LEFT, padx=10, expand=True, fill="x")

    # --- Utility Functions ---

    def on_mode_change(self, event):
        if self.mode.get() == 'ECB':
            self.iv_entry.config(state=DISABLED)
            self.iv_input.set("")
        else:
            self.iv_entry.config(state=NORMAL)

    def generate_iv(self):
        """Tạo IV ngẫu nhiên (16 bytes) và hiển thị Base64."""
        random_iv = os.urandom(BLOCK_SIZE)
        self.iv_input.set(base64.b64encode(random_iv).decode('utf-8'))

    def generate_key(self):
        """Tạo Khóa ngẫu nhiên theo độ dài đã chọn và hiển thị Base64."""
        try:
            key_len = int(self.key_length.get())
            if key_len not in [16, 24, 32]:
                 messagebox.showerror("Lỗi Độ dài", "Độ dài khóa phải là 16, 24, hoặc 32 bytes.")
                 return
            
            random_key = os.urandom(key_len)
            self.key_input.set(base64.b64encode(random_key).decode('utf-8'))
            messagebox.showinfo("Thành công", f"Đã tạo khóa AES-{key_len*8} bit ngẫu nhiên.")
        except Exception as e:
            messagebox.showerror("Lỗi", f"Không thể tạo khóa: {e}")
            
    def safe_decode(self, data_str: str, source: str) -> Optional[bytes]:
        """Giải mã chuỗi Base64 hoặc Hex thành bytes."""
        if not data_str: return None
        try: return base64.b64decode(data_str)
        except:
            try: return bytes.fromhex(data_str)
            except:
                messagebox.showerror("Lỗi Định dạng", f"Dữ liệu {source} không hợp lệ (không phải Hex hoặc Base64).")
                return None

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
            key = self.safe_decode(key_str, "Key")
            if key is None: return
            
            # Kiểm tra độ dài khóa theo logic từ AES-crypto.py
            check_key_length(key) 
            
            iv = self.safe_decode(iv_str, "IV")
            if iv_str and iv is None: return
            
            # GỌI HÀM ENCRYPT TỪ AES-crypto.py
            ciphertext_b64, final_iv = encrypt(plaintext, key, mode, iv)
            
            self.ciphertext_text.delete("1.0", END)
            self.ciphertext_text.insert(END, ciphertext_b64)
            
            if final_iv:
                self.iv_input.set(base64.b64encode(final_iv).decode('utf-8'))

            messagebox.showinfo("Thành công", f"Mã hóa AES-{len(key)*8} bit ({mode}) hoàn tất.")

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
            
            key = self.safe_decode(key_str, "Key")
            iv = self.safe_decode(iv_str, "IV")

            if key is None: return
            check_key_length(key)

            if mode == 'CBC' and iv is None:
                messagebox.showerror("Lỗi IV", "Chế độ CBC bắt buộc phải có IV khi giải mã.")
                return
            
            # GỌI HÀM DECRYPT TỪ AES-crypto.py
            decrypted_data = decrypt(ciphertext_b64, key, mode, iv)
            
            self.plaintext_text.delete("1.0", END)
            self.plaintext_text.insert(END, decrypted_data.decode('utf-8', errors='ignore'))

            messagebox.showinfo("Thành công", f"Giải mã AES-{len(key)*8} bit ({mode}) hoàn tất.")

        except ValueError as e:
            messagebox.showerror("Lỗi Giải mã", f"Giải mã thất bại (Sai Key/IV/Padding): {e}")
        except Exception as e:
            messagebox.showerror("Lỗi Giải mã", f"Đã xảy ra lỗi trong quá trình giải mã: {e}")


if __name__ == '__main__':
    root = Tk()
    style = ttk.Style()
    style.theme_use('vista')
    style.configure('Accent.TButton', background='blue', foreground='black')
    
    app = AES_GUI_App(root)
    root.mainloop()