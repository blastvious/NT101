################################################################
# MSSV 23521717
# Nguyen Anh Tuan
# GUI_APP.py
# (Giao diện cho Caesar Brute Force)
################################################################

from tkinter import *
from tkinter import ttk, messagebox, filedialog
import os
from typing import Dict

# Import lớp logic từ file đã tạo ở trên
try:
    from Caesar_crypto import CaesarCracker
except ImportError:
    messagebox.showerror("Lỗi Module", "Không tìm thấy file Caesar_Crypto.py. Vui lòng đảm bảo đã tạo file này.")
    # Tạo lớp giả để chương trình có thể chạy GUI
    class CaesarCracker:
        def __init__(self, input_file_path: str = ""): pass
        def get_cipher_text_from_file(self, file_path: str) -> bool: return False
        def set_result(self): pass
        def get_results(self) -> Dict[int, str]: return {}
        def get_cipher_text(self) -> str: return "LỖI: THIẾU CAESAR_CRYPTO.PY"
        def write_plaintext_to_file(self, key: int, output_file_path: str): return False


class CaesarCrackerGUI:
    def __init__(self, master):
        self.master = master
        master.title("Caesar Cipher Brute Force - 23521717")
        master.geometry('1000x800')
        master.config(padx=20, pady=20)
        
        # --- Variables ---
        self.input_file_path = StringVar(value="Chưa chọn file")
        self.key_to_save = IntVar(value=-1)
        self.cracker: CaesarCracker = CaesarCracker(input_file_path="") # Khởi tạo rỗng
        
        # --- Setup Main Layout ---
        self.setup_ui_layout()
        
    def setup_ui_layout(self):
        
        # --- Khung 1: Chọn File & Xem Ciphertext ---
        file_frame = ttk.LabelFrame(self.master, text="1. Đầu vào Ciphertext", padding="10")
        file_frame.pack(fill="x", pady=10)

        ttk.Label(file_frame, text="Đường dẫn File:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        ttk.Entry(file_frame, textvariable=self.input_file_path, state='readonly', width=70).grid(row=0, column=1, padx=5, pady=5, sticky="ew")
        ttk.Button(file_frame, text="Chọn File", command=self.select_input_file).grid(row=0, column=2, padx=5, pady=5)
        
        ttk.Label(file_frame, text="Nội dung Ciphertext:").grid(row=1, column=0, padx=5, pady=5, sticky="w")
        self.ciphertext_text = Text(file_frame, height=5, width=80, wrap=WORD, state=DISABLED)
        self.ciphertext_text.grid(row=2, column=0, columnspan=3, padx=5, pady=5, sticky="nsew")
        
        file_frame.columnconfigure(1, weight=1)
        file_frame.rowconfigure(2, weight=1)
        
        # --- Khung 2: Thực thi Brute Force ---
        crack_frame = ttk.LabelFrame(self.master, text="2. Thực thi & Kết quả Vét cạn (26 Khóa)", padding="10")
        crack_frame.pack(fill="both", expand=True, pady=10)
        
        self.crack_button = ttk.Button(crack_frame, text="THỰC HIỆN BRUTE FORCE (Key 0-25)", command=self.handle_brute_force, style='Accent.TButton')
        self.crack_button.pack(fill="x", padx=5, pady=5)
        
        ttk.Label(crack_frame, text="Kết quả (Key: Plaintext - 50 ký tự đầu):").pack(padx=5, pady=5, anchor="w")
        
        self.result_listbox = Listbox(crack_frame, height=15, width=100)
        self.result_listbox.pack(fill="both", expand=True, padx=5, pady=5)
        self.result_listbox.bind('<<ListboxSelect>>', self.show_selected_plaintext)
        
        
        # --- Khung 3: Lựa chọn và Lưu kết quả ---
        save_frame = ttk.LabelFrame(self.master, text="3. Lưu Plaintext Chính xác", padding="10")
        save_frame.pack(fill="x", pady=10)
        
        ttk.Label(save_frame, text="Chọn Key (0-25) để Lưu:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        
        # Dropdown/Combobox cho Key
        self.key_combo = ttk.Combobox(save_frame, textvariable=self.key_to_save, state='readonly', width=5)
        self.key_combo.grid(row=0, column=1, padx=5, pady=5, sticky="w")
        
        ttk.Button(save_frame, text="LƯU PLAINTEXT VÀO result.txt", command=self.handle_save_plaintext).grid(row=0, column=2, padx=10, pady=5)
        
        # Vùng xem trước Plaintext
        ttk.Label(save_frame, text="Xem trước Plaintext đã chọn:").grid(row=1, column=0, padx=5, pady=5, sticky="w")
        self.preview_text = Text(save_frame, height=3, width=80, wrap=WORD, state=DISABLED)
        self.preview_text.grid(row=2, column=0, columnspan=3, padx=5, pady=5, sticky="ew")
        
        save_frame.columnconfigure(2, weight=1)

    # --- Utility Functions ---

    def select_input_file(self):
        """Mở hộp thoại chọn file và đọc dữ liệu."""
        file_path = filedialog.askopenfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
            initialfile="ciphertext.txt"
        )
        
        if file_path:
            self.cracker = CaesarCracker(input_file_path=file_path)
            success = self.cracker.get_cipher_text_from_file(file_path)
            
            if success:
                self.input_file_path.set(file_path)
                
                # Hiển thị Ciphertext
                self.ciphertext_text.config(state=NORMAL)
                self.ciphertext_text.delete("1.0", END)
                self.ciphertext_text.insert(END, self.cracker.get_cipher_text())
                self.ciphertext_text.config(state=DISABLED)
                
                # Reset kết quả cũ
                self.result_listbox.delete(0, END)
                self.key_combo['values'] = []
                self.key_to_save.set(-1)
                self.preview_text.config(state=NORMAL)
                self.preview_text.delete("1.0", END)
                self.preview_text.config(state=DISABLED)

                messagebox.showinfo("Thông báo", "Đã tải file thành công.")
            else:
                messagebox.showerror("Lỗi", "Không thể đọc file hoặc file không tồn tại.")
                self.input_file_path.set("Lỗi đọc file")

    def handle_brute_force(self):
        """Thực thi Brute Force và hiển thị kết quả."""
        if not self.cracker.get_cipher_text():
            messagebox.showerror("Lỗi", "Vui lòng chọn file ciphertext hợp lệ trước khi phá mã.")
            return

        self.cracker.set_result()
        results = self.cracker.get_results()
        
        self.result_listbox.delete(0, END)
        keys = []

        for k in sorted(results.keys()):
            plaintext = results[k]
            display_text = f"Key {k:02d}: {plaintext[:80]}..."
            self.result_listbox.insert(END, display_text)
            keys.append(k)

        # Cập nhật Combobox
        self.key_combo['values'] = keys
        if keys:
            self.key_to_save.set(keys[0]) # Chọn mặc định key 0

        messagebox.showinfo("Hoàn thành", "Vét cạn hoàn tất! Vui lòng kiểm tra danh sách kết quả để tìm Key đúng.")

    def show_selected_plaintext(self, event):
        """Hiển thị toàn bộ plaintext của key được chọn trong listbox."""
        selected_indices = self.result_listbox.curselection()
        if not selected_indices:
            return

        # Key tương ứng với index trong listbox
        key = selected_indices[0] 
        
        # Cập nhật Combobox
        self.key_to_save.set(key)
        
        # Hiển thị Plaintext đầy đủ
        plaintext = self.cracker.get_results().get(key, "Không tìm thấy Plaintext.")
        self.preview_text.config(state=NORMAL)
        self.preview_text.delete("1.0", END)
        self.preview_text.insert(END, plaintext)
        self.preview_text.config(state=DISABLED)


    def handle_save_plaintext(self):
        """Lưu plaintext của key đã chọn vào result.txt."""
        key = self.key_to_save.get()
        if key < 0 or key not in self.cracker.get_results():
            messagebox.showerror("Lỗi Lưu", "Vui lòng chạy Brute Force và chọn một Key hợp lệ (0-25).")
            return
        
        success = self.cracker.write_plaintext_to_file(key, "result.txt")
        if success:
            messagebox.showinfo("Thành công", f"Đã lưu plaintext cho Key {key} vào file result.txt.")
        else:
            messagebox.showerror("Lỗi", "Không thể ghi file result.txt.")


if __name__ == '__main__':
    root = Tk()
    style = ttk.Style()
    style.theme_use('vista') 
    style.configure('Accent.TButton', font=('Arial', 10, 'bold'), foreground='black')
    
    app = CaesarCrackerGUI(root)
    root.mainloop()