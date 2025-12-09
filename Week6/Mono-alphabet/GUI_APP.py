################################################################
# MSSV 23521717
# Nguyen Anh Tuan
# GUI_APP.py (Dành cho Mono-alphabetic Cracker)
################################################################

from tkinter import *
from tkinter import ttk, messagebox, filedialog
import os
import time
import string


try:
    # Import các hàm chính từ module logic Mono-alphabetic
    from Mono_alphabetic import get_cipher_only, simulated_annealing_cracker, apply_mapping, main_program 
    
except ImportError:
    messagebox.showerror("Lỗi Module", "Không tìm thấy file Mono-alphabetic.py. Vui lòng đảm bảo đã tạo file này.")
    # Tạo hàm giả để chương trình có thể chạy GUI
    def get_cipher_only(text): return "".join(filter(str.isalpha, text))
    def simulated_annealing_cracker(*args): return ({c:c for c in string.ascii_uppercase}, 0.0)
    def apply_mapping(text, mapping): return text
    def main_program(*args): pass

class MonoAlphabetic_Cracker_GUI:
    def __init__(self, master):
        self.master = master
        master.title("Phá Mã Hoán Vị Đơn Ký Tự (Simulated Annealing) - 23521717")
        master.geometry('900x750')
        master.config(padx=20, pady=20)
        
        # --- Variables ---
        self.input_file_path = StringVar(value="Chưa chọn file")
        self.ciphertext_alpha = "" # Chỉ chứa chữ cái
        self.raw_ciphertext = ""   # Chứa toàn bộ ký tự gốc
        
        # --- Setup Main Layout ---
        self.setup_ui_layout()
        
    def setup_ui_layout(self):
        # Frame 1: Input Control (File Selection)
        file_frame = ttk.LabelFrame(self.master, text="Đầu vào", padding="10")
        file_frame.pack(fill="x", pady=10)

        ttk.Label(file_frame, text="File Ciphertext:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        ttk.Entry(file_frame, textvariable=self.input_file_path, state='readonly', width=60).grid(row=0, column=1, padx=5, pady=5, sticky="ew")
        ttk.Button(file_frame, text="Chọn File", command=self.select_input_file).grid(row=0, column=2, padx=5, pady=5)
        
        file_frame.columnconfigure(1, weight=1)

        # Frame 2: Text Areas (Ciphertext & Plaintext)
        text_frame = ttk.Frame(self.master)
        text_frame.pack(fill="both", expand=True, pady=10)

        # Ciphertext Area
        ttk.Label(text_frame, text="Ciphertext (Đã làm sạch, chỉ chữ cái):").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.ciphertext_text = Text(text_frame, height=15, width=40, state=DISABLED, wrap=WORD)
        self.ciphertext_text.grid(row=1, column=0, padx=5, pady=5, sticky="nsew")

        # Plaintext Area
        ttk.Label(text_frame, text="Plaintext Phục Hồi:").grid(row=0, column=1, padx=5, pady=5, sticky="w")
        self.plaintext_text = Text(text_frame, height=15, width=40, wrap=WORD)
        self.plaintext_text.grid(row=1, column=1, padx=5, pady=5, sticky="nsew")
        
        text_frame.columnconfigure(0, weight=1)
        text_frame.columnconfigure(1, weight=1)
        text_frame.rowconfigure(1, weight=1)

        # Frame 3: Key and Score Output
        result_frame = ttk.LabelFrame(self.master, text="Kết Quả Phân Tích", padding="10")
        result_frame.pack(fill="x", pady=10)
        
        ttk.Label(result_frame, text="Điểm Log-Likelihood Cuối cùng:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.score_label = ttk.Label(result_frame, text="N/A", font=('Arial', 10, 'bold'))
        self.score_label.grid(row=0, column=1, padx=5, pady=5, sticky="w")

        ttk.Label(result_frame, text="Key Mapping (C->P):").grid(row=1, column=0, padx=5, pady=5, sticky="w")
        self.mapping_label = ttk.Label(result_frame, text="N/A", wraplength=700, justify=LEFT)
        self.mapping_label.grid(row=1, column=1, padx=5, pady=5, sticky="w")
        
        result_frame.columnconfigure(1, weight=1)

        # Frame 4: Action Button
        button_frame = ttk.Frame(self.master)
        button_frame.pack(fill="x", pady=10)
        
        self.crack_button = ttk.Button(button_frame, text="THỰC THI PHÁ MÃ (SIMULATED ANNEALING)", command=self.handle_crack, style='Accent.TButton')
        self.crack_button.pack(side=LEFT, padx=10, expand=True, fill="x")

    # --- Utility Functions ---

    def select_input_file(self):
        """Mở hộp thoại chọn file và đọc dữ liệu."""
        file_path = filedialog.askopenfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        
        if file_path:
            self.input_file_path.set(file_path)
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    self.raw_ciphertext = f.read().upper()
                
                # Làm sạch chỉ giữ lại chữ cái
                self.ciphertext_alpha = get_cipher_only(self.raw_ciphertext)
                
                # Hiển thị ciphertext đã làm sạch
                self.ciphertext_text.config(state=NORMAL)
                self.ciphertext_text.delete("1.0", END)
                self.ciphertext_text.insert(END, self.ciphertext_alpha)
                self.ciphertext_text.config(state=DISABLED)
                
                self.plaintext_text.delete("1.0", END)
                self.score_label.config(text="N/A")
                self.mapping_label.config(text="N/A")
                
                messagebox.showinfo("Thông báo", f"Đã tải file thành công. Độ dài (chỉ chữ cái): {len(self.ciphertext_alpha)}.")

            except Exception as e:
                messagebox.showerror("Lỗi Đọc File", f"Không thể đọc file: {e}")
                self.input_file_path.set("Lỗi đọc file")
                self.raw_ciphertext = ""
                self.ciphertext_alpha = ""


    def handle_crack(self):
        """Thực thi thuật toán Simulated Annealing."""
        if not self.ciphertext_alpha:
            messagebox.showerror("Lỗi", "Vui lòng chọn file ciphertext hợp lệ trước khi thực thi.")
            return

        # Vô hiệu hóa nút và chạy trong luồng chính (cho ví dụ đơn giản)
        self.crack_button.config(state=DISABLED)
        self.master.update_idletasks() # Cập nhật giao diện

        try:
            start_time = time.time()
            
            # Khởi tạo và chạy SA (hàm này có thể mất vài giây)
            best_mapping, final_score = simulated_annealing_cracker(
                self.ciphertext_alpha, 
                max_iterations=500000, 
                initial_temp=10.0 
            )
            
            end_time = time.time()
            
            # Giải mã toàn bộ văn bản gốc (giữ nguyên khoảng trắng và ký tự khác)
            final_plaintext = apply_mapping(self.raw_ciphertext, best_mapping)
            
            # --- Hiển thị kết quả ---
            
            # Plaintext
            self.plaintext_text.delete("1.0", END)
            self.plaintext_text.insert(END, final_plaintext)
            
            # Score
            self.score_label.config(text=f"{final_score:.4f} (Thời gian: {end_time - start_time:.2f} giây)")
            
            # Mapping
            mapping_str = ", ".join([f"{c}->{best_mapping[c]}" for c in sorted(best_mapping.keys())])
            self.mapping_label.config(text=mapping_str)

            # Tự động ghi ra file plaintext_recovered.txt (như trong main_program gốc)
            self.write_output_file(final_score, best_mapping, final_plaintext)

            messagebox.showinfo("Hoàn thành", "Phá mã Simulated Annealing đã hoàn tất!")

        except Exception as e:
            messagebox.showerror("Lỗi SA", f"Lỗi trong quá trình phá mã: {e}")
            
        finally:
            self.crack_button.config(state=NORMAL) # Bật lại nút

    def write_output_file(self, score, mapping, plaintext):
        """Ghi kết quả ra file plaintext_recovered.txt."""
        OUTPUT_FILE = "plaintext_recovered.txt"
        try:
            with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
                f.write(f"Log-Likelihood Score: {score:.4f}\n")
                
                mapping_str = ", ".join([f"{c}->{mapping[c]}" for c in sorted(mapping.keys())])
                f.write(f"Mapping (Cipher->Plain): {mapping_str}\n")
                
                f.write("\n--- PLAINTEXT ---\n")
                f.write(plaintext)
            messagebox.showinfo("Xuất File", f"Kết quả đã được ghi vào file: {OUTPUT_FILE}")
        except IOError:
            messagebox.showerror("Lỗi Xuất File", "Không thể ghi vào file output.")
            

if __name__ == '__main__':
    root = Tk()
    style = ttk.Style()
    # Tùy chỉnh theme cho giao diện đẹp hơn
    style.theme_use('vista') 
    style.configure('Accent.TButton', font=('Arial', 10, 'bold'), foreground='black')
    
    app = MonoAlphabetic_Cracker_GUI(root)
    root.mainloop()