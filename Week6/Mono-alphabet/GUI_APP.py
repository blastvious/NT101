################################################################
# MSSV 23521717
# Nguyen Anh Tuan
# GUI_APP.py (Mono-alphabetic Cracker GUI)
################################################################

from tkinter import *
from tkinter import ttk, messagebox, filedialog
import threading
import time
import string

# ===== IMPORT CORE LOGIC =====
try:
    from Mono_alphabetic import (
        get_cipher_only,
        crack_with_restarts,
        apply_mapping
    )
except ImportError:
    messagebox.showerror(
        "Lỗi",
        "Không tìm thấy file Mono_alphabetic.py.\nHãy để GUI_APP.py cùng thư mục."
    )
    raise


class MonoAlphabetic_Cracker_GUI:
    def __init__(self, master):
        self.master = master
        master.title("Mono-alphabetic Cipher Cracker (SA + Hill Climbing)")
        master.geometry("900x750")
        master.config(padx=20, pady=20)

        # ===== VARIABLES =====
        self.input_file_path = StringVar(value="Chưa chọn file")
        self.raw_ciphertext = ""
        self.ciphertext_alpha = ""

        self.setup_ui()

    # ================= UI =================

    def setup_ui(self):
        # ---------- INPUT ----------
        file_frame = ttk.LabelFrame(self.master, text="Đầu vào", padding=10)
        file_frame.pack(fill="x", pady=10)

        ttk.Label(file_frame, text="Ciphertext file:").grid(row=0, column=0, sticky="w")
        ttk.Entry(
            file_frame,
            textvariable=self.input_file_path,
            state="readonly",
            width=60
        ).grid(row=0, column=1, padx=5, sticky="ew")

        ttk.Button(
            file_frame,
            text="Chọn file",
            command=self.select_input_file
        ).grid(row=0, column=2, padx=5)

        file_frame.columnconfigure(1, weight=1)

        # ---------- TEXT AREA ----------
        text_frame = ttk.Frame(self.master)
        text_frame.pack(fill="both", expand=True, pady=10)

        ttk.Label(text_frame, text="Ciphertext (chỉ chữ cái):").grid(row=0, column=0, sticky="w")
        ttk.Label(text_frame, text="Plaintext phục hồi:").grid(row=0, column=1, sticky="w")

        self.ciphertext_text = Text(text_frame, height=18, wrap=WORD, state=DISABLED)
        self.plaintext_text = Text(text_frame, height=18, wrap=WORD)

        self.ciphertext_text.grid(row=1, column=0, padx=5, pady=5, sticky="nsew")
        self.plaintext_text.grid(row=1, column=1, padx=5, pady=5, sticky="nsew")

        text_frame.columnconfigure(0, weight=1)
        text_frame.columnconfigure(1, weight=1)
        text_frame.rowconfigure(1, weight=1)

        # ---------- RESULT ----------
        result_frame = ttk.LabelFrame(self.master, text="Kết quả", padding=10)
        result_frame.pack(fill="x", pady=10)

        ttk.Label(result_frame, text="Log-likelihood score:").grid(row=0, column=0, sticky="w")
        self.score_label = ttk.Label(result_frame, text="N/A", font=("Arial", 10, "bold"))
        self.score_label.grid(row=0, column=1, sticky="w")

        ttk.Label(result_frame, text="Key mapping (C → P):").grid(row=1, column=0, sticky="nw")
        self.mapping_label = ttk.Label(result_frame, text="N/A", wraplength=720, justify=LEFT)
        self.mapping_label.grid(row=1, column=1, sticky="w")

        result_frame.columnconfigure(1, weight=1)

        # ---------- BUTTON ----------
        self.crack_button = ttk.Button(
            self.master,
            text="THỰC HIỆN PHÁ MÃ (SA + HILL CLIMBING)",
            command=self.handle_crack
        )
        self.crack_button.pack(fill="x", pady=10)

    # ================= LOGIC =================

    def select_input_file(self):
        file_path = filedialog.askopenfilename(
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )

        if not file_path:
            return

        self.input_file_path.set(file_path)

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                self.raw_ciphertext = f.read().upper()

            self.ciphertext_alpha = get_cipher_only(self.raw_ciphertext)

            self.ciphertext_text.config(state=NORMAL)
            self.ciphertext_text.delete("1.0", END)
            self.ciphertext_text.insert(END, self.ciphertext_alpha)
            self.ciphertext_text.config(state=DISABLED)

            self.plaintext_text.delete("1.0", END)
            self.score_label.config(text="N/A")
            self.mapping_label.config(text="N/A")

            messagebox.showinfo(
                "OK",
                f"Đã tải file.\nĐộ dài (chỉ chữ cái): {len(self.ciphertext_alpha)}"
            )

        except Exception as e:
            messagebox.showerror("Lỗi", str(e))

    def handle_crack(self):
        if not self.ciphertext_alpha:
            messagebox.showerror("Lỗi", "Chưa có ciphertext hợp lệ.")
            return

        self.crack_button.config(state=DISABLED)
        self.score_label.config(text="Đang chạy...")
        self.mapping_label.config(text="")

        threading.Thread(
            target=self.run_cracker,
            daemon=True
        ).start()

    def run_cracker(self):
        try:
            start = time.time()

            best_mapping, best_score = crack_with_restarts(
                self.ciphertext_alpha,
                restarts=6
            )

            plaintext = apply_mapping(self.raw_ciphertext, best_mapping)
            elapsed = time.time() - start

            self.master.after(
                0,
                self.update_result,
                best_mapping,
                best_score,
                plaintext,
                elapsed
            )

        except Exception as e:
            self.master.after(
                0,
                messagebox.showerror,
                "Lỗi",
                str(e)
            )

    def update_result(self, mapping, score, plaintext, elapsed):
        self.plaintext_text.delete("1.0", END)
        self.plaintext_text.insert(END, plaintext)

        self.score_label.config(
            text=f"{score:.4f}  |  {elapsed:.2f} giây"
        )

        mapping_str = ", ".join(
            f"{c}->{mapping[c]}" for c in sorted(mapping)
        )
        self.mapping_label.config(text=mapping_str)

        self.write_output(score, mapping, plaintext)
        self.crack_button.config(state=NORMAL)

        messagebox.showinfo("Hoàn thành", "Phá mã thành công!")

    def write_output(self, score, mapping, plaintext):
        try:
            with open("plaintext_recovered.txt", "w", encoding="utf-8") as f:
                f.write(f"Log-Likelihood Score: {score:.4f}\n")
                f.write(
                    "Mapping (Cipher->Plain): " +
                    ", ".join(f"{c}->{mapping[c]}" for c in sorted(mapping)) +
                    "\n\n--- PLAINTEXT ---\n"
                )
                f.write(plaintext)
        except IOError:
            messagebox.showerror("Lỗi", "Không ghi được file output.")


# ================= RUN =================

if __name__ == "__main__":
    root = Tk()
    style = ttk.Style()
    style.theme_use("vista")
    app = MonoAlphabetic_Cracker_GUI(root)
    root.mainloop()
