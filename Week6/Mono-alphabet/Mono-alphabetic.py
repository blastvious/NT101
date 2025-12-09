import random
import math
import time
import string
import re



ALPHABET = string.ascii_uppercase
ALPHABET_SIZE = 26

COMMON_WORDS = {
    "the", "of", "and", "to", "in", "a", "is", "that", "for", "it", 
    "as", "was", "with", "be", "by", "on", "not", "he", "i", "this", 
    "are", "or", "his", "from", "at", "which", "but", "have", "an", 
    "had", "they", "you", "were", "their", "one", "all", "we", "can", 
    "her", "has", "there", "been", "if", "more", "when", "will", 
    "would", "who", "so", "no"
}


BIGRAM_DATA_RAW = """
TH 3.56 HE 3.07 IN 2.43 ER 2.05 AN 1.99 RE 1.85 ON 1.76 AT 1.49 EN 1.45 ND 1.35 TI 1.34 ES 1.34 OR 1.28 TE 1.20 OF 1.17 ED 1.17 IS 1.13 IT 1.12 AL 1.09 AR 1.07 ST 1.05 TO 1.04 NT 1.04 NG 0.95 SE 0.93 HA 0.93 AS 0.87 OU 0.87 IO 0.83 LE 0.83 VE 0.83 CO 0.79 ME 0.79 DE 0.76 HI 0.76 RI 0.73 RO 0.73 IC 0.70 NE 0.69 EA 0.69 RA 0.69 CE 0.65 LI 0.62 CH 0.60 LL 0.58 BE 0.58 MA 0.57 SI 0.55 OM 0.55 UR 0.54
"""


TRIGRAM_DATA_LIST = [
    "THE", "AND", "ING", "ION", "TIO", "ENT", "ATI", "FOR", "HER", "TER", 
    "HAT", "THA", "ERE", "ATE", "HIS", "CON", "RES", "VER", "ALL", "ONS",
    "NCE", "MEN", "ITH", "TED", "ERS", "PRO", "THI", "WIT", "ARE", "ESS",
    "NOT", "IVE", "WAS", "ECT", "REA", "COM", "EVE", "PER", "INT", "EST",
    "STA", "CTI", "ICA", "IST", "EAR", "AIN", "ONE", "OUR", "ITI", "RAT"
]

#Normalize data 2gram
ENGLISH_2GRAM_LOGPROB = {}
pairs = re.findall(r'([A-Z]{2})\s([\d\.]+)[\sB\(%]*', BIGRAM_DATA_RAW.strip())
for pair, prob_str in pairs:
    prob = float(prob_str) / 100 
    ENGLISH_2GRAM_LOGPROB[pair] = math.log(prob)

#Normalize data 2gram
ENGLISH_3GRAM_LOGPROB = {}
high_prob_3gram = 0.005 # Xác suất cao cho 3-gram phổ biến (0.5%)
low_prob_3gram = 0.0001 # Xác suất thấp cho 3-gram hiếm (0.01%)

for tri in TRIGRAM_DATA_LIST:
    ENGLISH_3GRAM_LOGPROB[tri] = math.log(high_prob_3gram)

# Log-Likelihood mặc định cho các N-gram không có trong danh sách
default_log_prob = math.log(low_prob_3gram) 


# --- ANALYZE SUPPORT FUNTION ---

def preprocess_cipher(file_path):
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            text = f.read().upper()
    except FileNotFoundError:
        print(f"Lỗi: Không tìm thấy file {file_path}")
        return ""
    cleaned_text = ''.join(filter(str.isalpha, text))
    return cleaned_text

def get_cipher_only(text):
    return ''.join(filter(str.isalpha, text))

def apply_mapping(text, mapping):
    plaintext = ""
    for char in text:
        if 'A' <= char <= 'Z':
            plaintext += mapping.get(char, char) 
        else:
            plaintext += char
    return plaintext

def initialize_random_mapping():
    cipher_chars = list(ALPHABET)
    plain_chars = list(ALPHABET)
    random.shuffle(plain_chars)
    mapping = {c: p for c, p in zip(cipher_chars, plain_chars)}
    return mapping

def generate_neighbor_mapping(mapping):
    new_mapping = mapping.copy()
    char1, char2 = random.sample(ALPHABET, 2)
    new_mapping[char1], new_mapping[char2] = new_mapping[char2], new_mapping[char1]
    return new_mapping

def calculate_fitness(plaintext_alpha):

    score = 0
    N = len(plaintext_alpha)
    if N < 3: return -float('inf')

    W_2GRAM = 0.4
    W_3GRAM = 0.6
    
    #  2-gram Score
    score_2gram = 0
    for i in range(N - 1):
        bigram = plaintext_alpha[i:i+2]
        log_prob = ENGLISH_2GRAM_LOGPROB.get(bigram, default_log_prob)
        score_2gram += log_prob
    
    # 3-gram Score
    score_3gram = 0
    for i in range(N - 2):
        trigram = plaintext_alpha[i:i+3]
        log_prob = ENGLISH_3GRAM_LOGPROB.get(trigram, default_log_prob)
        score_3gram += log_prob

    
    total_score = (W_2GRAM * score_2gram) + (W_3GRAM * score_3gram)
    
    return total_score / N 

def validate_plaintext_with_words(plaintext_with_spaces, common_words_set):
    plaintext_alpha = get_cipher_only(plaintext_with_spaces).lower() 
    total_length = len(plaintext_alpha)
    if total_length == 0:
        return 0.0

    match_count = 0
    for word in common_words_set:
        match_count += plaintext_alpha.count(word.lower())

    return match_count / total_length

# ---  ALGORITHM SIMULATED ANNEALING  ---

def simulated_annealing_cracker(ciphertext_alpha, max_iterations=500000, initial_temp=10.0, cooling_rate=0.9999):
    
    current_mapping = initialize_random_mapping()
    current_plaintext = apply_mapping(ciphertext_alpha, current_mapping)
    current_score = calculate_fitness(current_plaintext)
    
    best_mapping = current_mapping
    best_score = current_score
    temp = initial_temp
    
    print(f"\nBắt đầu SA | Điểm Khởi tạo: {best_score:.4f}")
    
    for iteration in range(max_iterations):
        temp *= cooling_rate
        
        neighbor_mapping = generate_neighbor_mapping(current_mapping)
        neighbor_plaintext = apply_mapping(ciphertext_alpha, neighbor_mapping)
        neighbor_score = calculate_fitness(neighbor_plaintext)
        
        delta_score = neighbor_score - current_score
        
        if delta_score > 0:
            current_mapping = neighbor_mapping
            current_score = neighbor_score
            
            if current_score > best_score:
                best_score = current_score
                best_mapping = current_mapping.copy()
        
        elif temp > 0:
            acceptance_prob = math.exp(delta_score / temp)
            if random.random() < acceptance_prob:
                current_mapping = neighbor_mapping
                current_score = neighbor_score
        
        if iteration % 50000 == 0 and iteration > 0:
            print(f"Lặp {iteration} | Nhiệt độ: {temp:.6f} | Điểm Tốt nhất: {best_score:.4f}")

    return best_mapping, best_score

# --- MAIN FUNTION AND EXCUTE ---

def main_program(input_file_path, output_file_path):
    
    print(f"--- BẮT ĐẦU PHÁ MÃ HOÁN VỊ TỆP: {input_file_path} ---")
    
    try:
        with open(input_file_path, 'r', encoding='utf-8') as f:
            raw_ciphertext = f.read().upper()
    except FileNotFoundError:
        print(f"Lỗi: Không tìm thấy file {input_file_path}")
        return
    
    ciphertext_alpha = get_cipher_only(raw_ciphertext)
    
    print(f"-> Độ dài Ciphertext (gốc): {len(raw_ciphertext)} ký tự.")
    print(f"-> Độ dài Ciphertext (chỉ chữ cái): {len(ciphertext_alpha)} ký tự.")
    
    # Simulated Annealing
    start_time = time.time()
    best_mapping, final_score = simulated_annealing_cracker(
        ciphertext_alpha, 
        max_iterations=500000, 
        initial_temp=10.0 
    )
    end_time = time.time()
    
    print(f"\n--- QUÁ TRÌNH HOÀN THÀNH ---")
    print(f"Thời gian chạy: {end_time - start_time:.2f} giây")

    # Giải mã toàn bộ văn bản gốc
    final_plaintext = apply_mapping(raw_ciphertext, best_mapping)
    
    # XÁC NHẬN bằng TỪ PHỔ BIẾN
    validation_ratio = validate_plaintext_with_words(final_plaintext, COMMON_WORDS)
    
    print("\n--- XÁC NHẬN CHẤT LƯỢNG GIẢI MÃ ---")
    print(f"-> Điểm Log-Likelihood Tốt nhất: {final_score:.4f} (Điểm càng gần 0 càng tốt)")
    print(f"-> Tỷ lệ từ phổ biến trong Plaintext (Heuristic): {validation_ratio:.4f}")
    
    if validation_ratio > 0.05 and final_score > -3.0: # Giảm ngưỡng cho 3-gram giả định
        print("-> **XÁC NHẬN MẠNH:** Khóa rất chính xác, Plaintext khả năng cao là đúng.")
    else:
        print("-> **LƯU Ý:** Tỷ lệ từ phổ biến thấp hoặc điểm SA chưa cao. Khuyến nghị kiểm tra thủ công.")
    print("----------------------------------------\n")

    
    try:
        with open(output_file_path, 'w', encoding='utf-8') as f:
            # Dòng 1: Điểm Log-Likelihood cuối cùng
            f.write(f"Log-Likelihood Score: {final_score:.4f}\n")
            
            # Dòng 2: Bản đồ ánh xạ ký tự (Mapping)
            mapping_str = ", ".join([f"{c}->{best_mapping[c]}" for c in sorted(best_mapping.keys())])
            f.write(f"Mapping (Cipher->Plain): {mapping_str}\n")
            
            # Dòng tiếp theo: Plaintext
            f.write("\n--- PLAINTEXT ---\n")
            f.write(final_plaintext)
            
        print(f"Kết quả đã ghi vào file: {output_file_path}")
    except IOError:
        print("Lỗi: Không thể ghi vào file output.")
    

INPUT_FILE = "ciphertext.txt"
OUTPUT_FILE = "plaintext_recovered.txt"

if __name__ == "__main__":
    main_program(INPUT_FILE, OUTPUT_FILE)