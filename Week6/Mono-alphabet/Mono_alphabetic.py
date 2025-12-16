################################################################
# MSSV 23521717
# Nguyen Anh Tuan
# Mono-alphabetic.py
################################################################


import random
import math
import time
import string
import re

from collections import Counter

ALPHABET = string.ascii_uppercase
ALPHABET_SIZE = 26

ENGLISH_LETTER_FREQ = {
    'E': 12.7, 'T': 9.1, 'A': 8.2, 'O': 7.5, 'I': 7.0, 'N': 6.7,
    'S': 6.3, 'H': 6.1, 'R': 6.0, 'D': 4.3, 'L': 4.0,
    'C': 2.8, 'U': 2.8, 'M': 2.4, 'W': 2.4, 'F': 2.2,
    'G': 2.0, 'Y': 2.0, 'P': 1.9, 'B': 1.5, 'V': 1.0,
    'K': 0.8, 'X': 0.2, 'J': 0.15, 'Q': 0.1, 'Z': 0.07
}

COMMON_WORDS = {
    "the", "of", "and", "to", "in", "a", "is", "that", "for", "it", 
    "as", "was", "with", "be", "by", "on", "not", "he", "i", "this", 
    "are", "or", "his", "from", "at", "which", "but", "have", "an", 
    "had", "they", "you", "were", "their", "one", "all", "we", "can", 
    "her", "has", "there", "been", "if", "more", "when", "will", 
    "would", "who", "so", "no",
}


BIGRAM_DATA_RAW = """
TH 3.56 HE 3.07 IN 2.43 ER 2.05 AN 1.99 RE 1.85 ON 1.76 AT 1.49 EN 1.45 ND 1.35 TI 1.34 ES 1.34 OR 1.28 TE 1.20 OF 1.17 ED 1.17 IS 1.13 IT 1.12 AL 1.09 AR 1.07 ST 1.05 TO 1.04 NT 1.04 NG 0.95 SE 0.93 HA 0.93 AS 0.87 OU 0.87 IO 0.83 LE 0.83 VE 0.83 CO 0.79 ME 0.79 DE 0.76 HI 0.76 RI 0.73 RO 0.73 IC 0.70 NE 0.69 EA 0.69 RA 0.69 CE 0.65 LI 0.62 CH 0.60 LL 0.58 BE 0.58 MA 0.57 SI 0.55 OM 0.55 UR 0.54
"""


TRIGRAM_DATA_LIST = [
    "THE", "AND", "ING", "ION", "TIO", "ENT", "ATI", "FOR", "HER", "TER", 
    "HAT", "THA", "ERE", "ATE", "HIS", "CON", "RES", "VER", "ALL", "ONS",
    "NCE", "MEN", "ITH", "TED", "ERS", "PRO", "THI", "WIT", "ARE", "ESS",
    "NOT", "IVE", "WAS", "ECT", "REA", "COM", "EVE", "PER", "INT", "EST",
    "STA", "CTI", "ICA", "IST", "EAR", "AIN", "ONE", "OUR", "ITI", "RAT", 
]

#Normalize data 2gram
ENGLISH_2GRAM_LOGPROB = {}
pairs = re.findall(r'([A-Z]{2})\s([\d\.]+)[\sB\(%]*', BIGRAM_DATA_RAW.strip())
for pair, prob_str in pairs:
    prob = float(prob_str) / 100 
    ENGLISH_2GRAM_LOGPROB[pair] = math.log(prob)

#Normalize data 3gram
ENGLISH_3GRAM_LOGPROB = {}
high_prob_3gram = 0.005 # Xác suất cao cho 3-gram phổ biến (0.5%)
low_prob_3gram = 0.0001 # Xác suất thấp cho 3-gram hiếm (0.01%)

for tri in TRIGRAM_DATA_LIST:
    ENGLISH_3GRAM_LOGPROB[tri] = math.log(high_prob_3gram)

# Log-Likelihood mặc định cho các N-gram không có trong danh sách
default_log_prob = math.log(low_prob_3gram) 

def initialize_frequency_mapping(ciphertext):
    counter = Counter(ciphertext)
    cipher_sorted = [c for c, _ in counter.most_common()]
    english_sorted = sorted(
        ENGLISH_LETTER_FREQ,
        key=ENGLISH_LETTER_FREQ.get,
        reverse=True
    )

    mapping = {}
    for c, p in zip(cipher_sorted, english_sorted):
        mapping[c] = p

    remaining_p = [c for c in ALPHABET if c not in mapping.values()]
    remaining_c = [c for c in ALPHABET if c not in mapping]
    random.shuffle(remaining_p)

    for c, p in zip(remaining_c, remaining_p):
        mapping[c] = p

    return mapping
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
    new = mapping.copy()
    r = random.random()

    if r < 0.4:
        # random swap
        c1, c2 = random.sample(ALPHABET, 2)
        new[c1], new[c2] = new[c2], new[c1]

    elif r < 0.7:
        # frequency-guided swap (FIXED)
        group = random.choice(["ETAOIN", "SHRDLC", "UMWFGY", "PBVKJXQZ"])
        cipher_candidates = [c for c, p in new.items() if p in group]
        if len(cipher_candidates) >= 2:
            c1, c2 = random.sample(cipher_candidates, 2)
            new[c1], new[c2] = new[c2], new[c1]

    else:
        # block move
        chars = random.sample(ALPHABET, 4)
        values = [new[c] for c in chars]
        random.shuffle(values)
        for c, v in zip(chars, values):
            new[c] = v

    return new


def calculate_fitness(plaintext, phase):
    plaintext = get_cipher_only(plaintext)
    if phase == 1:
        W_2, W_3, W_F = 0.4, 0.4, 0.2
    else:
        W_2, W_3, W_F = 0.2, 0.7, 0.1

    score_2, score_3 = 0, 0
    N = len(plaintext)

    for i in range(N - 1):
        score_2 += ENGLISH_2GRAM_LOGPROB.get(
            plaintext[i:i+2], default_log_prob
        )

    for i in range(N - 2):
        score_3 += ENGLISH_3GRAM_LOGPROB.get(
            plaintext[i:i+3], default_log_prob
        )

    return (
        W_2 * score_2 +
        W_3 * score_3 +
        W_F * letter_freq_penalty(plaintext)
    )




def validate_plaintext_with_words(plaintext_with_spaces, common_words_set):
    plaintext_alpha = get_cipher_only(plaintext_with_spaces).lower() 
    total_length = len(plaintext_alpha)
    if total_length == 0:
        return 0.0

    match_count = 0
    for word in common_words_set:
        match_count += plaintext_alpha.count(word.lower())

    return match_count / total_length

def letter_freq_penalty(plaintext):
    from collections import Counter
    counter = Counter(plaintext)
    total = sum(counter.values())

    penalty = 0
    for c in ALPHABET:
        observed = counter.get(c, 0) / total
        expected = ENGLISH_LETTER_FREQ[c] / 100
        penalty += abs(observed - expected)

    return -50 * penalty


# ---  ALGORITHM SIMULATED ANNEALING  ---


def simulated_annealing_cracker(ciphertext, max_iter, temp, cooling, phase,init_mapping=None):
    mapping = init_mapping if init_mapping else initialize_frequency_mapping(ciphertext)
    plaintext = apply_mapping(ciphertext, mapping)
    score = calculate_fitness(plaintext, phase)

    best_map = mapping.copy()
    best_score = score

    stagnant = 0
   

    for i in range(max_iter):
        temp *= cooling
        neighbor = generate_neighbor_mapping(mapping)
        new_plain = apply_mapping(ciphertext, neighbor)
        new_score = calculate_fitness(new_plain, phase)

        delta = new_score - score
        if i % 50000 == 0 and i > 0:
            if best_score - score < 1e-4:
                break

        if delta > 0 or (temp > 1e-6 and random.random() < math.exp(delta / temp)):
            mapping = neighbor
            score = new_score
            stagnant = 0

            if score > best_score:
                best_map = mapping.copy()
                best_score = score
        else:
            stagnant += 1

        # Escape local optimum
        if stagnant > 20000:
            fixed = list("ETAOIN")
            shuffled = [c for c in ALPHABET if c not in fixed]
            random.shuffle(shuffled)

            new_map = {}
            for c in fixed:
                new_map[c] = mapping[c]
            remaining_plain = [mapping[c] for c in shuffled]
            random.shuffle(remaining_plain)
            for c, p in zip(shuffled, shuffled):
                new_map[c] = p

            mapping = new_map
            stagnant = 0

    return best_map, best_score


def local_refinement(mapping, ciphertext, steps=5000):
    best_map = mapping
    best_score = calculate_fitness(apply_mapping(ciphertext, mapping), phase=2)

    for _ in range(steps):
        new_map = generate_neighbor_mapping(best_map)
        score = calculate_fitness(apply_mapping(ciphertext, new_map),phase=2)
        if score > best_score:
            best_map = new_map
            best_score = score

    return best_map


def crack_with_restarts(ciphertext, restarts=8):
    global_best_map = None
    global_best_score = -float('inf')

    for r in range(restarts):
        print(f"--- Restart {r+1}/{restarts} ---")

        # Phase 1: Exploration
        map1, _ = simulated_annealing_cracker(
            ciphertext,
            max_iter=150000,
            temp=15.0,
            cooling=0.9995,
            phase=1
        )

        # Phase 2: Exploitation
        map2, score2 = simulated_annealing_cracker(
            ciphertext,
            max_iter=200000,
            temp=5.0,
            cooling=0.9998,
            phase=2,
            init_mapping=map1
        )

        # Hill climbing
        map2 = local_refinement(map2, ciphertext, steps=5000)
        final_score = calculate_fitness(apply_mapping(ciphertext, map2),phase=2)

        if final_score > global_best_score:
            global_best_map = map2
            global_best_score = final_score

    return global_best_map, global_best_score


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
    best_mapping, final_score = crack_with_restarts(ciphertext_alpha)
    end_time = time.time()
    best_mapping = local_refinement(best_mapping, ciphertext_alpha)
    final_score = calculate_fitness(apply_mapping(ciphertext_alpha, best_mapping),phase=2)

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