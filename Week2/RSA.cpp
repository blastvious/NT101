#include <bits/stdc++.h>
using namespace std;

class RSA {
private:
    long long p, q, n, phi, e, d;

    // Kiểm tra số nguyên tố
    bool isPrime(long long n) {
        if (n <= 1) return false;
        if (n <= 3) return true;
        if (n % 2 == 0 || n % 3 == 0) return false;
        
        for (long long i = 5; i * i <= n; i += 6) {
            if (n % i == 0 || n % (i + 2) == 0)
                return false;
        }
        return true;
    }

    // Tạo số nguyên tố ngẫu nhiên trong khoảng [min, max]
    long long generateRandomPrime(long long min, long long max) {
        random_device rd;
        mt19937 gen(rd());
        uniform_int_distribution<long long> dis(min, max);
        
        long long num = dis(gen);
        while (!isPrime(num)) {
            num = dis(gen);
        }
        return num;
    }

    // Tính lũy thừa modulo
    long long power(long long base, long long expo, long long m) {
        long long res = 1;
        base = base % m;
        while (expo > 0) {
            if (expo & 1)
                res = (res * base) % m;
            base = (base * base) % m;
            expo = expo >> 1;
        }
        return res;
    }

    // Thuật toán Euclid mở rộng
    long long extendedGCD(long long a, long long b, long long& x, long long& y) {
        if (b == 0) {
            x = 1;
            y = 0;
            return a;
        }
        long long x1, y1;
        long long gcd = extendedGCD(b, a % b, x1, y1);
        x = y1;
        y = x1 - (a / b) * y1;
        return gcd;
    }

    // Tính nghịch đảo modulo
    long long modInverse(long long a, long long m) {
        long long x, y;
        long long gcd = extendedGCD(a, m, x, y);
        if (gcd != 1) return -1;
        return (x % m + m) % m;
    }

public:
    // Khởi tạo với p, q, e cho trước
    void initializeWithValues(long long p_val, long long q_val, long long e_val) {
        if (!isPrime(p_val) || !isPrime(q_val)) {
            throw runtime_error("p và q phải là số nguyên tố!");
        }
        p = p_val;
        q = q_val;
        n = p * q;
        phi = (p - 1) * (q - 1);
        
        if (e_val >= phi || __gcd(e_val, phi) != 1) {
            throw runtime_error("Giá trị e không hợp lệ!");
        }
        e = e_val;
        d = modInverse(e, phi);
    }
    
    // Khởi tạo ngẫu nhiên
    void generateRandomKeys() {
        // Tạo p, q ngẫu nhiên (đủ lớn)
        p = generateRandomPrime(1000, 10000);
        q = generateRandomPrime(1000, 10000);
        while (p == q) {
            q = generateRandomPrime(1000, 10000);
        }
        
        n = p * q;
        phi = (p - 1) * (q - 1);
        
        // Chọn e = 65537 (số Fermat thứ 4)
        e = 65537;
        while (e >= phi || __gcd(e, phi) != 1) {
            e = generateRandomPrime(65537, phi - 1);
        }
        
        d = modInverse(e, phi);
    }
    
    // Mã hóa số
    long long encrypt(long long message) {
        if (message >= n) {
            throw runtime_error("Thông điệp quá lớn cho khóa hiện tại!");
        }
        return power(message, e, n);
    }
    
    // Giải mã số
    long long decrypt(long long ciphertext) {
        return power(ciphertext, d, n);
    }
    
    // Mã hóa chuỗi
    vector<long long> encryptString(const string& message) {
        vector<long long> ciphertext;
        for (char c : message) {
            ciphertext.push_back(encrypt(static_cast<long long>(c)));
        }
        return ciphertext;
    }
    
    // Giải mã chuỗi
    string decryptString(const vector<long long>& ciphertext) {
        string message;
        for (long long c : ciphertext) {
            message += static_cast<char>(decrypt(c));
        }
        return message;
    }
    
    // Lấy khóa công khai
    pair<long long, long long> getPublicKey() {
        return {e, n};
    }
    
    // Lấy khóa riêng tư
    pair<long long, long long> getPrivateKey() {
        return {d, n};
    }

    // Lấy p và q
    pair<long long, long long> getPQ() {
        return {p, q};
    }
};

void showMenu() {
    cout << "\n\t\t+================== Menu RSA ==================+";
    cout << "\n\t\t|  1. Xem thong tin khoa                      |";
    cout << "\n\t\t|  2. Ma hoa so                               |";
    cout << "\n\t\t|  3. Giai ma so                              |";
    cout << "\n\t\t|  4. Ma hoa chuoi                           |";
    cout << "\n\t\t|  5. Giai ma chuoi                          |";
    cout << "\n\t\t|  6. Tao ngau nhien khoa moi                |";
    cout << "\n\t\t|  0. Thoat chuong trinh                     |";
    cout << "\n\t\t+===========================================+";
    cout << "\n\nNhap lua chon cua ban: ";
}

int main() {
    RSA rsa;
    cout << "Generate random key...\n";
    rsa.generateRandomKeys();
    cout << "Successful!\n\n";
    
    // Hiển thị thông tin khóa ban đầu
    auto [p, q] = rsa.getPQ();
    auto [e, n] = rsa.getPublicKey();
    auto [d, _] = rsa.getPrivateKey();
    cout << "Key's infomation:" << endl;
    cout << "p = " << p << ", q = " << q << endl;
    cout << "n = p x q = " << n << endl;
    cout << "PU (e,n): (" << e << "," << n << ")" << endl;
    cout << "PR (d,n): (" << d << "," << n << ")" << endl;
    
    system("pause");
    
    int choice;
    while (true) {
        system("cls");
        showMenu();
        cin >> choice;
        cin.ignore(numeric_limits<streamsize>::max(), '\n');

        try {
            switch (choice) {
                case 0:
                    return 0;

                case 1: {
                    auto [p, q] = rsa.getPQ();
                    auto [e, n] = rsa.getPublicKey();
                    auto [d, _] = rsa.getPrivateKey();
                    cout << "Key's infomation:" << endl;
                    cout << "p = " << p << ", q = " << q << endl;
                    cout << "n = p x q = " << n << endl;
                    cout << "PU (e,n): (" << e << "," << n << ")" << endl;
                    cout << "PR (d,n): (" << d << "," << n << ")" << endl;
                    break;
                }

                case 2: {
                    long long message;
                    cout << "Nhap so can ma hoa: ";
                    cin >> message;
                    long long encrypted = rsa.encrypt(message);
                    cout << "Ket qua ma hoa: " << encrypted << endl;
                    
                    break;
                }

                case 3: {
                    long long ciphertext;
                    cout << "Nhap so can giai ma: ";
                    cin >> ciphertext;
                    long long decrypted = rsa.decrypt(ciphertext);
                    cout << "Ket qu giai ma: " << decrypted << endl;
                    break;
                }

                case 4: {
                    string message;
                    cout << "Nhap chuoi ma hoa: ";
                    getline(cin, message);
                    vector<long long> encrypted = rsa.encryptString(message);
                    cout << "ket qua ma hoa dang so: " << endl;
                    for (long long num : encrypted) {
                        cout << num << " ";
                    }
                    cout << endl;
                    break;
                }

                case 5: {
                    cout << "Nhap so luong can giai ma: ";
                    int count;
                    cin >> count;
                    vector<long long> encrypted;
                    cout << "Nhap " << count << " so (moi so mot dong):" << endl;
                    for (int i = 0; i < count; i++) {
                        long long num;
                        cin >> num;
                        encrypted.push_back(num);
                    }
                    string decrypted = rsa.decryptString(encrypted);
                    cout << "ket qua giai ma: " << decrypted << endl;
                    break;
                }

                case 6: {
                    rsa.generateRandomKeys();
                    auto [p, q] = rsa.getPQ();
                    auto [e, n] = rsa.getPublicKey();
                    auto [d, _] = rsa.getPrivateKey();
                    cout << "Tao khoa moi thanh cong!\n";
                    cout << "Kye's infomation:" << endl;
                    cout << "p = " << p << ", q = " << q << endl;
                    cout << "n = p x q = " << n << endl;
                    cout << "PU (e,n): (" << e << "," << n << ")" << endl;
                    cout << "PR (d,n): (" << d << "," << n << ")" << endl;
                    break;
                }

                default:
                    cout << "Lua chon khong hop le!" << endl;
            }
        } catch (const exception& e) {
            cout << "Error: " << e.what() << endl;
        }
        
        cout << "\n----------------------------------------\n";
        system("pause");
    }

    return 0;
}