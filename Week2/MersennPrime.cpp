#include <iostream>
#include <cstdlib>
#include <ctime>
#include <random>
#include <chrono>
#include <limits>
#include <cstdint>

using ull = unsigned long long;
using u128 = unsigned __int128;
using namespace std;

// Fast and safe multiply modulo using 128-bit intermediate
ull mulmod(ull a, ull b, ull m) {
    return (ull)((u128)a * b % m);
}

// For computing modular exponentiation (a^e mod m)
ull modpow(ull base, ull e, ull m) {
    ull x = 1;
    ull y = base % m;
    while (e > 0) {
        if (e & 1) {
            x = mulmod(x, y, m);
        }
        y = mulmod(y, y, m);
        e >>= 1;
    }
    return x % m;
}

// Miller-Rabin primality test (probabilistic)
static std::mt19937_64 rng((unsigned)chrono::high_resolution_clock::now().time_since_epoch().count());

bool miller_rabin(ull n, int k = 12) {
    if (n < 2) return false;
    if (n == 2 || n == 3) return true;
    if ((n & 1) == 0) return false;

    ull d = n - 1;
    int s = 0;
    while ((d & 1) == 0) {
        d >>= 1;
        s++;
    }

    std::uniform_int_distribution<ull> dist;
    for (int i = 0; i < k; i++) {
        if (n <= 4) break; // small n handled above
        dist.param(std::uniform_int_distribution<ull>::param_type(2, n - 2));
        ull a = dist(rng);
        ull x = modpow(a, d, n);

        if (x == 1 || x == n - 1) continue;

        bool composite = true;
        for (int j = 0; j < s - 1; j++) {
            x = mulmod(x, x, n);
            if (x == n - 1) {
                composite = false;
                break;
            }
        }
        if (composite) return false; // composite
    }
    return true; // probably prime
}

// Sinh số nguyên tố có đúng bits bit
ull random_prime(int bits) {
    if (bits < 2) return 2;
    ull lo = (bits == 64) ? (1ULL << 63) : (1ULL << (bits - 1));
    ull hi;
    if (bits >= 64) hi = numeric_limits<ull>::max();
    else hi = (1ULL << bits) - 1;

    std::uniform_int_distribution<ull> dist(lo, hi);
    while (true) {
        ull x = dist(rng);
        x |= lo;      // ensure top bit set (correct bit length)
        x |= 1ULL;    // ensure odd
        if (miller_rabin(x, 20)) return x;
    }
}

// GCD Euclid
ull gcd(ull a, ull b) {
    while (b) {
        ull r = a % b;
        a = b;
        b = r;
    }
    return a;
}

void cls() {
    #ifdef _WIN32
        system("cls");
    #else
        system("clear");
    #endif
}

void pause() {
    cout << "\nNhan Enter de tiep tuc...";
    cin.ignore();
    getchar();
}

int main() {
    
    cin.tie(nullptr);
    srand(time(0));

    while (true) {
        cls();
        cout << "\n=== ===================Menu==================== ===\n";
        cout << "                                                     \n";
        cout << "  1 Sinh so nguyen to                 \n";
        cout << "      - So 8 bits  (toi da: 255)                   \n";
        cout << "      - So 16 bits (toi da: 65,535)               \n";
        cout << "      - So 64 bits (toi da: 2^64-1)               \n";
        cout << "                                                     \n";
        cout << "  2 Tim so nguyen to lon nhat                    \n";
        cout << "      duoi Mersenne thu 10 (2^89-1)                \n";
        cout << "                                                     \n";
        cout << "   3  Kiem tra so nguyen to                         \n";
        cout << "      (Nhap so de kiem tra)                        \n";
        cout << "                                                     \n";
        cout << "  4   Uoc so chung lon nhat (GCD)             \n";
        cout << "                                                     \n";
        cout << "  5   Tinh luy thua theo modulo (a^x mod p)        \n";
        cout << "      Vi du: 7^40 mod 19 = 1                       \n";
        cout << "                                                     \n";
        cout << "  0 Ke thuc                           \n";
        cout << "                                                     \n";
        cout << "========================================================\n";
        cout << "\nChon chuc nang (0-5): ";
        
        int choice;
        cin >> choice;
        
        if (choice == 0) break;
        
        cls();
        switch (choice) {
            case 1: {
                cout << "\n=== Sinh so nguyen to ngau nhien ===\n\n";
                cout << "So nguyen to 8 bits: " << random_prime(8) << "\n";
                cout << "So nguyen to 16 bits: " << random_prime(16) << "\n";
                cout << "So nguyen to 64 bits: " << random_prime(64) << "\n";
                break;
            }
            case 2: {
                cout << "\n=== TIm so nguyen to gan 2^89-1 ===\n\n";
                ull x = (1ULL << 63) - 1; // Max 64-bit
                int found = 0;
                while (found < 1) {
                    if (miller_rabin(x, 20)) {
                        cout << "So nguyen to co the tim: " << x << "\n";
                        found++;
                    }
                    x--;
                }
                break;
            }
            case 3: {
                cout << "\n=== Kiem tra so nguyen to ===\n\n";
                cout << "Nhap so de kiem tra: ";
                ull n;
                cin >> n;
                bool prime = miller_rabin(n, 20);
                cout << n << (prime ? " la so nguyen to!\n" : " Khong phai so nguyen to!\n");
                break;
            }
            case 4: {
                cout << "\n=== Uoc so chung lon nhat ===\n\n";
                cout << "So thu nhat: ";
                ull a; cin >> a;
                cout << "So thu 2: ";
                ull b; cin >> b;
                cout << "GCD(" << a << ", " << b << ") = " << gcd(a, b) << "\n";
                break;
            }
            case 5: {
                cout << "\n=== LUY THUA THEO MODULO ===\n\n";
                cout << "a (co so): ";
                ull a; cin >> a;
                cout << "x (so mu): ";
                ull x; cin >> x;
                cout << "p (modulo): ";
                ull p; cin >> p;
                if (p <= 0) {
                    cout << "Modulo > 0!\n";
                    break;
                }
                ull result = modpow(a, x, p);
                cout << a << "^" << x << " mod " << p << " = " << result << "\n";
                break;
            }
            default:
                cout << "Lua chon khong hop le!\n";
        }
        pause();
    }
    
    return 0;
}