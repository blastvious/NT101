#include <iostream>
#include <string>
using namespace std;

string caesarEncrypt(const string& text, int key) {
    string result = "";
    for (char c : text) {
        if (isalpha(c)) {
            char base = isupper(c) ? 'A' : 'a';
            result += char((c - base + key) % 26 + base);
        }
        else {
            result += c; 
        }
    }
    return result;
}


string caesarDecrypt(const string& cipher, int key) {
    string result = "";
    for (char c : cipher) {
        if (isalpha(c)) {
            char base = isupper(c) ? 'A' : 'a';
            result += char((c - base - key + 26) % 26 + base);
        }
        else {
            result += c;
        }
    }
    return result;
}

int main() {
    int choice;
    string text;
    int key;

    cout << "===== Caesar Cipher =====" << endl;
    cout << "1. Ma hoa" << endl;
    cout << "2. Giai ma" << endl;
    cout << "Chon chuc nang (1 hoac 2): ";
    cin >> choice;
    cin.ignore();

    if (choice == 1) {
        cout << "Nhap plaintext: ";
        getline(cin, text);
        cout << "Nhap key: ";
        cin >> key;

        string encrypted = caesarEncrypt(text, key);
        cout << "Ciphertext: " << encrypted << endl;
    }
    else if (choice == 2) {
        cout << "Nhap ciphertext: ";
        getline(cin, text);
        cout << "Nhap key: ";
        cin >> key;

        string decrypted = caesarDecrypt(text, key);
        cout << "Plaintext: " << decrypted << endl;
    }
    else {
        cout << "Lua chon khong hop le!" << endl;
    }

    return 0;
}