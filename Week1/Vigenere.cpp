#include <iostream>
#include <cctype>
#include <limits>
using namespace std;

string generateKeyStream(string str, string key)
{

    int x = str.size();
    for (int i = 0;; i++)
    {
        if (x == i)
            i = 0;

        if (key.size() == str.size())
            break;
        ;
        key.push_back(key[i]);
    }
    return key;
}

string cipherText(string str, string key)
{
    string CypherText;

    for (int i = 0; i < str.size(); i++)
    {
        char x = (str[i] + key[i] + 26) % 26;

        x += 'A';

        CypherText.push_back(x);
    }
    return CypherText;
}

string originalText(string cypherText, string key)
{
    string originText;

    for (int i = 0; i < cypherText.size(); i++)
    {
        char x = (cypherText[i] - key[i] + 26) % 26;

        x += 'A';

        originText.push_back(x);
    }
    return originText;
}

void removespace(string &s)
{
    string tmp;
    for (char &x : s)
    {
        if (x != ' ')
        {
            tmp += x;
        }
    }
    s = tmp;
}

void upperString(string &str)
{
    for (char &c : str)
    {
        c = toupper(c);
    }
}

// void EncryptVigenere(string &plaintext, string &key)
// {
//     removespace(plaintext);
//     removespace(key);
//     upperString(plaintext);
//     upperString(key);

//     string keyStream = generateKeyStream(plaintext, key);
//     string CypherText = cipherText(plaintext, keyStream);

//     cout << "Ciphertext: " << CypherText << "\n";
//     cout << "Original/ Decrypted Text: " << originalText(CypherText, keyStream);
// }



void Menu (){
    int luachon;
    string plaintext = "", key = "", keystream ="", cipherstring="";
    while (true)
    {
        system("cls");
        cout<<"\n\n\t\t ================== Menu ==================";
        cout<<"\n\t1. Nhap plaintext:";
        cout<<"\n\t2. Nhap keyword";
        cout<<"\n\t3. Tao key stream:";
        cout<<"\n\t4. Encrypt:";
        cout<<"\n\t5. DeCrypt:";
        cout<<"\n\t6. Nhap cipher text: ";
        cout<<"\n\t0. Ket thuc"; 
        cout<<"\n\n\t\t ================== End ==================";
        cout<<"\nNhap lua chon: ";
        cin >> luachon;
        cin.ignore(numeric_limits<streamsize>::max(), '\n'); // bỏ enter thừa

        switch (luachon)
        {
        case 0: 
            return; // Thoát luôn hàm Menu

        case 1:
            cout<<"Nhap plaintext: ";
            getline(cin, plaintext);
            removespace(plaintext);
            upperString(plaintext);
            break;

        case 2:
            cout<<"Nhap keyword: ";
            getline(cin, key);
            removespace(key);
            upperString(key);
            break;

        case 3:
            keystream = generateKeyStream(plaintext, key);
            cout<<"Key Stream: "<<keystream<<"\n";
            break;

        case 4:
            cipherstring = cipherText(plaintext,keystream);
            cout<<"Cipher text: "<<cipherstring<<"\n";
            break;

        case 5: 
            plaintext = originalText(cipherstring, keystream);
            cout<<"Original text: "<<plaintext<<"\n";
            break;

        case 6:
            cout<<"Nhap ciphertext: ";
            getline(cin, cipherstring);
            removespace(cipherstring);
            upperString(cipherstring);
            break;

        default:
            cout << "Lua chon khong hop le!\n";
            break;
        }
        system("pause"); // dừng để xem kết quả trước khi clear màn hình
    }
}



int main()
{
    // string str = "N h om t am thuc hanh atm";
    // string keyword = "He lLo";
    Menu();
    system("pause");
    return 0;
}