#include <iostream>
#include <cctype>
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

void EncryptVigenere(string &plaintext, string &key)
{
    removespace(plaintext);
    removespace(key);
    upperString(plaintext);
    upperString(key);

    string keyStream = generateKeyStream(plaintext, key);
    string CypherText = cipherText(plaintext, keyStream);

    cout << "Ciphertext: " << CypherText << "\n";
    cout << "Original/ Decrypted Text: " << originalText(CypherText, keyStream);
}

int main()
{
    string str = "Dai hoc CN T T";
    string keyword = "Nhom TH";
    EncryptVigenere(str, keyword);
    return 0;
}