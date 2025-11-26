#include <iostream>
#include <fstream>
#include <list>
#include <sstream>
#include <string>
#include <map>
using namespace std;
#define BRUTEFORCE_KEY 26

class Caesar
{
private:
    string ciphertext;
    map<int, string> results;

public:
    Caesar();
    void SetCipherText(string);
    string GetCipherText()
    {
        return this->ciphertext;
    }
    map<int, string> GetResults(){
        return this->results;
    }
    void SetResult();
    void GetCipherTextFromFile();
    map<int, string> BruteForceDecryption(string);
    void PrintResult ();
    void WritePlaintextToFile(int);
};

Caesar::Caesar()
{
    this->GetCipherTextFromFile();
}
void Caesar::SetCipherText(string strCipher)
{
    this->ciphertext = strCipher;
}
void Caesar :: SetResult(){
    this->results = BruteForceDecryption(this->ciphertext);
}
void Caesar :: PrintResult (){
    for (auto &p : this->results) {
        cout << "Key " << p.first << ": " << p.second << endl;
    }
}
void Caesar ::GetCipherTextFromFile()
{
    fstream file("ciphertext.txt");
    if (!file.is_open())
    {
        cout << "Can not open file to read";
        SetCipherText("");
    }
    stringstream buffer;
    buffer << file.rdbuf();
    file.close();
    SetCipherText(buffer.str());
}
map<int, string> Caesar ::BruteForceDecryption(string cipher)
{
    map<int, string> results;
    for (int k = 0; k < BRUTEFORCE_KEY; k++)
    {
        string plaintext = "";
        for (char c : cipher)
        {
            if (isalpha(c))
            {
                char base = isupper(c) ? 'A' : 'a';
                plaintext += char((c - base - k + 26) % 26 + base);
            }
            else
                plaintext += c;
        }
        results[k] = plaintext;
    }
    return results;
}

void Caesar :: WritePlaintextToFile(int key){
    if (results.find(key) == results.end()) {
        cout << "Key not found. Please run SetResult() first.\n";
        return;
    }

    
    ofstream out("result.txt");
    if (!out.is_open()) {
        cout << "Cannot open result.txt to write.\n";
        return;
    }

    out << "Key: " << key << endl;
    out << "Plaintext: " << endl;
    out << results[key] << endl;

    out.close();
    cout << "Plaintext written to result.txt successfully.\n";
}

int main()
{

    Caesar test;
    test.SetResult();   // <<-- QUAN TRỌNG
    test.PrintResult();
    test.WritePlaintextToFile(4);
}