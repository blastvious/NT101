#include <iostream>
#include <fstream>
#include <list>
#include <sstream>
using namespace std;

class BruteForceCaesar
{
private:
    string ciphertext;
public:
    BruteForceCaesar ();
    void SetCipherText(string);
    string GetCipherText () {
        return this->ciphertext;
    }
    void GetCipherTextFromFile();

};

BruteForceCaesar:: BruteForceCaesar(){
    this->GetCipherTextFromFile();
}
void BruteForceCaesar:: SetCipherText (string strCipher) {
    this->ciphertext = strCipher;
}

void BruteForceCaesar ::  GetCipherTextFromFile (){
    fstream file("ciphertext.txt");
    if(!file.is_open()){
        cout<<"Can not open file to read";
        SetCipherText("");
    }
    stringstream buffer;
    buffer<<file.rdbuf();
    file.close();
    SetCipherText(buffer.str());
}

int main () {

    BruteForceCaesar test;
    cout<<test.GetCipherText();

}