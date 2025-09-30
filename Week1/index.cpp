#include <iostream>
#include <vector>
#include <limits>
using namespace std;

void toLowercase(string &s)
{
    for (char &x : s)
    {
        if (x > 64 && x < 91)
        {
            x += 32;
        }
    }
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

void generateKeyTable(string &key, vector<vector<char>> &TableKey)
{

    int lengOfKey = key.size();
    // Khoi tao ma tran 5x5 value set = 0
    TableKey.resize(5, vector<char>(5, 0));
    vector<int> hash(26, 0);

    int i, j;

    for (i = 0; i < lengOfKey; i++)
    {
        if (key[i] != 'j')
        {
            hash[key[i] - 'a'] = 2;
        }
    }

    hash['j' - 'a'] = 1;

     i = 0, j = 0;
    for (int  k = 0; k < lengOfKey; k++)
    {
        if(hash[key[k]- 'a']  == 2){
            hash[key[k]-'a'] -= 1;
            TableKey[i][j] = key[k];
            j++;
            if(j == 5){
                i++;
                j = 0;
            }
        }
    }
    for(int k = 0; k < 26; k++){
        if(hash[k]  == 0){
            TableKey[i][j] = (char)(k + 'a');
            j++;
            if(j == 5){
                i++;
                j = 0;
            }
        }
    }
    
}


void Search(vector<vector<char>> &keyTable, char a, char b, vector<int> &arr){
    if(a == 'j') a ='i';
    else if ( b=='j') b ='i';

    for(int i = 0; i < 5; i++){
        for(int j = 0; j < 5; j++){
            if(keyTable[i][j] == a){
                arr[0] = i;
                arr[1] = j;
            }
            else if (keyTable[i][j] == b){
                arr[2] = i;
                arr[3] = j;
            }
        }
    }
}

int standardize (string &str){
    if(str.size() % 2 != 0) str += 'z';
    
    return str.size();
}


void encrypt(string &str, vector<vector<char>> &keyT) {
    int n = str.size();
    vector<int> arr(4);

    for (int i = 0; i < n; i += 2) {

        Search(keyT, str[i], str[i + 1], arr);

        if (arr[0] == arr[2]) {
            str[i] = keyT[arr[0]][(arr[1] + 1) % 5];
            str[i + 1] = keyT[arr[0]][(arr[3] + 1) % 5];
        }
        else if (arr[1] == arr[3]) {
            str[i] = keyT[(arr[0] + 1) % 5][arr[1]];
            str[i + 1] = keyT[(arr[2] + 1) % 5][arr[1]];
        }
        else {
            str[i] = keyT[arr[0]][arr[3]];
            str[i + 1] = keyT[arr[2]][arr[1]];
        }
    }
}


void decrypt(string &str, vector<vector<char>> &keyT) {
    int n = str.size();
    vector<int> arr(4);

    for (int i = 0; i < n; i += 2) {

        Search(keyT, str[i], str[i + 1], arr);

        if (arr[0] == arr[2]) {  
         
            str[i]     = keyT[arr[0]][(arr[1] + 4) % 5];
            str[i + 1] = keyT[arr[0]][(arr[3] + 4) % 5];
        }
        else if (arr[1] == arr[3]) {  
         
            str[i]     = keyT[(arr[0] + 4) % 5][arr[1]];
            str[i + 1] = keyT[(arr[2] + 4) % 5][arr[1]];
        }
        else {
           
            str[i]     = keyT[arr[0]][arr[3]];
            str[i + 1] = keyT[arr[2]][arr[1]];
        }
    }
}



void encryptByPlayfairCipher(string &str, string &key) {
    vector<vector<char>> keyT;
    removespace(key);
    toLowercase(key);
    toLowercase(str);
    removespace(str);
    standardize(str);
    generateKeyTable(key, keyT);
    // encrypt(str, keyT);
    decrypt(str,keyT);
}

void InTable (vector<vector<char>> keyT){
    for(int i = 0; i < 5; i++){
        for(int j = 0; j < 5; j ++){
            cout<<keyT[i][j]<<" ";
        }
        cout<<"\n";
    }
}


void Menu (){
    int luachon;
    vector<vector<char>> keyT;
    string plaintext = "", key = "", cipherstring="";
    while (true)
    {
        system("cls");
        cout<<"\n\n\t\t ================== Menu ==================";
        cout<<"\n\t1. Nhap plaintext:";
        cout<<"\n\t2. Nhap keyword";
        cout<<"\n\t3. Tao key table matrix (5 x 5):";
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
            toLowercase(plaintext);
            standardize(plaintext);
            break;

        case 2:
            cout<<"Nhap keyword: ";
            getline(cin, key);
            removespace(key);
            toLowercase(key);
            break;

        case 3:
            generateKeyTable(key, keyT);
            InTable(keyT);
            break;

        case 4:
            cipherstring = plaintext;
            encrypt(cipherstring,keyT);
            
            cout<<"Cipher text: "<<cipherstring<<"\n";
            break;

        case 5: 
            decrypt(cipherstring, keyT);
            cout<<"Original text: "<<plaintext<<"\n";
            break;

        case 6:
            cout<<"Nhap ciphertext: ";
            getline(cin, cipherstring);
            removespace(cipherstring);
            toLowercase(cipherstring);
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


    
    // string key = "Harry Potter";
    // string str = "ARYWYPHCBVEBYGMPNCYGCNTDNCWTMGRMFTQPLEWTMLREFBEBQEBIYGBFLPHVOAEHKDHEUNGQFEROLEWTMLOPHEQGOSBEROQDWTLCMTHBWLNRKXRYLORYYPHCBVEBYRLGYDMKYGGWKLROANDBWGNERMNGYRLGHEWRTRLMBRHMUDGVODVTEGMCHLGWCMTFODNRRYCMZKODDUTDXGEOPOYRMFRMGUKXRYGHABROVTGQMCEHPRPEOTSEGEQLARYWYPOTMGQDOEXGOAUDHGUTULTNEHFTFHPGXGVPHGURBDMEGWKLETCBOTNTFQLTAEHMTUGEOAHEVEROXGVPHGDEWTEWGQIEDLPILERWPMOATNGQKQEAHBMVRFKBRMKLXODXFREBHMNUKXRYKLRMFLWDDNCN";
    // cout << "Key text: " << key << endl;
    // cout << "Plain text: " << str << endl;
    // encryptByPlayfairCipher(str, key);
    
    // cout << "Cipher text: " << str << endl;
    Menu();
    system("pause");
    return 0;
}
