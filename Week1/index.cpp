#include <iostream>
#include <vector>
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

    int i, j, flag=0;

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
    encrypt(str, keyT);
    decrypt(str,keyT);
}
int main()
{


    
    string key = "Harry Potter";
    string str = "ARYWYPHCBVEBYGMPNCYGCNTDNCWTMGRMFTQPLEWTMLREFBEBQEBIYGBFLPHVOAEHKDHEUNGQFEROLEWTMLOPHEQGOSBEROQDWTLCMTHBWLNRKXRYLORYYPHCBVEBYRLGYDMKYGGWKLROANDBWGNERMNGYRLGHEWRTRLMBRHMUDGVODVTEGMCHLGWCMTFODNRRYCMZKODDUTDXGEOPOYRMFRMGUKXRYGHABROVTGQMCEHPRPEOTSEGEQLARYWYPOTMGQDOEXGOAUDHGUTULTNEHFTFHPGXGVPHGURBDMEGWKLETCBOTNTFQLTAEHMTUGEOAHEVEROXGVPHGDEWTEWGQIEDLPILERWPMOATNGQKQEAHBMVRFKBRMKLXODXFREBHMNUKXRYKLRMFLWDDNCN";
    cout << "Key text: " << key << endl;
    cout << "Plain text: " << str << endl;
    encryptByPlayfairCipher(str, key);
    
    cout << "Cipher text: " << str << endl;

    return 0;
}
