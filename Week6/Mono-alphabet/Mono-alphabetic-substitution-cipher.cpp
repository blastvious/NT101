#include <bits/stdc++.h>
using namespace std;

// Expected English letter distribution (kept for compatibility) 
map<char, double> letterDistribution = {
    {'e', 12.7}, {'t', 9.1}, {'a', 8.2}, {'o', 7.5}, {'i', 7.0},
    {'n', 6.7}, {'s', 6.3}, {'h', 6.1}, {'r', 6.0}, {'d', 4.3},
    {'l', 4.0}, {'c', 2.8}, {'u', 2.8}, {'m', 2.4}, {'w', 2.4},
    {'f', 2.2}, {'g', 2.0}, {'y', 2.0}, {'p', 1.9}, {'b', 1.5},
    {'v', 1.0}, {'k', 0.8}, {'j', 0.2}, {'x', 0.2}, {'q', 0.1},
    {'z', 0.1}
};

// A small list of common bigrams and approximate weights (you can expand)
static const vector<pair<string, double>> commonBigrams = {
    {"th", 2.71}, {"he", 2.33}, {"in", 2.03}, {"er", 1.78}, {"an", 1.61},
    {"re", 1.41}, {"ed", 1.17}, {"on", 1.13}, {"es", 1.13}, {"st", 1.12},
    {"en", 1.12}, {"at", 1.08}, {"te", 1.07}, {"or", 1.07}, {"ti", 0.99},
    {"hi", 0.99}, {"as", 0.93}, {"ng", 0.73}, {"of", 0.71}, {"ou", 0.68},
    {"ea", 0.67}, {"is", 0.66}, {"it", 0.65}, {"al", 0.64}, {"ar", 0.63}
};

// Some very common words to reward
static const vector<string> commonWords = {
    " the ", " and ", " that ", " have ", " for ", " not ", " with ",
    " you ", " this ", " but ", " his ", " from ", " they ", " will ",
    " one ", " all ", " would ", " there ", " their ", " what "
};


class Mono_alphabetic {
private:
    string cipherText;

public:
    void GetCiphertextFromFile() {
        ifstream file("ciphertext.txt");
        if (!file.is_open()) {
            cout << "Cannot open ciphertext.txt\n";
            cipherText = "";
            return;
        }
        stringstream buffer;
        buffer << file.rdbuf();
        cipherText = buffer.str();
        file.close();

        // Convert letters to lowercase (leave other chars unchanged)
        for (char &c : cipherText) {
            if (isalpha((unsigned char)c)) c = tolower(c);
        }
    }

    string getCipher() { return cipherText; }
};

class SubstitutionSolver {
private:
    string cipher;
    map<char, double> freq; // single-letter frequency %

    // RNG
    std::mt19937_64 rng;

    // Precomputed bigram weight map
    unordered_map<string, double> bigramMap;

public:
    SubstitutionSolver(string text)
        : cipher(text)
    {
        // seed RNG with time
        rng.seed((uint64_t)chrono::high_resolution_clock::now().time_since_epoch().count());
        // fill bigram map
        for (auto &p : commonBigrams) bigramMap[p.first] = p.second;
    }

    void computeFrequency() {
        int count[26] = {0};
        int total = 0;

        for (char c : cipher) {
            if (c >= 'a' && c <= 'z') {
                count[c - 'a']++;
                total++;
            }
        }

        for (int i = 0; i < 26; i++) {
            char ch = 'a' + i;
            if (total > 0) freq[ch] = (count[i] * 100.0) / total;
            else freq[ch] = 0.0;
        }
    }

    // apply mapping: mapping from cipher-char -> plain-char
    string applyMapping(const map<char, char> &mapping) {
        string plaintext = cipher;
        for (char &c : plaintext) {
            if (c >= 'a' && c <= 'z') {
                auto it = mapping.find(c);
                if (it != mapping.end()) c = it->second;
            }
        }
        return plaintext;
    }

    // convert array mapping to map<char,char>
    map<char,char> arrayToMap(const array<char,26> &arr) {
        map<char,char> m;
        for (int i=0;i<26;i++) m['a'+i] = arr[i];
        return m;
    }

    // initial mapping by frequency match (cipher most frequent -> english most frequent)
    array<char,26> initialMappingByFreq() {
        array<int,26> cnt; cnt.fill(0);
        for (char c : cipher) if (c >= 'a' && c <= 'z') cnt[c - 'a']++;
        vector<pair<int,char>> v;
        for (int i=0;i<26;i++) v.push_back({cnt[i], char('a'+i)});
        sort(v.begin(), v.end(), greater<pair<int,char>>());
        string eng = "etaoinshrdlcumwfgypbvkjxqz";
        array<char,26> mapC2P;
        for (int i=0;i<26;i++) mapC2P[v[i].second - 'a'] = eng[i];
        return mapC2P;
    }

    // Score plaintext by bigrams + word matches
    double scorePlaintext(const string &plain) {
        double score = 0.0;
        for (size_t i = 1; i < plain.size(); ++i) {
            char a = plain[i-1], b = plain[i];
            if (isalpha((unsigned char)a) && isalpha((unsigned char)b)) {
                string bg; bg.push_back(tolower(a)); bg.push_back(tolower(b));
                auto it = bigramMap.find(bg);
                if (it != bigramMap.end()) {
                    score += log( it->second + 1e-6 );
                } else {
                    score += log(0.01); // small penalty for rare bigram
                }
            } else {
                // small reward for spaces/punctuation boundaries
                if (a==' ' || b==' ') score += 0.01;
            }
        }

        // reward common words 
        string low = plain;
        for (char &c : low) if (isalpha((unsigned char)c)) c = tolower(c);
        string padded = " " + low + " ";
        for (auto &w : commonWords) {
            size_t pos = 0;
            int cnt = 0;
            while ((pos = padded.find(w, pos)) != string::npos) {
                cnt++;
                pos += w.size();
            }
            if (cnt > 0) score += cnt * (4.0 + (double)w.size());
        }

        // small penalty for unusual characters 
        int other = 0;
        for (char c : plain) if (!(isalpha((unsigned char)c) || c==' ' || ispunct((unsigned char)c))) other++;
        score -= other * 0.01;

        return score;
    }

    // hill-climbing with simulated annealing and random restarts
    void hillClimbSolve(int RESTARTS = 30, int ITER_PER_RESTART = 20000) {
        computeFrequency();
        // initial mapping
        array<char,26> bestArr = initialMappingByFreq();
        map<char,char> bestMap = arrayToMap(bestArr);
        string bestPlain = applyMapping(bestMap);
        double bestScore = scorePlaintext(bestPlain);

        // prepare helper distributions
        uniform_int_distribution<int> dist26(0,25);
        uniform_real_distribution<double> dist01(0.0,1.0);

        for (int r = 0; r < RESTARTS; ++r) {
            array<char,26> curArr;
            if (r == 0) curArr = bestArr;
            else {
                // randomize starting mapping: either shuffle or small perturbation of best
                if (r % 3 == 0) {
                    // full shuffle
                    string letters = "abcdefghijklmnopqrstuvwxyz";
                    shuffle(letters.begin(), letters.end(), rng);
                    for (int i=0;i<26;i++) curArr[i] = letters[i];
                } else {
                    // perturb best
                    curArr = bestArr;
                    for (int k=0;k<10;k++) {
                        int i = dist26(rng), j = dist26(rng);
                        swap(curArr[i], curArr[j]);
                    }
                }
            }

            map<char,char> curMap = arrayToMap(curArr);
            string curPlain = applyMapping(curMap);
            double curScore = scorePlaintext(curPlain);

            // simulated annealing parameters
            double T0 = 1.0;
            double TF = 1e-4;
            double T = T0;
            double cooling = pow(TF / T0, 1.0 / max(1, ITER_PER_RESTART));

            for (int it = 0; it < ITER_PER_RESTART; ++it) {
                // propose swap
                int i = dist26(rng), j = dist26(rng);
                if (i==j) continue;
                swap(curArr[i], curArr[j]);
                map<char,char> candMap = arrayToMap(curArr);
                string candPlain = applyMapping(candMap);
                double candScore = scorePlaintext(candPlain);

                double delta = candScore - curScore;
                bool accept = false;
                if (delta > 0) accept = true;
                else {
                    double prob = exp(delta / max(1e-12, T));
                    if (dist01(rng) < prob) accept = true;
                }

                if (accept) {
                    curScore = candScore;
                    curPlain.swap(candPlain);
                    curMap.swap(candMap);
                } else {
                    // revert swap
                    swap(curArr[i], curArr[j]);
                }

                // update global best
                if (curScore > bestScore) {
                    bestScore = curScore;
                    bestPlain = curPlain;
                    bestArr = curArr;
                    bestMap = arrayToMap(bestArr);
                    // optional progress
                    cerr << "[*] New best score: " << bestScore << " (restart " << r << " iter " << it << ")\n";
                }

                T *= cooling;
            } // end iterations
            // quick status
            if (r % 5 == 0) cerr << "Restart " << r << " current best_score=" << bestScore << "\n";
        } // end restarts

        // write result
        writeOutput(bestScore, arrayToMap(bestArr), bestPlain);
    }

    void writeOutput(double score, map<char, char> mapping, string plaintext) {
        ofstream out("plaintext_output.txt");
        if (!out.is_open()) {
            cerr << "Cannot open plaintext_output.txt for writing\n";
            return;
        }
        out << fixed << setprecision(6) << score << "\n";
        for (auto &p : mapping) out << p.first << "->" << p.second << " ";
        out << "\n";
        out << plaintext << "\n";
        out.close();
    }

    // compatibility: single-call solve (uses hillClimb)
    void solve() {
    
        int RESTARTS = 40;
        int ITER_PER_RESTART = 30000;
        hillClimbSolve(RESTARTS, ITER_PER_RESTART);
    }
};


// ---------------- main ----------------
int main() {
    Mono_alphabetic MA;
    MA.GetCiphertextFromFile();
    string cipher = MA.getCipher();
    if (cipher.empty()) {
        cerr << "Empty ciphertext - exiting\n";
        return 1;
    }

    SubstitutionSolver solver(cipher);
    solver.solve();

    cout << "Done. Check plaintext_output.txt\n";
    return 0;
}
