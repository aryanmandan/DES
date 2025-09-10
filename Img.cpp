#include<bits/stdc++.h>
using namespace std;

const int IP[64] ={ 58,50,42,34,26,18,10, 2,     // Initial Permutation box
                    60,52,44,36,28,20,12, 4,
                    62,54,46,38,30,22,14, 6,
                    64,56,48,40,32,24,16, 8,
                    57,49,41,33,25,17, 9, 1,
                    59,51,43,35,27,19,11, 3,
                    61,53,45,37,29,21,13, 5,
                    63,55,47,39,31,23,15, 7 };

const int E[48] ={ 32, 1, 2, 3, 4, 5,            // 32->48 Expansion box
                    4, 5, 6, 7, 8, 9,
                    8, 9,10,11,12,13,
                   12,13,14,15,16,17,
                   16,17,18,19,20,21,
                   20,21,22,23,24,25,
                   24,25,26,27,28,29,
                   28,29,30,31,32, 1 };

const int PC1[56] ={ 57,49,41,33,25,17, 9,       // Pick 56 bits out of 64 bit key
                      1,58,50,42,34,26,18,
                     10, 2,59,51,43,35,27,
                     19,11, 3,60,52,44,36,
                     63,55,47,39,31,23,15,
                      7,62,54,46,38,30,22,
                     14, 6,61,53,45,37,29,
                     21,13, 5,28,20,12, 4 };

const int PC2[48] ={14,17,11,24, 1, 5,           // Pick 48 bits out of 56 bits after circular left shift key
                     3,28,15, 6,21,10,
                    23,19,12, 4,26, 8,
                    16, 7,27,20,13, 2,
                    41,52,31,37,47,55,
                    30,40,51,45,33,48,
                    44,49,39,56,34,53,
                    46,42,50,36,29,32 };

const int P[32] = {29,12,28,17,                 // 32-bit Permutation box for 
                   16, 7,20,21,
                    1,15,23,26,
                    5,18,31,10,
                    2, 8,24,14,
                   32,27, 3, 9,
                   19,13,30, 6,
                   22,11, 4,25 };

const int shift[16]={1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1};   // left shift according to round 

int S[8][4][16] = {{{14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7},    // S1
                    {0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8},
                    {4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0},
                    {15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13}},

                    {{15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10},   // S2
                    {3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5},
                    {0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15},
                    {13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9}},

                    {{10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8},   // S3
                    {13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1},
                    {13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7},
                    {1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12}},

                    {{7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15},   // S4
                    {13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9},
                    {10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4},
                    {3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14}},

                    {{2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9},   // S5
                    {14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6},
                    {4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14},
                    {11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3}},

                    {{12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11},   // S6
                    {10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8},
                    {9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6},
                    {4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13}},

                    {{4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1},   // S7
                    {13,0,11,7,4,9,1,10,14,3,5,12,2,15,6,8},
                    {1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2},
                    {6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12}},

                    {{13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7},   // S8
                    {1,15,13,8,10,3,7,4,12,5,6,11,0,14,9, 2},
                    {7,11,4,1,9,12,14,2,0, 6,10,13,15, 3, 5},
                    {2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11}}};

const int FP[64] ={40, 8,48,16,56,24,64,32,
                   39, 7,47,15,55,23,63,31,
                   38, 6,46,14,54,22,62,30,
                   37, 5,45,13,53,21,61,29,
                   36, 4,44,12,52,20,60,28,
                   35, 3,43,11,51,19,59,27,
                   34, 2,42,10,50,18,58,26,
                   33, 1,41, 9,49,17,57,25 };

vector<bitset<48>> keys;                             // Store round keys

bitset<64> text_to_bitset(const string &text){      // plaintext or key into bits
    bitset<64> block;
    for(int i=0;i<8;i++){
        unsigned char c=text[i];
        for(int j=0;j<8;j++){
            block[63-(i*8+j)]=(c>>(7-j))&1;
        }
    }
    return block;
}

string bitset_to_text(const bitset<64> &block){
    string text;
    text.reserve(8);
    for(int i=0;i<8;i++){
        unsigned char c=0;
        for(int j=0;j<8;j++){
            c|=(block[63-(i*8+j)]<<(7-j));
        }
        text.push_back(c);
    }
    return text;
}

template<size_t N,size_t M>
bitset<N> p_box(const bitset<M> &input, const int table[]){    // permutation or expansion or compression box
    bitset<N> output;
    for(int i=0;i<int(N);i++){
        output[N-1-i]=input[M-table[i]];
    }
    return output;

}

pair<bitset<32>,bitset<32>> block_split(const bitset<64> &x64 ){ // split plaintext bits into two blocks
    bitset<32> L;
    bitset<32>R;
    for(int i=0;i<32;++i){
        L[i]=x64[i];
        R[i]=x64[i+32];
    }
    return {L,R};
}

pair<bitset<28>,bitset<28>> round_key_gen_split(const bitset<64> &key){ 
    bitset<56> r_key=p_box<56,64>(key,PC1);  // Key generation with splitting into C,D
    bitset<28> C;
    bitset<28> D;
    for(int i=0;i<28;++i){
            C[i]=r_key[i];
            D[i]=r_key[i+28];
    }
    return {C,D};
}

bitset<28> left_shift(const bitset<28> &half, int shift){           // Left shift for 28-bit 
    shift%=28;
    bitset<28> res;
    for (int i=0;i<28;i++) {
        res[i]=half[(i+shift)%28];
    }
    return res;
}

bitset<56> merge_halves(const bitset<28> &C, const bitset<28> &D){   // Merge two 28-bit halves into 56-bit
    bitset<56> output;
    for (int i=0;i<28;i++) {
        output[i]=C[i];
        output[28+i]=D[i];
    }
    return output;
}

void round_key_store(const string &key, bool rev=false){      // Generate and store round keys
    keys.clear();
    bitset<64> x64_key=text_to_bitset(key);
    pair<bitset<28>,bitset<28>>CD=round_key_gen_split(x64_key);
    bitset<28> C=CD.first;
    bitset<28> D=CD.second;
    for (int i=0;i<16;i++){
        C = left_shift(C,shift[i]);
        D = left_shift(D,shift[i]);
        bitset<56> merged=merge_halves(C,D);
        keys.push_back(p_box<48,56>(merged,PC2));
    }
    if (rev) {
        reverse(keys.begin(), keys.end());
    }
}

bitset<32> s_box(const bitset<48> &input){        // Substitution box function
    bitset<32> output;
    int x=0;
    for(int i=0;i<8;i++){
        bitset<6> six_bits;
        for(int j=0;j<6;j++){
            six_bits[5-j]=input[i*6+j];
        }
        int row=(six_bits[5]<<1) | six_bits[0];
        int col=(six_bits[4]<<3) | (six_bits[3]<<2) | (six_bits[2]<<1) | six_bits[1];
        int value=S[i][row][col];
        bitset<4> sub_value(value);
        for(int k=3;k>=0;k--,x++){
            output[x]=sub_value[k];
        }
    }
    return output;
}

string encrypt(const string &plaintext,const string &key){    // Main encryption function
    bitset<64> msg=text_to_bitset(plaintext);
    round_key_store(key);
    msg=p_box<64,64>(msg,IP);
    auto LR= block_split(msg);
    bitset<32> L0=LR.first,R0=LR.second;
    for(int i=0;i<16;i++){
        bitset<32> temp=R0;
        bitset<48> R_expanded=p_box<48,32>(R0,E);
        bitset<48> XOR_result=R_expanded^keys[i];
        bitset<32> result=s_box(XOR_result);
        bitset<32> p_result=p_box<32,32>(result,P);
        R0=L0^p_result;
        L0=temp;
    }
    bitset<64> cipherblock;
    for(int i=0;i<32;i++){
        cipherblock[i]=R0[i];
        cipherblock[i+32]=L0[i];
    }
    cipherblock=p_box<64,64>(cipherblock,FP);
    string ciphertext=bitset_to_text(cipherblock);
    return ciphertext;
}

string decrypt(const string &ciphertext,const string &key){    //Main decryption function
    bitset<64> secret_msg=text_to_bitset(ciphertext);
    round_key_store(key,true);
    secret_msg=p_box<64,64>(secret_msg,IP);
    auto LR=block_split(secret_msg);
    bitset<32> L0=LR.first, R0=LR.second;
    for(int i=0;i<16;i++){
        bitset<32> temp=R0;
        bitset<48> R_expanded=p_box<48,32>(R0,E);
        bitset<48> XOR_result=R_expanded^keys[i];
        bitset<32> result=s_box(XOR_result);
        bitset<32> p_result=p_box<32,32>(result,P);
        R0=L0^p_result;
        L0=temp;
    }
    bitset<64> plaintext_block;
    for(int i=0;i<32;i++){
        plaintext_block[i]=R0[i];
        plaintext_block[i+32]=L0[i];
    }
    plaintext_block=p_box<64,64>(plaintext_block,FP);
    string plaintext=bitset_to_text(plaintext_block);
    return plaintext;
}

string CBC_CTS_encrypt(const string &plaintext,const string &key,const string &IV){
    const unsigned long long bsz=8ULL;
    string ciphertext;
    string prev=IV;
    if (plaintext.empty()){
        return ciphertext;
    }
    unsigned long long full_len=(plaintext.size()/bsz)*bsz; 
    unsigned long long d=plaintext.size()-full_len;
    if(d==0){
        for(unsigned long long i=0;i<plaintext.size();i+=bsz){
            string block=plaintext.substr(i,bsz);
            string x; 
            x.reserve(bsz);
            for(unsigned long long j=0;j<bsz;++j) x.push_back(block[j]^prev[j]);
            string c=encrypt(x,key);
            ciphertext+=c;
            prev=c;
        }
        return ciphertext;
    }
    if(full_len==0){
        string block=plaintext+string(bsz-d,'\0');
        string x;
        x.reserve(bsz);
        for(unsigned long long j=0;j<bsz;++j) x.push_back(block[j]^prev[j]);
        string c=encrypt(x,key);
        ciphertext+=c;
        return ciphertext;
    }
    unsigned long long upto=full_len -bsz; 
    for(unsigned long long i=0;i<upto;i+=bsz){
        string block=plaintext.substr(i,bsz);
        string x;x.reserve(bsz);
        for(unsigned long long j=0;j<bsz;++j) x.push_back(block[j]^prev[j]);
        string c=encrypt(x,key);
        ciphertext+=c;
        prev=c;
    }
    string Pn_1=plaintext.substr(full_len-bsz,bsz);
    string Pn_star=plaintext.substr(full_len);
    string Pn=Pn_star+string(bsz-d,'\0'); 
    string x1; 
    x1.reserve(bsz);
    for(unsigned long long j=0;j<bsz;++j)x1.push_back(Pn_1[j]^prev[j]);
    string Cn_1=encrypt(x1,key);
    string x2; 
    x2.reserve(bsz);
    for(unsigned long long j=0;j<bsz;++j) x2.push_back(Pn[j]^Cn_1[j]);
    string Cn=encrypt(x2,key);
    ciphertext+=Cn_1.substr(0,d);
    ciphertext+=Cn;
    return ciphertext;
}

string CBC_CTS_decrypt(const string &ciphertext,const string &key,const string &IV,unsigned long long plaintext_len) {
    const unsigned long long bsz=8ULL;
    string plaintext;
    string prev=IV;
    if(plaintext_len==0 || ciphertext.empty()){
        return string();
    }
    unsigned long long d=plaintext_len%bsz;
    if(d==0){
        for(unsigned long long i=0;i<ciphertext.size();i+=bsz){
            string C=ciphertext.substr(i,bsz);
            string D=decrypt(C, key);
            string P; 
            P.reserve(bsz);
            for(unsigned long long j=0;j<bsz;++j) P.push_back(D[j]^prev[j]);
            plaintext+=P;
            prev=C;
        }
        return plaintext.substr(0,plaintext_len);
    }
    if(ciphertext.size()<(bsz+d)){
        string C=ciphertext.substr(0,bsz);
        string D=decrypt(C,key);
        string P;
        P.reserve(bsz);
        for(unsigned long long j=0;j<bsz;++j) P.push_back(D[j]^prev[j]);
        return P.substr(0,plaintext_len);
    }
    unsigned long long pre_len=ciphertext.size()-(bsz+d);
    for(unsigned long long i=0;i<pre_len;i+=bsz){
        string C=ciphertext.substr(i,bsz);
        string D=decrypt(C,key);
        string P; 
        P.reserve(bsz);
        for(unsigned long long j=0;j<bsz;++j) P.push_back(D[j]^prev[j]);
        plaintext+=P;
        prev=C;
    }
    string Cn_1_star=ciphertext.substr(pre_len,d);
    string Cn=ciphertext.substr(pre_len+d,bsz);
    string Z=decrypt(Cn,key);
    string Cn_1=Cn_1_star+Z.substr(d);
    string Dn_1=decrypt(Cn_1,key);
    string Pn_1; 
    Pn_1.reserve(bsz);
    for(unsigned long long j=0; j<bsz;++j) Pn_1.push_back(Dn_1[j]^prev[j]);
    string Zn_xor_Cn_1; 
    Zn_xor_Cn_1.reserve(bsz);
    for(unsigned long long j=0;j<bsz;++j) Zn_xor_Cn_1.push_back(Z[j]^Cn_1[j]);
    string Pn_star=Zn_xor_Cn_1.substr(0,d);
    plaintext+=Pn_1;
    plaintext+=Pn_star;
    return plaintext.substr(0,plaintext_len);
}

static bool read_file_all(const string& path, string& out) {
    ifstream f(path, ios::binary);
    if (!f) return false;
    f.seekg(0, ios::end);
    streampos sz = f.tellg();
    if (sz < 0) return false;
    out.resize(static_cast<size_t>(sz));
    f.seekg(0, ios::beg);
    if (sz > 0) f.read(&out[0], sz);
    return f.good() || f.eof();
}

static bool write_file_all(const string& path, const string& data) {
    ofstream f(path, ios::binary);
    if (!f) return false;
    f.write(data.data(), static_cast<streamsize>(data.size()));
    return f.good();
}

static void append_u64_le(string& s, uint64_t v) {
    for (int i = 0; i < 8; ++i) s.push_back(static_cast<char>((v >> (8 * i)) & 0xFF));
}

static uint64_t read_u64_le(const string& s, size_t off) {
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i) {
        v |= (static_cast<uint64_t>(static_cast<unsigned char>(s[off + i])) << (8 * i));
    }
    return v;
}

int main() {
    cout << "Data Encryption Standatd (DES) for Files\n";
    cout << "1. Encrypt\n";
    cout << "2. Decrypt\n";
    cout << "3. Exit\n";
    cout << "Choice: ";
    int choice = 0;
    if (!(cin >> choice)) return 0;
    cin.ignore();
    if (choice == 1) {
        string in_path, out_path, key;
        cout << "Enter path and name of file : ";
        getline(cin, in_path);
        cout << "Enter 8-byte key : ";
        getline(cin, key);
        cout << "Enter path and name to save after Encryption : ";
        getline(cin, out_path);
        string plain;
        if (!read_file_all(in_path, plain)) {
            cerr << "Failed to read input file\n";
            return 1;
        }
        string iv;
        cout<< "Enter Initial Vector (IV) : ";
        getline(cin,iv);
        string ct = CBC_CTS_encrypt(plain, key, iv);
        string out;
        out.reserve(4 + 8 + 8 + ct.size());
        out.push_back('D');
        out.push_back('C');
        out.push_back('T');
        out.push_back('S');
        append_u64_le(out, static_cast<uint64_t>(plain.size()));
        out += iv;
        out += ct;
        if (!write_file_all(out_path, out)){
            cerr << "Failed to write output file\n";
            return 1;
        }
        cout << "Encrypted and saved with IV and length in header.\n";
    } else if (choice == 2){
        string in_path, out_path, key;
        cout << "Enter path and name of encrypted file : ";
        getline(cin, in_path);
        cout << "Enter 8-byte key : ";
        getline(cin, key);
        cout << "Enter path and name to save after Decryption : ";
        getline(cin, out_path);
        string enc;
        if (!read_file_all(in_path, enc)) {
            cerr << "Failed to read input file\n";
            return 1;
        }
        if (enc.size() < 4 + 8 + 8 ||
            enc[0] != 'D' || enc[1] != 'C' || enc[2] != 'T' || enc[3] != 'S') {
            cerr << "Invalid or corrupted file header\n";
            return 1;
        }
        uint64_t plain_len = read_u64_le(enc, 4);
        string iv = enc.substr(12, 8);
        string ct = enc.substr(20);

        string pt = CBC_CTS_decrypt(ct, key, iv, plain_len);

        if (!write_file_all(out_path, pt)) {
            cerr << "Failed to write output file\n";
            return 1;
        }
        cout << "Decrypted and saved.\n";
    } else {
        cout << "Exiting...\n";
    }
    return 0;
}
