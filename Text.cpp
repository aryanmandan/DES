#include<bits/stdc++.h>
#include "tables.cpp"
using namespace std;

vector<bitset<48>> keys;                     // Store round keys

const string base64_chars="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

string string_to_base64(const string &input){         // For output in base 64
    string output;
    int val=0, valb=-6;
    for (unsigned char c : input){
        val = (val<<8)+c;
        valb+=8;
        while (valb>=0){
            output.push_back(base64_chars[(val>>valb)&0x3F]);
            valb -= 6;
        }
    }
    if (valb>-6) output.push_back(base64_chars[((val<<8)>>(valb+8))&0x3F]);
    while (output.size()%4) output.push_back('=');
    return output;
}

string base64_to_string(const string &input){
    vector<int> T(256,-1);
    for (int i=0;i<64;i++) T[base64_chars[i]]=i;

    string output;
    int val=0, valb=-8;
    for (unsigned char c : input){
        if (T[c]==-1) break; 
        val=(val<<6)+T[c];
        valb+=6;
        if (valb>=0){
            output.push_back(char((val>>valb)&0xFF));
            valb-=8;
        }
    }
    return output;
}

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

pair<bitset<32>,bitset<32>> block_split(const bitset<64> &x64 ){   // split plaintext bits into two blocks
    bitset<32> L;
    bitset<32>R;
    for(int i=0;i<32;++i){
        L[i]=x64[i];
        R[i]=x64[i+32];
    }
    return {L,R};
}

pair<bitset<28>,bitset<28>> round_key_gen_split(const bitset<64> &key){ 
    bitset<56> r_key=p_box<56,64>(key,PC1);
                   // Key generation with splitting into C,D
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

int main() {
    string input,key;
    int choice;
    cout<<"\n==================Data Encryption Standard (DES)==================\n";
    cout<<"|  1. Encrypt                                                    |\n";
    cout<<"|  2. Decrypt                                                    |\n";
    cout<<"|  0. Exit                                                       |\n";
    cout<<"==================================================================\n";
    while(true){
        cout<<"\nEnter your choice : ";
        cin>>choice;
        cin.ignore();
        switch(choice){
            case 1:{
                cout<<"Enter plaintext : ";
                getline(cin,input);
                cout<<"Enter 8-byte key : ";
                getline(cin,key);
                if(key.length()!=8){
                    cout<<"Key must be exactly 8 bytes.\n";
                    break;
                }
                cout<<"Enter IV (8 characters, exactly 8 bytes) : ";
                string IV;
                getline(cin,IV);
                if(IV.size()!=8){
                    cout<<"IV must be exactly 8 bytes for DES-CBC.\n";
                    break;
                }
                string ciphertext=CBC_CTS_encrypt(input,key,IV);
                cout<<"Ciphertext (Base64) : "<<string_to_base64(ciphertext)<<endl;
                break;
            }
            case 2:{ 
                cout << "Enter ciphertext (Base64) : ";
                getline(cin, input);
                cout << "Enter IV (8 characters, exactly 8 bytes) : ";
                string IV;
                getline(cin, IV);
                cout << "Enter original plaintext length : ";
                unsigned long long len;
                cin>>len;
                cin.ignore();
                cout << "Enter 8-byte key : ";
                getline(cin, key);
                if(key.length() != 8){
                    cout<<"Key must be exactly 8 bytes.\n";
                    break;
                }
                if(IV.size()!=8){
                    cout<< "IV must be exactly 8 bytes for DES-CBC.\n";
                    break;
                }
                string ciphertext=base64_to_string(input);
                string decrypted_plain=CBC_CTS_decrypt(ciphertext,key,IV,len);
                cout<<"Decrypted plaintext : "<<decrypted_plain<<endl;
                break;
            }


            case 0:{
                cout<<"Exiting...\n";
                return 0;
            }
            default:{
                cout<<"Not a valid choice.\n";
                break;
            }
        }
    }
    return 0;
}