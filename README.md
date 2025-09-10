# DES Decryption (CBC with CTS Support)

## Overview
This project implements **DES decryption** in C++ using `std::bitset<64>` for block-level operations.  
Files are read in binary mode, decrypted block by block, and then written back to an output file.  
The implementation also supports **Cipher Block Chaining (CBC)** with **Ciphertext Stealing (CTS)** to handle inputs that are not multiples of 64 bits.

---

## How Decryption Works

1. **Open Encrypted File**
   - File is opened in binary mode using `std::ifstream`.
   - Data is processed in 8-byte blocks (64 bits).

2. **Convert Bytes → Bitset**
   - Each 8-byte chunk is converted into a `std::bitset<64>` for DES operations.
   - Enables bitwise permutation, XOR, and S-box substitution.

3. **DES Rounds (Reverse Keys)**
   - The decryption function runs **16 DES rounds** in reverse key order.
   - Uses the same Feistel structure as encryption.

4. **Apply CBC Mode (if enabled)**
   - Each decrypted block is XORed with the previous ciphertext block (or IV for the first block).
   - Ensures proper chaining across blocks.

5. **Ciphertext Stealing (CTS)**
   - If the final block is shorter than 8 bytes, CTS logic rearranges the last two blocks to avoid padding.
   - Guarantees the decrypted file matches the exact size of the original.

6. **Convert Bitset → Bytes**
   - The resulting `bitset<64>` is converted back into 8 raw bytes.

7. **Write Output File**
   - Decrypted data is written using `std::ofstream` in binary mode.
   - Output file matches the original plaintext file exactly.

---

## File Handling

- **Input:** `encrypted.bin` (raw DES-encrypted file)  
- **Output:** `decrypted.txt` (restored original file)  
- **Modes:** CBC + CTS supported  

---

## Core Functions

- `bitset<64> decrypt(const bitset<64> &cipher_block, const string &key)`  
  Runs 16 Feistel rounds in reverse.

- `toBitset64()`  
  Converts 8 bytes → `bitset<64>`.

- `fromBitset64()`  
  Converts `bitset<64>` → 8 bytes.

- `decrypt_file()`  
  Handles binary file I/O, block chaining, and CTS.
