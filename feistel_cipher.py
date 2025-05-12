"""
A Python module implementing a Feistel-product cipher built from three classical algorithms:
1. Caesar cipher (with arbitrary shift),
2. Columnar transposition cipher,
3. Vigenère cipher (with repeating key).

This module provides:
  - encrypt_block(block: bytes, master_key: bytes) -> bytes
  - decrypt_block(block: bytes, master_key: bytes) -> bytes
  - File-level encryption/decryption functions.
  - A master key generator.

The plaintext is processed in 32-byte blocks (padded with null bytes).
A 16-round Feistel network is used where each round subkey is derived from the
master key mixed with the round index.
"""

import os
import secrets
from typing import List, Tuple

# Helper functions for basic ciphers

def caesar_cipher(data: bytes, offset: int) -> bytes:
    """Shift each byte by offset modulo 256."""
    return bytes((b + offset) % 256 for b in data)

def columnar_transposition_encrypt(data: bytes, key: List[int]) -> bytes:
    """
    Encrypt data using a basic columnar transposition cipher.
    The key (list of ints) defines the column order.
    """
    num_cols = len(key)
    # Split data into rows of num_cols; pad last row if needed.
    rows = []
    for i in range(0, len(data), num_cols):
        row = list(data[i:i + num_cols])
        if len(row) < num_cols:
            row += [0] * (num_cols - len(row))
        rows.append(row)
    # Determine column order based on sorted key indices.
    order = sorted(range(num_cols), key=lambda i: key[i])
    cipher_bytes = []
    for col in order:
        for row in rows:
            cipher_bytes.append(row[col])
    return bytes(cipher_bytes)

def columnar_transposition_decrypt(data: bytes, key: List[int]) -> bytes:
    """
    Decrypt data encrypted with the columnar transposition cipher.
    """
    num_cols = len(key)
    num_rows = len(data) // num_cols
    order = sorted(range(num_cols), key=lambda i: key[i])
    # Prepare grid to hold the transposed data.
    grid = [[0] * num_cols for _ in range(num_rows)]
    index = 0
    for col in order:
        for row in range(num_rows):
            grid[row][col] = data[index]
            index += 1
    plain_bytes = []
    for row in grid:
        plain_bytes.extend(row)
    return bytes(plain_bytes)

def vigenere_cipher(data: bytes, key: bytes) -> bytes:
    """Encrypt data using Vigenère cipher with repeating key."""
    key_len = len(key)
    return bytes((data[i] + key[i % key_len]) % 256 for i in range(len(data)))

def vigenere_decipher(data: bytes, key: bytes) -> bytes:
    """Decrypt data using Vigenère cipher with repeating key."""
    key_len = len(key)
    return bytes((data[i] - key[i % key_len]) % 256 for i in range(len(data)))

def derive_subkey(master_key: bytes, round_index: int) -> bytes:
    """
    Derive a subkey for the given round from the master_key.
    Mix each byte with its index and the round index.
    """
    return bytes(((b + round_index + i) % 256) for i, b in enumerate(master_key))

def get_subkey_parts(subkey: bytes) -> Tuple[int, List[int], bytes]:
    """
    Split the subkey into three parts:
      - Caesar shift offset (first byte)
      - Columnar transposition key (next 4 bytes as list of ints)
      - Vigenère key (next 4 bytes)
    If subkey is shorter than 9 bytes, it is cycled.
    """
    def get_bytes(start: int, count: int) -> bytes:
        return bytes(subkey[(start + i) % len(subkey)] for i in range(count))
    caesar = subkey[0]
    col_bytes = get_bytes(1, 4)
    num_key = list(col_bytes)
    vig_key = get_bytes(5, 4)
    return caesar, num_key, vig_key

def f_function(data: bytes, subkey: bytes) -> bytes:
    """
    The round function F:
      a) Apply Caesar cipher.
      b) Apply columnar transposition.
      c) Apply Vigenère cipher.
    """
    caesar_offset, num_key, vig_key = get_subkey_parts(subkey)
    step1 = caesar_cipher(data, caesar_offset)
    step2 = columnar_transposition_encrypt(step1, num_key)
    step3 = vigenere_cipher(step2, vig_key)
    return step3

# Feistel network block functions

def encrypt_block(block: bytes, master_key: bytes) -> bytes:
    """
    Encrypt a 32-byte block using a 16-round Feistel network.
    If the block is shorter than 32 bytes, it is padded with null bytes.
    The final ciphertext is produced as: (R_final || L_final)
    """
    if len(block) < 32:
        block = block.ljust(32, b'\x00')
    else:
        block = block[:32]
    L = block[:16]
    R = block[16:]
    for round_index in range(16):
        subkey = derive_subkey(master_key, round_index)
        F_out = f_function(R, subkey)
        # Use only 16 bytes from F_out (in case F_out is longer)
        F_part = F_out[:16]
        new_L = R
        new_R = bytes(l ^ f for l, f in zip(L, F_part))
        L, R = new_L, new_R
    # Final swap to complete the Feistel structure
    return R + L

def decrypt_block(block: bytes, master_key: bytes) -> bytes:
    """
    Decrypt a 32-byte block using a 16-round Feistel network.
    It expects the block to be in the form: (R_final || L_final)
    """
    if len(block) < 32:
        block = block.ljust(32, b'\x00')
    else:
        block = block[:32]
    # Swap halves before reversing rounds
    R = block[:16]
    L = block[16:]
    for round_index in reversed(range(16)):
        subkey = derive_subkey(master_key, round_index)
        F_out = f_function(L, subkey)
        F_part = F_out[:16]
        new_R = L
        new_L = bytes(r ^ f for r, f in zip(R, F_part))
        R, L = new_R, new_L
    return L + R

# File I/O and block processing functions

def load_file(filepath: str) -> bytes:
    """Load a binary file and return its contents."""
    with open(filepath, 'rb') as f:
        return f.read()

def write_file(filepath: str, data: bytes) -> None:
    """Write binary data to a file."""
    with open(filepath, 'wb') as f:
        f.write(data)

def process_blocks(data: bytes, master_key: bytes, block_func) -> bytes:
    """
    Process the given data block by block (32-byte each) using the specified block_func.
    Blocks shorter than 32 bytes are padded with null bytes.
    """
    out_bytes = bytearray()
    for i in range(0, len(data), 32):
        block = data[i:i + 32]
        processed = block_func(block, master_key)
        out_bytes.extend(processed)
    return bytes(out_bytes)

def encrypt_file(in_filepath: str, out_filepath: str, master_key: bytes) -> None:
    """
    Read the binary file at in_filepath, encrypt all 32-byte blocks,
    and write the encrypted data to out_filepath.
    """
    data = load_file(in_filepath)
    encrypted = process_blocks(data, master_key, encrypt_block)
    write_file(out_filepath, encrypted)

def decrypt_file(in_filepath: str, out_filepath: str, master_key: bytes) -> None:
    """
    Read the binary file at in_filepath, decrypt all 32-byte blocks,
    and write the decrypted data to out_filepath.
    """
    data = load_file(in_filepath)
    decrypted = process_blocks(data, master_key, decrypt_block)
    write_file(out_filepath, decrypted)

def generate_master_key(length: int) -> bytes:
    """
    Generate a random master key of the specified length (in bytes).
    Uses the secrets module for cryptographically strong randomness.
    """
    return secrets.token_bytes(length)

if __name__ == "__main__":
    # Example usage:
    import sys

    if len(sys.argv) < 4:
        print("Usage: python feistel_cipher.py <encrypt|decrypt> <input_file> <output_file>")
        print("Generating a random master key of 16 bytes for demonstration.")
        master_key = generate_master_key(16)
        print(f"Random key (hex): {master_key.hex()}")
    else:
        mode = sys.argv[1]
        in_file = sys.argv[2]
        out_file = sys.argv[3]
        # For demo purposes, generate a 16-byte key (in practice, store or derive it securely)
        master_key = generate_master_key(16)
        print(f"Using master key (hex): {master_key.hex()}")

        if mode == "encrypt":
            encrypt_file(in_file, out_file, master_key)
            print(f"File encrypted and saved to {out_file}")
        elif mode == "decrypt":
            decrypt_file(in_file, out_file, master_key)
            print(f"File decrypted and saved to {out_file}")
        else:
            print("Invalid mode. Use 'encrypt' or 'decrypt'.")