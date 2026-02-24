import base64
import os
import struct
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


def aes_ecb_encrypt(key, data):
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(data) + encryptor.finalize()

def aes_ctr_transform(data, key, nonce=0):
    block_size = 16
    output = bytearray()
    for i in range(0, len(data), block_size):
        block_count = i // block_size
        counter_block = struct.pack('<Q', nonce) + struct.pack('<Q', block_count)
        keystream = aes_ecb_encrypt(key, counter_block)
        chunk = data[i:i + block_size]
        for j in range(len(chunk)):
            output.append(chunk[j] ^ keystream[j])
    return bytes(output)

def score_english(b_str):
    etaoin = b"etaoinshrdlu "
    score = 0
    for b in b_str.lower():
        if b in etaoin:
            score += 1
        if (b < 32 or b > 126) and b != 10 and b != 13:
            score -= 10
    return score

def solve_single_byte_xor(ciphertext_column):
    best_byte = 0
    highest_score = -float('inf')
    
    for guess in range(256):
        decrypted = bytes([b ^ guess for b in ciphertext_column])
        current_score = score_english(decrypted)
        if current_score > highest_score:
            highest_score = current_score
            best_byte = guess
    return best_byte

with open("20.txt", "r") as f:
    lines = [base64.b64decode(line.strip()) for line in f if line.strip()]

key = os.urandom(16)
ciphertexts = [aes_ctr_transform(line, key, 0) for line in lines]

min_length = min(len(c) for c in ciphertexts)
truncated_ciphertexts = [c[:min_length] for c in ciphertexts]

recovered_keystream = bytearray()

for i in range(min_length):
    column = [c[i] for c in truncated_ciphertexts]
    keystream_byte = solve_single_byte_xor(column)
    recovered_keystream.append(keystream_byte)

for c in truncated_ciphertexts:
    plaintext = bytes([c[j] ^ recovered_keystream[j] for j in range(len(c))])
    print(plaintext.decode('utf-8', errors='replace'))