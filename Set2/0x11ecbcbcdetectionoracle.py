import os
import random
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def pkcs7_padding(data, block_size=16):
    padding_len = block_size - (len(data) % block_size)
    padding = bytes([padding_len] * padding_len)
    return data + padding

def xor_bytes(b1, b2):
    return bytes(a ^ b for a, b in zip(b1, b2))

def get_random_bytes(n):
    return os.urandom(n)

def encryption_oracle(user_input):
    key = get_random_bytes(16)
    
    prefix = get_random_bytes(random.randint(5, 10))
    suffix = get_random_bytes(random.randint(5, 10))
    
    plaintext = pkcs7_padding(prefix + user_input + suffix, 16)
    
    mode_choice = random.randint(0, 1)
    
    if mode_choice == 0:
        actual_mode = "ECB"
        cipher = Cipher(algorithms.AES(key), modes.ECB())
    else:
        actual_mode = "CBC"
        iv = get_random_bytes(16)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    
    return ciphertext, actual_mode

def detect_cipher_mode(ciphertext):
    blocks = [ciphertext[i:i+16] for i in range(0, len(ciphertext), 16)]
    
    if len(blocks) != len(set(blocks)):
        return "ECB"
    else:
        return "CBC"

if __name__ == "__main__":

    test_data = b"A" * 64
    
    success = 0
    for i in range(10):
        ciphertext, true_mode = encryption_oracle(test_data)
        detected_mode = detect_cipher_mode(ciphertext)
        
        status = "True" if true_mode == detected_mode else "Greška!"
        if true_mode == detected_mode: success += 1
        
        print(f"[+] {i+1}: Mode: {true_mode} | Detected: {detected_mode} -> {status}")
