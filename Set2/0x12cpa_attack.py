import base64
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

GLOBAL_KEY = os.urandom(16)

def pkcs7_padding(data, block_size=16):
    padding_len = block_size - (len(data) % block_size)
    return data + bytes([padding_len] * padding_len)

def ecb_oracle(user_input):
    secret_padding = base64.b64decode(
        "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg"
        "aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq"
        "dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg"
        "YnkK"
    )
    plaintext = pkcs7_padding(user_input + secret_padding, 16)
    cipher = Cipher(algorithms.AES(GLOBAL_KEY), modes.ECB())
    encryptor = cipher.encryptor()
    return encryptor.update(plaintext) + encryptor.finalize()

def crack_ecb_secret():
    block_size = 16
    secret = b""
    
    total_len = len(ecb_oracle(b""))
    
    for i in range(total_len):
        padding_len = (block_size - 1 - (i % block_size))
        prefix = b"A" * padding_len
        
        target_output = ecb_oracle(prefix)
        block_start = (i // block_size) * block_size
        target_block = target_output[block_start : block_start + block_size]
        
        found = False
        for char_code in range(256):
            test_input = prefix + secret + bytes([char_code])
            test_output = ecb_oracle(test_input)
            test_block = test_output[block_start : block_start + block_size]
            
            if test_block == target_block:
                secret += bytes([char_code])
                found = True
                break
        
        if not found: 
            break
            
    return secret

decoded_secret = crack_ecb_secret()
print("[+] Secret:\n")
print(decoded_secret.decode('ascii'))