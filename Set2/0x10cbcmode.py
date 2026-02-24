from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def xor_bytes(b1, b2):
    return bytes(a ^ b for a, b in zip(b1, b2))

def aes_ecb_decrypt_block(data, key):
    cipher = Cipher(algorithms.AES(key), modes.ECB())
    decryptor = cipher.decryptor()
    return decryptor.update(data) + decryptor.finalize()

def cbc_decrypt(ciphertext, key, iv):
    block_size = len(key)
    plaintext = b""
    prev_block = iv
    
    for i in range(0, len(ciphertext), block_size):
        current_block = ciphertext[i:i+block_size]
        
        decrypted_block = aes_ecb_decrypt_block(current_block, key)
        plaintext_block = xor_bytes(decrypted_block, prev_block)
        
        plaintext += plaintext_block
        prev_block = current_block
        
    return plaintext

import base64

key = b"YELLOW SUBMARINE"
iv = b"\x00" * 16

with open("10.txt", "r") as f:
    content = base64.b64decode(f.read())

result = cbc_decrypt(content, key, iv)
print(result.decode('ascii'))