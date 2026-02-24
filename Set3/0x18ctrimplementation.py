import struct
import base64
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

ciphertext_b64 = "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=="
key = b"YELLOW SUBMARINE"
ciphertext = base64.b64decode(ciphertext_b64)

plaintext = aes_ctr_transform(ciphertext, key, nonce=0)

print("[+] Decrypted message")
print(plaintext.decode('utf-8'))

original_text = b"Yo, VIP, Let's kick it!"
ct = aes_ctr_transform(original_text, key, nonce=42)
pt = aes_ctr_transform(ct, key, nonce=42)
print(f"Original: {original_text}")
print(f"Reconstructed: {pt}")