import base64
import struct
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def aes_ecb_decrypt(data, key):
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(data) + decryptor.finalize()

def aes_ecb_encrypt(data, key):
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(data) + encryptor.finalize()

def aes_ctr_transform(data, key, nonce=0):
    output = bytearray()
    for i in range(0, len(data), 16):
        counter_block = struct.pack('<Q', nonce) + struct.pack('<Q', i // 16)
        keystream = aes_ecb_encrypt(counter_block, key)
        
        chunk = data[i:i+16]
        for j in range(len(chunk)):
            output.append(chunk[j] ^ keystream[j])
    return bytes(output)

def edit(ciphertext, key, offset, newtext):
    plaintext = bytearray(aes_ctr_transform(ciphertext, key))
    plaintext[offset : offset + len(newtext)] = newtext
    return aes_ctr_transform(bytes(plaintext), key)

with open("25.txt", "rb") as f:
    b64_data = f.read().replace(b'\n', b'').replace(b'\r', b'')
    ciphertext_ecb = base64.b64decode(b64_data)

original_plaintext = aes_ecb_decrypt(ciphertext_ecb, b"YELLOW SUBMARINE")

secret_key = os.urandom(16)
ciphertext_ctr = aes_ctr_transform(original_plaintext, secret_key)

print("[+] Attack on CTR random access...")

null_payload = b'\x00' * len(ciphertext_ctr)
recovered_keystream = edit(ciphertext_ctr, secret_key, 0, null_payload)

recovered_plaintext = bytearray()
for i in range(len(ciphertext_ctr)):
    recovered_plaintext.append(ciphertext_ctr[i] ^ recovered_keystream[i])

print(recovered_plaintext.decode('utf-8', errors='ignore'))