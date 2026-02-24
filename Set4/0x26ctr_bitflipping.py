import os
import struct
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

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

GLOBAL_KEY = os.urandom(16)

def encrypt_userdata(user_input):
    user_input = user_input.replace(';', '";"').replace('=', '"="')
    
    prefix = "comment1=cooking%20MCs;userdata="
    suffix = ";comment2=%20like%20a%20pound%20of%20bacon"
    
    full_string = prefix + user_input + suffix
    return aes_ctr_transform(full_string.encode(), GLOBAL_KEY)

def is_admin(ciphertext):
    decrypted = aes_ctr_transform(ciphertext, GLOBAL_KEY).decode('utf-8', errors='ignore')
    print(f"[Server] Decrypted result: {decrypted}")
    return ";admin=true;" in decrypted

def run_attack():
    payload = "?admin?true?"
    
    print(f"[+] Sending payload: {payload}")
    ciphertext = bytearray(encrypt_userdata(payload))
    offset = 32
    print("[+] Flipping bits in the ciphertext...")
    # Flip first '?' to ';'
    ciphertext[offset] ^= ord('?') ^ ord(';')
    # Flip second '?' to '='
    ciphertext[offset + 6] ^= ord('?') ^ ord('=')
    # Flip third '?' to ';'
    ciphertext[offset + 11] ^= ord('?') ^ ord(';')
    print("[+] Submitting modified ciphertext to server...")
    success = is_admin(bytes(ciphertext))
    
    if success:
        print("\n[+] You are now an admin!")
    else:
        print("\n[+] The admin flag was not found.")

if __name__ == "__main__":
    run_attack()