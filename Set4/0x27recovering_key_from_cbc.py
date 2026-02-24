import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def pkcs7_pad(data, block_size=16):
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)

def pkcs7_unpad(data):
    pad_len = data[-1]
    return data[:-pad_len]

SHARED_KEY = os.urandom(16)

def encrypt_cbc_iv_is_key(plaintext):
    # Using key as IV (The vulnerability)
    cipher = Cipher(algorithms.AES(SHARED_KEY), modes.CBC(SHARED_KEY), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(pkcs7_pad(plaintext)) + encryptor.finalize()

def decrypt_and_check_ascii(ciphertext):
    cipher = Cipher(algorithms.AES(SHARED_KEY), modes.CBC(SHARED_KEY), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted = decryptor.update(ciphertext) + decryptor.finalize()
    
    for b in decrypted:
        if b > 127:
            raise Exception("High-ASCII detected!", decrypted)
    
    return pkcs7_unpad(decrypted)

def run_attack():
    print("[+] Starting Key Recovery Attack (IV=Key)...")
    # Each block is 16 bytes. 3 * 16 = 48 bytes.
    message = b"RECOVER_THE_KEY_FROM_CBC_WITH_IV_EQUALS_THE_KEY_!!!"
    ciphertext = encrypt_cbc_iv_is_key(message)
    
    # Modify the ciphertext: C_1, C_2, C_3 -> C_1, 0, C_1
    c1 = ciphertext[0:16]
    c2_zeros = b'\x00' * 16
    modified_ciphertext = c1 + c2_zeros + c1 + ciphertext[48:]
    print("[+] Submitting modified ciphertext to leak plaintext blocks...")
    try:
        decrypt_and_check_ascii(modified_ciphertext)
        print("[+] Attack failed: No high-ASCII detected.")
    except Exception as e:
        decrypted_raw = e.args[1]
        p_prime_1 = decrypted_raw[0:16]
        p_prime_3 = decrypted_raw[32:48]
        
        recovered_key = bytes([p1 ^ p3 for p1, p3 in zip(p_prime_1, p_prime_3)])
        
        print(f"\n[+] Recovered Key: {recovered_key.hex()}")
        print(f"[+] Original Key: {SHARED_KEY.hex()}")
        
        if recovered_key == SHARED_KEY:
            print("[+] Key matches perfectly.")

if __name__ == "__main__":
    run_attack()