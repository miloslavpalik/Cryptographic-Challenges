import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

KEY = os.urandom(16)

def pkcs7_padding(data, block_size=16):
    padding_len = block_size - (len(data) % block_size)
    return data + bytes([padding_len] * padding_len)

def parse_kv(string):
    res = {}
    for pair in string.split('&'):
        if '=' in pair:
            parts = pair.split('=')
            if len(parts) == 2: res[parts[0]] = parts[1]
    return res

def profile_for(email):
    email = email.replace('&', '').replace('=', '')
    return f"email={email}&uid=10&role=user"

def encrypt_profile(email):
    plaintext = profile_for(email).encode()
    padded = pkcs7_padding(plaintext)
    cipher = Cipher(algorithms.AES(KEY), modes.ECB())
    encryptor = cipher.encryptor()
    return encryptor.update(padded) + encryptor.finalize()

def decrypt_and_parse(ciphertext):
    cipher = Cipher(algorithms.AES(KEY), modes.ECB())
    decryptor = cipher.decryptor()
    decrypted = decryptor.update(ciphertext) + decryptor.finalize()
    padding_len = decrypted[-1]
    clean_text = decrypted[:-padding_len] if 0 < padding_len <= 16 else decrypted
    return parse_kv(clean_text.decode('utf-8', errors='ignore'))


admin_content = "admin" + (chr(11) * 11)
cipher_admin = encrypt_profile("AAAAAAAAAA" + admin_content)
admin_block = cipher_admin[16:32]

print("[+] Looking for the ideal email length...")

for i in range(1, 32):
    test_email = "A" * i
    cipher_base = encrypt_profile(test_email)
    for block_end in [32, 48]:
        if len(cipher_base) >= block_end:
            evil_ciphertext = cipher_base[0:block_end] + admin_block
            result = decrypt_and_parse(evil_ciphertext)
            
            role = result.get('role', '')
            if role == 'admin':
                print(f"\n[+] Found Email length: {i}, End of block: {block_end}")
                print(f"Final profile: {result}")
                exit()
            elif 'admin' in role:
                print(f"Length {i} role: {role}")