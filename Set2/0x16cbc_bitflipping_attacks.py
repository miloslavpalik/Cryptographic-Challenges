import os
from Crypto.Cipher import AES

KEY = os.urandom(16)
IV = os.urandom(16)

def pkcs7_pad(data):
    pad_len = 16 - (len(data) % 16)
    return data + bytes([pad_len] * pad_len)

def pkcs7_unpad(data):
    padding_len = data[-1]
    if padding_len == 0 or padding_len > 16:
        raise ValueError("Invalid padding")
    return data[:-padding_len]

def encrypt_oracle(user_input):
    prefix = "comment1=cooking%20MCs;userdata="
    suffix = ";comment2=%20like%20a%20pound%20of%20bacon"
    
    # Quote out restricted characters
    safe_input = user_input.replace(';', '";"').replace('=', '"="')
    plaintext = (prefix + safe_input + suffix).encode()
    
    cipher = AES.new(KEY, AES.MODE_CBC, IV)
    return cipher.encrypt(pkcs7_pad(plaintext))

def is_admin(ciphertext):
    cipher = AES.new(KEY, AES.MODE_CBC, IV)
    decrypted = pkcs7_unpad(cipher.decrypt(ciphertext))
    return b";admin=true;" in decrypted


def bitflip_attack():
    # Inject ";admin=true;"
    # Use a placeholder that we can flip later.
    # Full block (16 bytes) to scramble so it doesn't break our target.
    # Block 1: comment1=cooking
    # Block 2: %20MCs;userdata=
    # Block 3: AAAAAAAAAAAAAAAA (This is the block we will corrupt)
    # Block 4: :admin<true:AAAA (This is our target block)
    
    target_data = ":admin<true:"
    payload = "A" * 16 + target_data
    ciphertext = bytearray(encrypt_oracle(payload))

    # Identify the blocks. 
    # Prefix "comment1=cooking%20MCs;userdata=" is 32 bytes (exactly 2 blocks).
    # Our 'A's start at block index 2 (byte 32).
    # Our target_data starts at block index 3 (byte 48).
    
    # Flip bits in Block 2 to change Block 3.
    # ':' (0x3a) ^ 1 = ';' (0x3b)
    # '<' (0x3c) ^ 1 = '=' (0x3d)
    
    # Flip byte at index 32 (starts our target block's ';' position)
    ciphertext[32] ^= 1
    # Flip byte at index 38 (starts our target block's '=' position)
    ciphertext[38] ^= 1
    # Flip byte at index 43 (starts our target block's ending ';' position)
    ciphertext[43] ^= 1

    print(f"Admin found: {is_admin(bytes(ciphertext))}")

if __name__ == "__main__":
    bitflip_attack()