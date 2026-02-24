import base64
import os
from Crypto.Cipher import AES

RANDOM_KEY = os.urandom(16)
RANDOM_PREFIX = os.urandom(os.urandom(1)[0] % 64 + 1) 
SECRET_B64 = (
    "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg"
    "aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq"
    "dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg"
    "YnkK"
)
SECRET_BYTES = base64.b64decode(SECRET_B64)

def oracle(attacker_input):
    payload = RANDOM_PREFIX + attacker_input + SECRET_BYTES
    pad_len = 16 - (len(payload) % 16)
    payload += bytes([pad_len] * pad_len)
    
    cipher = AES.new(RANDOM_KEY, AES.MODE_ECB)
    return cipher.encrypt(payload)


def find_prefix_info():
    ct_long = oracle(b"A" * 48)
    
    target_idx = -1
    for i in range(0, len(ct_long) - 16, 16):
        if ct_long[i:i+16] == ct_long[i+16:i+32]:
            target_idx = i
            break
            
    for i in range(16):
        test_input = b"A" * i + b"A" * 32
        ct = oracle(test_input)
        if ct[target_idx:target_idx+16] == ct[target_idx+16:target_idx+32]:
            return target_idx, i
            
    return target_idx, 0


def solve():
    print("[+] Analyse oracle...")
    
    prefix_end, bridge_len = find_prefix_info()
    if prefix_end == -1:
        print("[!] Greška: Nije moguće detektovati ECB mod ili prefiks.")
        return


    decoded = b""
    total_expected_len = len(oracle(b"")) - prefix_end

    while True:
        current_pad_len = 15 - (len(decoded) % 16)
        filler = b"A" * bridge_len + b"A" * current_pad_len
        
        ct_reference = oracle(filler)
        
        target_block_start = prefix_end + (len(decoded) // 16) * 16
        target_block = ct_reference[target_block_start : target_block_start + 16]
        
        found_byte = False
        for i in range(256):
            test_input = filler + decoded + bytes([i])
            ct_test = oracle(test_input)
            
            if ct_test[target_block_start : target_block_start + 16] == target_block:
                decoded += bytes([i])
                try:
                    char = bytes([i]).decode()
                    if char.isprintable(): print(char, end="", flush=True)
                    else: print(".", end="", flush=True)
                except:
                    print(".", end="", flush=True)
                
                found_byte = True
                break
        
        if not found_byte:
            break

    print("\n\n[+] Decoded message:\n")
    final_text = decoded.decode(errors='ignore')
    print(final_text)

if __name__ == "__main__":
    solve()