import os
import base64
import random
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

class PaddingOracleServer:
    def __init__(self):
        self._key = os.urandom(16)  
        self.block_size = 16
        self.strings = [
            "MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
            "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
            "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
            "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
            "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
            "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
            "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
            "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
            "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
            "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93"
        ]

    def pkcs7_pad(self, data):
        pad_len = self.block_size - (len(data) % self.block_size)
        return data + bytes([pad_len] * pad_len)

    def encrypt_random_string(self):
        raw_string = base64.b64decode(random.choice(self.strings))
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(self._key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ct = encryptor.update(self.pkcs7_pad(raw_string)) + encryptor.finalize()
        return ct, iv

    def padding_oracle(self, ciphertext, iv):
        cipher = Cipher(algorithms.AES(self._key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        try:
            pt_padded = decryptor.update(ciphertext) + decryptor.finalize()
            pad_len = pt_padded[-1]
            if pad_len < 1 or pad_len > 16: return False
            return pt_padded.endswith(bytes([pad_len] * pad_len))
        except:
            return False

def decrypt_block(oracle_func, target_block, prev_block):
    intermediate_state = [0] * 16
    decrypted_block = [0] * 16
    
    for i in range(15, -1, -1):
        padding_val = 16 - i
        suffix = bytes([intermediate_state[j] ^ padding_val for j in range(i + 1, 16)])
        
        for byte_guess in range(256):
            prefix = os.urandom(i)
            test_iv = prefix + bytes([byte_guess]) + suffix
            
            if oracle_func(target_block, test_iv):
                if padding_val == 1:
                    test_iv_check = prefix[:-1] + bytes([(prefix[-1] + 1) % 256]) + bytes([byte_guess]) + suffix
                    if not oracle_func(target_block, test_iv_check):
                        continue
                
                intermediate_state[i] = byte_guess ^ padding_val
                decrypted_block[i] = intermediate_state[i] ^ prev_block[i]
                break
            
    return bytes(decrypted_block)

def pkcs7_unpad(data):
    pad_len = data[-1]
    return data[:-pad_len]

def run_attack():
    server = PaddingOracleServer()
    ciphertext, iv = server.encrypt_random_string()
    
    blocks = [iv] + [ciphertext[i:i+16] for i in range(0, len(ciphertext), 16)]
    recovered_full = b""
    
    for i in range(1, len(blocks)):
        print(f"Decripting block {i} from {len(blocks)-1}...")
        recovered_full += decrypt_block(server.padding_oracle, blocks[i], blocks[i-1])

    final_msg = pkcs7_unpad(recovered_full)
    print(f"Decripted: {final_msg.decode('utf-8', errors='ignore')}")

if __name__ == "__main__":
    run_attack()