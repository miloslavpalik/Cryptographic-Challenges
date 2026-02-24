import time
import os
import struct
import random

class MersenneTwister:
    def __init__(self, seed):
        self.w, self.n, self.m, self.r = 32, 624, 397, 31
        self.a = 0x9908B0DF
        self.u, self.d = 11, 0xFFFFFFFF
        self.s, self.b = 7, 0x9D2C5680
        self.t, self.c = 15, 0xEFC60000
        self.l = 18
        self.f = 1812433253

        self.MT = [0] * self.n
        self.index = self.n
        self.MT[0] = seed & 0xffffffff
        for i in range(1, self.n):
            self.MT[i] = (self.f * (self.MT[i-1] ^ (self.MT[i-1] >> (self.w - 2))) + i) & 0xffffffff

    def extract_number(self):
        if self.index >= self.n:
            self.twist()
        y = self.MT[self.index]
        y ^= (y >> self.u) & self.d
        y ^= (y << self.s) & self.b
        y ^= (y << self.t) & self.c
        y ^= (y >> self.l)
        self.index += 1
        return y & 0xffffffff

    def twist(self):
        for i in range(self.n):
            lower_mask = (1 << self.r) - 1
            upper_mask = (~lower_mask) & 0xffffffff
            x = (self.MT[i] & upper_mask) + (self.MT[(i + 1) % self.n] & lower_mask)
            xA = x >> 1
            if x % 2 != 0:
                xA ^= self.a
            self.MT[i] = self.MT[(i + self.m) % self.n] ^ xA
        self.index = 0


def mt19937_stream_cipher(data, seed):
    mt = MersenneTwister(seed & 0xffff) 
    output = bytearray()
    current_bytes = []
    
    for i in range(len(data)):
        if i % 4 == 0:
            new_val = mt.extract_number()
            current_bytes = [
                (new_val >> 24) & 0xff,
                (new_val >> 16) & 0xff,
                (new_val >> 8) & 0xff,
                new_val & 0xff
            ]
        output.append(data[i] ^ current_bytes[i % 4])
    return bytes(output)

def break_mt_cipher(ciphertext):
    known_suffix = b'A' * 14
    print("\n[+] Brute-forcing 16-bit seed...")
    for seed in range(65536):
        trial_pt = mt19937_stream_cipher(ciphertext, seed)
        if trial_pt.endswith(known_suffix):
            return seed
    return None

def generate_token():
    now = int(time.time())
    mt = MersenneTwister(now)
    token = bytearray()
    for _ in range(4):
        val = mt.extract_number()
        token.extend(struct.pack('>I', val))
    return bytes(token)

def is_from_mt19937(token, window_seconds=1000):
    current_time = int(time.time())
    print(f"\n[+] Checking token in timestamp {window_seconds}s...")
    for t in range(current_time - window_seconds, current_time + 1):
        mt = MersenneTwister(t)
        test_token = bytearray()
        for _ in range(4):
            val = mt.extract_number()
            test_token.extend(struct.pack('>I', val))
        
        if bytes(test_token) == token:
            return True, t
    return False, None

if __name__ == "__main__":
    real_seed = random.randint(0, 65535)
    random_prefix = os.urandom(random.randint(5, 20))
    plaintext = random_prefix + b'A' * 14
    
    ciphertext = mt19937_stream_cipher(plaintext, real_seed)
    found_seed = break_mt_cipher(ciphertext)
    
    print(f"Results: Found seed {found_seed}, real seed was: {real_seed}")

    token = generate_token()
    is_valid, timestamp = is_from_mt19937(token)
    if is_valid:
        print(f"Token is valid. Generated timestamp: {timestamp}")
    else:
        print("Token not found in database.")