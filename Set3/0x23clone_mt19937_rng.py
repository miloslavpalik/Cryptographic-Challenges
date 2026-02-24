class MersenneTwister:
    def __init__(self, seed):
        # Parameters for MT19937 (32-bit version)
        self.w, self.n, self.m, self.r = 32, 624, 397, 31
        self.a = 0x9908B0DF
        self.u, self.d = 11, 0xFFFFFFFF
        self.s, self.b = 7, 0x9D2C5680
        self.t, self.c = 15, 0xEFC60000
        self.l = 18
        self.f = 1812433253

        self.MT = [0] * self.n
        self.index = self.n
        self.MT[0] = seed
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


def untemper(y):
    # Parameters from MT19937 specification
    u, d = 11, 0xFFFFFFFF
    s, b = 7, 0x9D2C5680
    t, c = 15, 0xEFC60000
    l = 18

    # Invert y ^= (y >> l)
    y ^= (y >> l)

    # Invert y ^= (y << t) & c
    y ^= (y << t) & c

    # Invert y ^= (y << s) & b
    temp_y = y
    for _ in range(32 // 7):
        temp_y = y ^ ((temp_y << s) & b)
    y = temp_y

    # Invert y ^= (y >> u) & d
    temp_y = y
    for _ in range(32 // 11):
        temp_y = y ^ (temp_y >> u)
    y = temp_y

    return y & 0xffffffff

def clone_mt(original_mt):
    state = []
    for _ in range(624):
        output = original_mt.extract_number()
        state.append(untemper(output))
    
    cloned = MersenneTwister(0) 
    cloned.MT = state
    cloned.index = 624 
    return cloned

import os
random_seed = int.from_bytes(os.urandom(4), 'big')
original = MersenneTwister(random_seed)

print("[+] Generator cloning...")
cloned = clone_mt(original)

print("[+] Checking next 5 numbers:")
for i in range(5):
    o = original.extract_number()
    c = cloned.extract_number()
    print(f"Original: {o} | Clone: {c} | Match: {o == c}")