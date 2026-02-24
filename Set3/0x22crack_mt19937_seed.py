import time
import random

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

if __name__ == "__main__":
    mt = MersenneTwister(42)
    print("1st 5 random numbers:")
    for _ in range(5):
        print(mt.extract_number())

def simulate_server_output():
    wait_before = random.randint(40, 1000)
    simulated_time = int(time.time()) + wait_before
    
    print(f"[+] Seed timestamp: {simulated_time}")
    mt = MersenneTwister(simulated_time)
    
    wait_after = random.randint(40, 1000)
    final_time = simulated_time + wait_after
    
    return mt.extract_number(), final_time

def crack_seed(first_output, current_timestamp):
    print(f"[+] Bruteforce: {current_timestamp}")
    
    for potential_seed in range(current_timestamp, current_timestamp - 2000, -1):
        test_mt = MersenneTwister(potential_seed)
        if test_mt.extract_number() == first_output:
            return potential_seed
    
    return None

output, end_time = simulate_server_output()
print(f"[+] Number from server: {output}")

found_seed = crack_seed(output, end_time)

if found_seed:
    print(f"\n[+] Seed found: {found_seed}")
else:
    print("\n[+] Seed not found.")