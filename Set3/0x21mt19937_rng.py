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