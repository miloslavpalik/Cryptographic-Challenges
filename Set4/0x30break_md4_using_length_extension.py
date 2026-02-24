import struct

def left_rotate(n, b):
    return ((n << b) | (n >> (32 - b))) & 0xffffffff

class MD4:
    def __init__(self, h0=0x67452301, h1=0xefcdab89, h2=0x98badcfe, h3=0x10325476):
        self.h = [h0, h1, h2, h3]

    def _process(self, block):
        X = struct.unpack("<16I", block)
        a, b, c, d = self.h

        for i in range(16):
            k = i
            s = [3, 7, 11, 19][i % 4]
            f = (b & c) | (~b & d)
            a = left_rotate((a + f + X[k]) & 0xffffffff, s)
            a, b, c, d = d, a, b, c

        for i in range(16):
            k = (i // 4) + (i % 4) * 4
            s = [3, 5, 9, 13][i % 4]
            g = (b & c) | (b & d) | (c & d)
            a = left_rotate((a + g + X[k] + 0x5a827999) & 0xffffffff, s)
            a, b, c, d = d, a, b, c

        for i in range(16):
            k = [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15][i]
            s = [3, 9, 11, 15][i % 4]
            h = b ^ c ^ d
            a = left_rotate((a + h + X[k] + 0x6ed9eba1) & 0xffffffff, s)
            a, b, c, d = d, a, b, c

        self.h = [(x + y) & 0xffffffff for x, y in zip(self.h, [a, b, c, d])]

    def update(self, data):
        for i in range(0, len(data), 64):
            self._process(data[i:i+64])

    def digest(self):
        return struct.pack("<4I", *self.h)

def md4_padding(message_len):
    res = b'\x80'
    while (message_len + len(res)) % 64 != 56:
        res += b'\x00'
    res += struct.pack("<Q", message_len * 8)
    return res

def md4_mac(key, message):
    m = MD4()
    data = key + message
    m.update(data + md4_padding(len(data)))
    return m.digest()

def run_md4_attack():
    secret_key = b"applecore"
    original_msg = b"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
    original_mac = md4_mac(secret_key, original_msg)
    extension = b";admin=true"
    h_state = struct.unpack("<4I", original_mac)

    for key_len in range(1, 33):
        glue_padding = md4_padding(key_len + len(original_msg))
        total_len = key_len + len(original_msg) + len(glue_padding) + len(extension)
        attacker_md4 = MD4(*h_state)
        attacker_md4.update(extension + md4_padding(total_len))
        forged_mac = attacker_md4.digest()
        forged_msg = original_msg + glue_padding + extension

        if md4_mac(secret_key, forged_msg) == forged_mac:
            print(f"Key Length: {key_len}")
            print(f"Forged Message: {forged_msg}")
            print(f"Forged MAC: {forged_mac.hex()}")
            return

if __name__ == "__main__":
    run_md4_attack()