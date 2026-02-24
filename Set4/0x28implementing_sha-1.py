import struct

def left_rotate(n, b):
    return ((n << b) | (n >> (32 - b))) & 0xffffffff

def sha1(message, h0=0x67452301, h1=0xEFCDAB89, h2=0x98BADCFE, h3=0x10325476, h4=0xC3D2E1F0, length=None):
    if length is None:
        original_bit_len = len(message) * 8
    else:
        original_bit_len = length * 8

    msg = bytearray(message)
    msg.append(0x80)
    while len(msg) % 64 != 56:
        msg.append(0x00)
    msg += struct.pack('>Q', original_bit_len)

    for i in range(0, len(msg), 64):
        w = [0] * 80
        for j in range(16):
            w[j] = struct.unpack('>I', msg[i + j*4:i + j*4 + 4])[0]

        for j in range(16, 80):
            w[j] = left_rotate(w[j-3] ^ w[j-8] ^ w[j-14] ^ w[j-16], 1)

        a, b, c, d, e = h0, h1, h2, h3, h4

        for j in range(80):
            if 0 <= j <= 19:
                f = (b & c) | ((~b) & d)
                k = 0x5A827999
            elif 20 <= j <= 39:
                f = b ^ c ^ d
                k = 0x6ED9EBA1
            elif 40 <= j <= 59:
                f = (b & c) | (b & d) | (c & d)
                k = 0x8F1BBCDC
            elif 60 <= j <= 79:
                f = b ^ c ^ d
                k = 0xCA62C1D6

            temp = (left_rotate(a, 5) + f + e + k + w[j]) & 0xffffffff
            e, d, c, b, a = d, c, left_rotate(b, 30), a, temp

        h0 = (h0 + a) & 0xffffffff
        h1 = (h1 + b) & 0xffffffff
        h2 = (h2 + c) & 0xffffffff
        h3 = (h3 + d) & 0xffffffff
        h4 = (h4 + e) & 0xffffffff

    return struct.pack('>5I', h0, h1, h2, h3, h4)

def secret_prefix_mac(key, message):
    return sha1(key + message)

def verify_mac(key, message, mac):
    return secret_prefix_mac(key, message) == mac

if __name__ == "__main__":
    key = b"YELLOW SUBMARINE"
    message = b"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
    
    mac = secret_prefix_mac(key, message)
    print(f"MAC: {mac.hex()}")
    
    is_valid = verify_mac(key, message, mac)
    print(f"Valid: {is_valid}")
    
    tampered_message = message + b";admin=true"
    is_tampered_valid = verify_mac(key, tampered_message, mac)
    print(f"Tampered Valid: {is_tampered_valid}")