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

def get_sha1_padding(message_byte_len):
    bit_len = message_byte_len * 8
    padding = b'\x80'
    while (message_byte_len + len(padding)) % 64 != 56:
        padding += b'\x00'
    padding += struct.pack('>Q', bit_len)
    return padding

def secret_prefix_mac(key, message):
    return sha1(key + message)

def run_attack():
    secret_key = b"cryptography" 
    original_msg = b"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
    original_mac = secret_prefix_mac(secret_key, original_msg).hex()
    extension = b";admin=true"
    h = struct.unpack('>5I', bytes.fromhex(original_mac))

    for guessed_key_len in range(1, 33):
        glue_padding = get_sha1_padding(guessed_key_len + len(original_msg))
        total_len = guessed_key_len + len(original_msg) + len(glue_padding) + len(extension)
        
        forged_mac_bytes = sha1(extension, h0=h[0], h1=h[1], h2=h[2], h3=h[3], h4=h[4], length=total_len)
        forged_mac = forged_mac_bytes.hex()
        forged_message = original_msg + glue_padding + extension
        
        if secret_prefix_mac(secret_key, forged_message).hex() == forged_mac:
            print(f"Key Length: {guessed_key_len}")
            print(f"Forged Message: {forged_message}")
            print(f"Forged MAC: {forged_mac}")
            return

if __name__ == "__main__":
    run_attack()