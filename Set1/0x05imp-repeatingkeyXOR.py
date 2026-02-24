def repeating_key_xor(plaintext, key):
    p_bytes = plaintext.encode('ascii')
    k_bytes = key.encode('ascii')
    
    result = []
    
    for i in range(len(p_bytes)):
        k_byte = k_bytes[i % len(k_bytes)]
        result.append(p_bytes[i] ^ k_byte)
    return bytes(result).hex()

stanza = (
    "Burning 'em, if you ain't quick and nimble\n"
    "I go crazy when I hear a cymbal"
)
key = "ICE"

encrypted = repeating_key_xor(stanza, key)
print(encrypted)