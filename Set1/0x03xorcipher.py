import string

def score_english_text(text):
    frequencies = {
        'a': .0817, 'b': .0149, 'c': .0278, 'd': .0425, 'e': .1270, 'f': .0223,
        'g': .0202, 'h': .0609, 'i': .0697, 'j': .0015, 'k': .0077, 'l': .0403,
        'm': .0241, 'n': .0675, 'o': .0751, 'p': .0193, 'q': .0010, 'r': .0599,
        's': .0633, 't': .0906, 'u': .0276, 'v': .0098, 'w': .0236, 'x': .0015,
        'y': .0197, 'z': .0007, ' ': .1300 
    }
    
    score = 0
    for char in text.lower():
        score += frequencies.get(char, 0)
    return score

def single_byte_xor_cipher(hex_str):
    ciphertext = bytes.fromhex(hex_str)
    best_score = 0
    best_key = None
    best_plaintext = ""

    for key_candidate in range(256):
        decrypted_bytes = bytes([b ^ key_candidate for b in ciphertext])
        
        try:
            plaintext = decrypted_bytes.decode('utf-8')
            current_score = score_english_text(plaintext)
            
            if current_score > best_score:
                best_score = current_score
                best_key = key_candidate
                best_plaintext = plaintext
        except UnicodeDecodeError:
            continue

    return best_key, best_plaintext

hex_encoded = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
key, message = single_byte_xor_cipher(hex_encoded)

print(f"Key Found: {key} (Character: '{chr(key)}')")
print(f"Decrypted Message: {message}")