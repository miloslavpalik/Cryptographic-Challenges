import base64

# Hamming Distance - The purpose is to count the number of differing bits (0s and 1s) between two blocks of data.
def hamming_distance(str1, str2):
    if isinstance(str1, str): str1 = str1.encode('ascii')
    if isinstance(str2, str): str2 = str2.encode('ascii')
    distance = 0
    for b1, b2 in zip(str1, str2):
        xor_result = b1 ^ b2
        distance += bin(xor_result).count('1')
    return distance
s1 = "Hi this is 0xPalik"
s2 = "Super random"
assert hamming_distance(s1, s2) == 37, "Hamming distance function is not working properly!"

# Finding KEYSIZE - We test possible lengths (2–40) to see which one results in the most similar blocks. 
# Normalization (dividing distance by KEYSIZE) is crucial here because it allows a fair comparison between a 
# small key (size 2) and a large key (size 29). The lowest score points to the most probable key length.
def find_best_keysizes(ciphertext, min_size=2, max_size=40):
    results = []
    for keysize in range(min_size, max_size + 1):
        block1 = ciphertext[0 : keysize]
        block2 = ciphertext[keysize : keysize*2]
        block3 = ciphertext[keysize*2 : keysize*3]
        block4 = ciphertext[keysize*3 : keysize*4]
        
        d1 = hamming_distance(block1, block2)
        d2 = hamming_distance(block2, block3)
        d3 = hamming_distance(block3, block4)
        
        avg_distance = (d1 + d2 + d3) / 3
        normalized_distance = avg_distance / keysize
        results.append((keysize, normalized_distance))
    
    results.sort(key=lambda x: x[1])
    return results[:3]

try:
    with open('6.txt', 'r') as f:
        raw_ciphertext = base64.b64decode(f.read())

    top_keys = find_best_keysizes(raw_ciphertext)

    print("--- KEYSIZE ---")
    for keysize, score in top_keys:
        print(f"[+] Length: {keysize} bytes, Score: {score:.4f}")

except FileNotFoundError:
    print("Error: File 6.txt not found in folder.")

# Transporting: This is the "divide and conquer" step. Since we know the key length (29), we group every 1st byte of every block together,
# every 2nd byte together, and so on. This transforms one complex cipher into 29 simple Single-byte XOR problems.
def solve_single_byte_xor(ciphertext):
    freqs = {'a': .0817, 'b': .0149, 'c': .0278, 'd': .0425, 'e': .1270, 'f': .0223, 'g': .0202, 'h': .0609, 'i': .0697, 'j': .0015, 'k': .0077, 'l': .0403, 'm': .0241, 'n': .0675, 'o': .0751, 'p': .0193, 'q': .0010, 'r': .0599, 's': .0633, 't': .0906, 'u': .0276, 'v': .0098, 'w': .0236, 'x': .0015, 'y': .0197, 'z': .0007, ' ': .1300}
    
    best_key = 0
    max_score = -1
    
    for key in range(256):
        score = 0
        for b in ciphertext:
            decoded_char = chr(b ^ key).lower()
            score += freqs.get(decoded_char, 0)
        
        if score > max_score:
            max_score = score
            best_key = key
    return best_key

KEYSIZE = 29
blocks = [[] for _ in range(KEYSIZE)]

for i, byte in enumerate(raw_ciphertext):
    blocks[i % KEYSIZE].append(byte)

full_key = []
for b in blocks:
    key_part = solve_single_byte_xor(bytes(b))
    full_key.append(key_part)

key_string = "".join(chr(k) for k in full_key)
print(f"\n[+] Key found: {key_string}")

def decrypt_repeating_xor(ciphertext, key):
    res = []
    for i in range(len(ciphertext)):
        res.append(ciphertext[i] ^ key[i % len(key)])
    return bytes(res)
# Reconstructing the Key -For each of the 29 groups, we find the single byte that produces the most "English" text (using letter frequency analysis).
# By putting these 29 best bytes back together in order, we recover the original repeating key.
final_text = decrypt_repeating_xor(raw_ciphertext, full_key)
print("\n[+] Message:\n")
print(final_text.decode('ascii'))