import string

def score_english_text(text):
    frequencies = {
        'a': .0817, 'b': .0149, 'c': .0278, 'd': .0425, 'e': .1270, 'f': .0223,
        'g': .0202, 'h': .0609, 'i': .0697, 'j': .0015, 'k': .0077, 'l': .0403,
        'm': .0241, 'n': .0675, 'o': .0751, 'p': .0193, 'q': .0010, 'r': .0599,
        's': .0633, 't': .0906, 'u': .0276, 'v': .0098, 'w': .0236, 'x': .0015,
        'y': .0197, 'z': .0007, ' ': .1300
    }
    return sum(frequencies.get(char.lower(), 0) for char in text)

def solve_challenge_4(filename):
    best_overall_score = 0
    winner = {
        'text': None,
        'line_no': None,
        'key': None
    }

    try:
        with open(filename, 'r') as f:
            lines = f.readlines()
    except FileNotFoundError:
        return "File doesn't exists."

    for line_idx, hex_line in enumerate(lines):
        hex_line = hex_line.strip()
        ciphertext = bytes.fromhex(hex_line)
        
        for key in range(256):
            candidate_bytes = bytes([b ^ key for b in ciphertext])
            
            try:
                candidate_text = candidate_bytes.decode('ascii')
                current_score = score_english_text(candidate_text)

                if current_score > best_overall_score:
                    best_overall_score = current_score
                    winner['text'] = candidate_text.strip()
                    winner['line_no'] = line_idx + 1
                    winner['key'] = key
            except UnicodeDecodeError:
                continue
                
    return winner

result = solve_challenge_4('4.txt')

if isinstance(result, dict):
    print(f"--- Solution ---")
    print(f"Line in the file: {result['line_no']}")
    print(f"Key (decimal): {result['key']} (character: '{chr(result['key'])}')")
    print(f"Message: {result['text']}")
else:
    print(result)