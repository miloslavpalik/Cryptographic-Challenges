def detect_ecb(filename):
    with open(filename, 'r') as f:
        lines = f.readlines()

    for line_num, line in enumerate(lines):
        line = line.strip()
        block_size = 32
        blocks = [line[i:i+block_size] for i in range(0, len(line), block_size)]
        
        if len(set(blocks)) < len(blocks):
            print(f"[+] ECB mode found")
            print(f"[+] Line number: {line_num}")
            print(f"[+] Ciphertext: {line[:50]}...")
            
            import collections
            counts = collections.Counter(blocks)
            most_common = counts.most_common(1)[0]
            print(f"[+] A repeating block: {most_common[0]}")
            print(f"[+] Number of repetitions: {most_common[1]}")
            return line
detect_ecb('8.txt')