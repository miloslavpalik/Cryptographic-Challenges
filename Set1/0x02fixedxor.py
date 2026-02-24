def fixed_xor(hex_str1, hex_str2):
    buf1 = bytes.fromhex(hex_str1)
    buf2 = bytes.fromhex(hex_str2)
    
    if len(buf1) != len(buf2):
        raise ValueError("Buffers must be of equal length")
    xor_result = bytes([b1 ^ b2 for b1, b2 in zip(buf1, buf2)])
    
    return xor_result.hex()

input_1 = "1c0111001f010100061a024b53535009181c"
input_2 = "686974207468652062756c6c277320657965"
expected = "746865206b696420646f6e277420706c6179"

result = fixed_xor(input_1, input_2)

print(f"Result:   {result}")
print(f"Expected: {expected}")
print(f"Match:    {result == expected}")