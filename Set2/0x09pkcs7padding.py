def pkcs7_padding(data, block_size):
    padding_len = block_size - (len(data) % block_size)
    padding = bytes([padding_len] * padding_len)
    return data + padding

original_text = b"YELLOW SUBMARINE"
target_len = 20
padded_text = pkcs7_padding(original_text, target_len)

print(f"[+] Original: {original_text}")
print(f"[+] Padded:   {padded_text}")
