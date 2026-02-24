def pkcs7_unpad(data):
    if len(data) == 0:
        raise ValueError("Data is empty")
    
    if len(data) % 16 != 0:
        raise ValueError("Data length is not a multiple of 16")

    padding_len = data[-1]

    if padding_len == 0 or padding_len > 16:
        raise ValueError("Invalid padding value")

    padding_section = data[-padding_len:]
    for byte in padding_section:
        if byte != padding_len:
            raise ValueError("Invalid PKCS#7 padding")

    return data[:-padding_len]


test_cases = [
    (b"ICE ICE BABY\x04\x04\x04\x04", "Valid padding"),
    (b"ICE ICE BABY\x05\x05\x05\x05", "Invalid value"),
    (b"ICE ICE BABY\x01\x02\x03\x04", "Mixed values")
]

for data, description in test_cases:
    try:
        result = pkcs7_unpad(data)
        print(f"SUCCESS: {result}")
    except ValueError as e:
        print(f"ERROR: {e} for input {data}")