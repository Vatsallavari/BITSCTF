def rotate_right(x, r):
    """Rotate an 8-bit number x right by r bits."""
    return ((x >> r) | (x << (8 - r))) & 0xff

def inverse_transform(obf_bytes):
    """
    Given a bytes object containing the obfuscated data, return the original data.
    
    The obfuscation processes the input byte-by-byte in a cycle of four transformations:
      - Pos 0: (x + 0x13) XOR keyA (keyA cycles over [0x57, 0x21, 0x43, 0x99])
      - Pos 1: x multiplied by 2 (inverse: divide by 2, assuming even values)
      - Pos 2: rotate_left(x, r) where r comes from keyC ([1, 3, 5, 7]); inverse is rotate_right.
      - Pos 3: ~(x XOR keyB) with keyB cycling over [0xaa, 0xbb, 0xcc, 0xdd]; inverse is (~y) XOR keyB.
    """
    # Define the key arrays.
    keyA = [0x57, 0x21, 0x43, 0x99]  # used in transformation 0
    keyB = [0xaa, 0xbb, 0xcc, 0xdd]  # used in transformation 3
    keyC = [1, 3, 5, 7]             # used in transformation 2

    # Pointers (indices) into the key arrays.
    idxA = 0
    idxB = 0
    idxC = 0

    original = []  # will store the recovered bytes

    # Process each obfuscated byte.
    for i, y in enumerate(obf_bytes):
        pos = i % 4
        if pos == 0:
            # Inverse of: y = (x + 0x13) XOR keyA
            k = keyA[idxA]
            idxA = (idxA + 1) % 4
            # Compute: x = ((y XOR key) - 0x13) mod 256
            x = ((y ^ k) - 0x13) & 0xff
        elif pos == 1:
            # Inverse of: y = x * 2 mod 256.
            # Since multiplication by 2 is not bijective over 0-255,
            # we assume that the original x was in a range (e.g. ASCII) so that y is even.
            if y % 2 != 0:
                raise ValueError(f"Unexpected odd byte at position {i} for multiplication transform: {y}")
            x = y // 2
        elif pos == 2:
            # Inverse of: y = rotate_left(x, r) where r comes from keyC.
            r = keyC[idxC]
            idxC = (idxC + 1) % 4
            x = rotate_right(y, r)
        elif pos == 3:
            # Inverse of: y = ~(x XOR keyB)
            k = keyB[idxB]
            idxB = (idxB + 1) % 4
            x = ((~y) & 0xff) ^ k
        original.append(x)

    return bytes(original)

def main():
    # The obfuscated hex stream (validation stream) provided:
    hex_string = "02 92 a8 06 77 a8 32 3f 15 68 c9 77 de 86 99 7d 08 60 8e 64 77 be ba 74 26 96 e7 4e"
    
    # Remove any spaces and convert from hex to bytes.
    hex_string = hex_string.replace(" ", "")
    obfuscated_bytes = bytes.fromhex(hex_string)
    
    # Reverse the transformation.
    try:
        original_bytes = inverse_transform(obfuscated_bytes)
        # Try decoding as UTF-8 (or use 'latin-1' if preferred)
        original_str = original_bytes.decode('utf-8')
        print("Recovered string:", original_str)
    except Exception as e:
        print("Error during reversal:", e)
        print("Recovered bytes:", original_bytes)

if __name__ == '__main__':
    main()



"""BITSCTF{C4ND4C3_L0G1C_W0RK?}"""
