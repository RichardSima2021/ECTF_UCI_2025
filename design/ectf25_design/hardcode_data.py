def bytes_to_c_array(byte_seq, var_name="data"):
    """
    Converts a Python byte sequence into a C-compatible uint8_t array declaration.
    
    :param byte_seq: The input byte sequence (bytes).
    :param var_name: The name of the C variable (default: "data").
    :return: A string containing the C array declaration.
    """
    # Convert each byte to its hexadecimal representation
    c_array = ", ".join(f"0x{b:02X}" for b in byte_seq)
    
    # Format as a valid C array declaration
    c_code = f"uint8_t {var_name}[] = {{ {c_array} }};"
    
    return c_code

# Example usage
if __name__ == "__main__":
    # Example byte sequence
    byte_seq = b'\x01\x00\x00\x00~\x1f\xc3I-65`\xa6\x93\xc51=H\xc7n3Gj\x8b@g\x89\x13&G\xfd\x84\x17\xd0<\x892\xce\xe7\x94\xb9\xb67wY\x1d]\x06\xed(\x07B\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01'
    # Convert to C array
    c_code = bytes_to_c_array(byte_seq, "data")

    # Print the generated C code
    print(c_code)
