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
    byte_seq = b"\x01\x00\x00\x00\x129\x99\xbd'x&\xc0\xcb\x9f\x93\xb9';KG\xda_\xbe\xe4=\xeb\x81j;e\x99\xf0\x06N'\x8d\xda\xae~\x12\x1d\xba\xe9\xd5%\x9c^Z2e\x82(\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01"
    
    # Convert to C array
    c_code = bytes_to_c_array(byte_seq, "data")

    # Print the generated C code
    print(c_code)
