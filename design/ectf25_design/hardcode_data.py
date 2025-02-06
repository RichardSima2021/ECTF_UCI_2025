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
    byte_seq = b"\x01\x00\x00\x00d\x00\x00\x00\x00\x00\x00\x00\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01b|\xe5'\xa1\xc8\xea\x9b\x05\x82\x9a/\x19\x11k\xf6;\x02\x05\xff\x0e\xd9\xee\xd3\xc5\xf6\xcc\xbc\xea\x1e\x99?\x81\xd4{\xdaf\xd7\x02m\xe7U6\x1c|\xd3\xde4"

    # Convert to C array
    c_code = bytes_to_c_array(byte_seq, "data")

    # Print the generated C code
    print(c_code)
