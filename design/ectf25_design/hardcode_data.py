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
    byte_seq = b'\x01\x00\x00\x00/u\x17sJ\xfa\x81eK\x1f\xcd\x10\x18\xc8\x7f\x05\r_\xe9\x0f\x9dSa6\x8fT\x05\xcae\xdd\xa1\xae\xd4\x97\xd69}K\x1ew*\xe4\xe4\xf2\x033\x99\xfe\xf3\x87\x0b\x183$\xa08>\xca\xd6S,\xea\xad\x99'
    
    # Convert to C array
    c_code = bytes_to_c_array(byte_seq, "data")

    # Print the generated C code
    print(c_code)
