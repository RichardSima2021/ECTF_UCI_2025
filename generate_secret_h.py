import sys
import json

def gen_sec(file_name):

    """
    Generates a C header file `secret.h` based on the input JSON file.

    Args:
        file_name (str): The path to the JSON file containing channel data.

    Raises:
        FileNotFoundError: If the given JSON file doesn't exist.
    """

    try:
        with open(file_name) as json_file:

            # Reading the JSON content and parsing it into a dictionary
            content_string = json_file.read()
            json_data = json.loads(content_string)

            secret_h = f"""/* secret.h 
 * 
 * This header defines a secret structure (secret_t) to store various keys
 * and a checksum for different channels. The `init_secret` function 
 * initializes secret objects and writes them to flash memory.
 * 
 * Functions:
 * - write_secret: Writes a secret structure to flash memory.
 * - init_secret: Initializes the secret structures for all channels.
 * - memset: Set a block of memory to a specific value to clear memory
*/

#ifndef SECRET_H
#define SECRET_H

// Struct to hold channel-specific keys
typedef struct secret_t {{
    int channel_id;
    char mask_key[16];
    char msg_key[16];
    char data_key[16];
    char subscription_key[16];
    char check_sum[24];
}} secret_t;

// Takes a pointer to a secret_t structure and writes it to flash memory
void write_secret(secret_t* in_sec);

// Takes a pointer to the block of memory you want to set/clear,
// value you want to set the memory to, and number of bytes to set to the value
void* memset(void* dst, int value, size_t size);

// Initializes all secret_t structs for all channels
void init_secret()
{{
"""

            for channel_idx in json_data.get('channels', []):
                channel_data = json_data.get(f"channel_{channel_idx}")
                if channel_data:
                    secret_h += f"""
    secret_t channel_{channel_idx} = {{
        {channel_data.get('channel_ID', 0)},
        "{channel_data.get('mask_key', '')}",
        "{channel_data.get('msg_key', '')}",
        "{channel_data.get('data_key', '')}",
        "{channel_data.get('subscription_key', '')}",
        "{channel_data.get('check_sum', '')}"
    }};

    // Write to flash memory
    write_secret(&channel_{channel_idx});

    // Erase SRAM
    memset(&channel_{channel_idx}, 0, sizeof(secret_t));
"""

            secret_h += f"""
}}

#endif // SECRET_H
"""

            with open("secret.h", "w") as header_file:
                header_file.write(secret_h)
    
    except FileNotFoundError:
        print(f"File '{file_name}' doesn't exist.")


def main():
    
    """
    Entry point of the script. Checks if a valid JSON file path is provided as an argument
    and generates the `secret.h` header file if the argument is valid.

    Usage:
        python generate_secret_h.py <json_file_name>
    """

    if len(sys.argv) != 2:
        print("Usage: python generate_secret_h.py <json_file_name>")
    else:
        gen_sec(sys.argv[1])

if __name__ == "__main__":
    main()