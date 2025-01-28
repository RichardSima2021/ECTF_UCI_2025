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

# ------------------------------------------------- Start of generating initial information ------------------------------------------------- #

            secret_h = f"""/* secret.h 
 * 
 * This header defines a secret structure (secret_t) to store various keys
 * and a checksum for different channels. The `init_secret` function 
 * initializes secret objects and writes them to flash memory.
 * 
 * Functions:
 * - write_secret: Takes a pointer to a secret_t structure and writes it to flash memory.
 * - init_secret: Initializes the secret structures for all channels.
 * - memset: Takes a pointer to the block of memory that you want to set a specific value to.
 * - write_flash_key: Writes the flash key.
*/

#ifndef SECRET_H
#define SECRET_H

#include "string.h"
#include "types.h"
#include "advanced_flash.h"

// Initializes all secret_t structs for all channels
void init_secret()
{{
"""
# ------------------------------------------------- End of generating initial information --------------------------------------------------- #

# ------------------------------------------------- Start of generating structs ------------------------------------------------------------- #
            
            for channel_idx in json_data.get('channels', []): # Extract the available channels in form of [0, 1, 2, 3, etc], formatted as a list
                channel_data = json_data.get(f"channel_{channel_idx}")
                if channel_data:
                    secret_h += f"""
    secret_t channel_{channel_idx} = {{
        {channel_data.get('channel_ID', 0)},
        "{channel_data.get('mask_key', '').strip("b'")}",
        "{channel_data.get('msg_key', '').strip("b'")}",
        "{channel_data.get('data_key', '').strip("b'")}",
        "{channel_data.get('subscription_key', '').strip("b'")}",
        "{channel_data.get('check_sum', '').strip("b'")}"
    }};

    // Takes a pointer to a secret_t structure and writes it to flash memory
    write_secret(&channel_{channel_idx});

    // Takes a pointer to the block of memory you want to set/clear,
    // value you want to set the memory to, and number of bytes to set to the value
    memset(&channel_{channel_idx}, 0, sizeof(secret_t)); // Erase SRAM

"""
            # Write the "flash_key" to memory after all structs are written
            secret_h += f"""
    // Writes the flash key to memory
    write_flash_secret("{json_data.get('flash_key', '').strip("b'")}");
}}

#endif // SECRET_H
"""
# ------------------------------------------------- End of generating structs --------------------------------------------------------------- #

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