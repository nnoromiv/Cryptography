def encrypt(message, key):
    """
    The function `encrypt` takes a message and a key, cleans the input message, applies a Caesar cipher
    encryption using the key, and returns the encrypted message formatted in groups of five characters.
    
    :param message: The `message` parameter in the `encrypt` function is the text that you want to
    encrypt using a key. It can contain alphabetic characters and spaces. The function will clean the
    input message by removing spaces and non-alphabetic characters before encryption
    :param key: The key is used to determine the shift amount for each character in the message during
    encryption. It is a string containing only alphabetic characters that will be used cyclically to
    shift the characters in the message
    :return: The `encrypt` function takes a message and a key as input, cleans the message by removing
    spaces and non-alphabet characters, and then encrypts the message using a Caesar cipher with a key.
    The encrypted message is formatted into groups of 5 characters separated by spaces before being
    returned.
    """
    # Cleaning the input message by removing spaces and non-alphabet characters
    plain_text = ''.join([char.lower() for char in message if char.isalpha()])
    key = ''.join([char.lower() for char in key if char.isalpha()])
    key_index = 0
    key_length = len(key)
    result = []
    
    for char in plain_text:
        # Get shift amount from corresponding key characters
        shift = ord(key[key_index % key_length]) - ord('a')

        # Applying Caeser's shift to current character
        new_char = chr((ord(char) - ord('a') + shift) % 26 + ord('a'))
        result.append(new_char)
        
        # Move to next letter in the key
        key_index += 1
            
    string =  ''.join(result)
    formatted_string = ' '.join(string[i:i+5] for i in range(0, len(string), 5))
    return formatted_string

def decrypt(message, key):
    """
    The function `decrypt` takes a message and a key, cleans the message by removing non-alphabet
    characters, decrypts the message using a Caesar cipher with a key, and returns the decrypted
    message.
    
    :param message: The `message` parameter in the `decrypt` function is the encrypted text that you
    want to decrypt using a given key. It should be a string containing the encrypted message that you
    want to decode
    :param key: The `key` parameter in the `decrypt` function is used as the key for decrypting the
    message. It is a string that is used to determine the shift amount for each character in the message
    during decryption. The key is cleaned by removing any non-alphabet characters and converting all
    characters to lowercase
    :return: The `decrypt` function returns the decrypted message after applying the Caesar cipher
    decryption algorithm using the provided key.
    """
    # Cleaning the input message by removing spaces and non-alphabet characters
    cipher_text = ''.join([char.lower() for char in message if char.isalpha()])
    key = ''.join([char.lower() for char in key if char.isalpha()])
    key_index = 0
    key_length = len(key)
    result = []
    
    for char in cipher_text:
        # Get shift amount from corresponding key characters
        shift = ord(key[key_index % key_length]) - ord('a')

        # Applying Caeser's shift to current character
        new_char = chr((ord(char) - ord('a') - shift) % 26 + ord('a'))
        result.append(new_char)
        
        # Move to next letter in the key
        key_index += 1
            
    string =  ''.join(result)
    return string
    
message = 'to be or not to be that is the question'
key = 'relations'

encrypted_message = encrypt(message, key)  
print(encrypted_message)

decrypted_message = decrypt(encrypted_message, key)
print(decrypted_message)
    