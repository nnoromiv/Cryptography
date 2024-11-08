def encrypt(message, key):
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

encrypted_message = encrypt(message=message, key=key)  
print(encrypted_message)

decrypted_message = decrypt(message=encrypted_message, key=key)
print(decrypted_message)
    