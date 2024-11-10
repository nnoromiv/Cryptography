import string

"""
    1. Poly-alphabetic: has the ability to use multiple versions of a pre-defined alphabet 
    2. Blocked cipher: you need to encode parts of the message with equal length. Use padding if necessary. 
    3. Encoded key: You will need to also create a mechanism to encrypt and decrypt the key to the poly-alphabetic 
        cipher. You can add extra keys if that is needed. 
"""

class CustomCipher:
            
    def __init__(self, block_size=5) -> None:
        """
        This Python function initializes an object with an alphabet, shifted alphabets, and a block
        size.
        
        :param block_size: The `block_size` parameter in the `__init__` method is used to specify the
        size of blocks that will be used in the program. It has a default value of 5, but you can
        provide a different value when creating an instance of the class. This parameter determines how
        many characters, defaults to 5 (optional)
        """
        
        self.alphabet  = string.ascii_lowercase
        self.alphabets = [
            self.shift_alphabet(i) for i in range(len(self.alphabet))
        ]
        self.block_size = block_size
        
    def shift_alphabet(self, shift):
        """
        The function `shift_alphabet` shifts the alphabet by a specified amount.
        
        :param shift: The `shift` parameter in the `shift_alphabet` method represents the number of
        positions by which each letter in the alphabet should be shifted. This method takes the original
        alphabet and shifts each letter by the specified amount to create a new shifted alphabet
        :return: The function `shift_alphabet` returns a new alphabet string that has been shifted by
        the specified amount. The characters in the alphabet are shifted to the left by the `shift`
        amount, with characters that go beyond the end of the alphabet wrapping around to the beginning.
        """
        return self.alphabet[shift:] + self.alphabet[:shift]
    
    def padding(self, message):
        """
        The `padding` function in Python adds padding to a message to ensure its length is a multiple of
        the block size.
        
        :param message: The `padding` function takes a `message` as input and calculates the padding
        length needed to make the message a multiple of the block size. It then pads the message with
        'x' characters to achieve the desired length
        :return: The `padding` method is returning the original `message` with additional 'x' characters
        added to the end to ensure that the length of the message is a multiple of the `block_size`.
        """
        padding_length =(self.block_size - len(message) % self.block_size) % self.block_size
        return message + 'x' * padding_length
    
    def encrypt_block(self, block, key):
        """
        The function `encrypt_block` encrypts a block of text using a key and a substitution cipher.
        
        :param block: The `block` parameter in the `encrypt_block` function represents the block of text
        that you want to encrypt. It is a string that contains the characters to be encrypted
        :param key: The `key` parameter is used as the encryption key to shift the characters in the
        `block` parameter. It is used to determine the amount of shift for each character in the block
        during encryption. The key is repeated if its length is shorter than the block to be encrypted
        :return: The `encrypt_block` method returns the encrypted block of text after applying the
        encryption algorithm using the provided key.
        """
        encrypted_block = []
        
        for i, char in enumerate(block):
            if char in self.alphabet:
                shift_alphabet = self.alphabets[ord(key[i % len(key)]) % len(self.alphabet)]
                encrypted_block.append(shift_alphabet[self.alphabet.index(char)])
            else:
                encrypted_block.append(char)
                
        return ''.join(encrypted_block)
    
    def decrypt_block(self, block, key):
        """
        The function decrypts a block of text using a key and a substitution cipher algorithm.
        
        :param block: The `block` parameter in the `decrypt_block` method is a string representing a
        block of text that needs to be decrypted. It is processed character by character to decrypt the
        text using the provided `key`. Each character in the block is decrypted based on the
        corresponding character in the key
        :param key: The `key` parameter is the encryption key used to decrypt the `block` of text. It is
        used to determine the shifting of characters in the decryption process. The key is applied
        cyclically to the block of text to decrypt it character by character
        :return: The `decrypt_block` method returns the decrypted block of text after applying the
        decryption algorithm using the provided key.
        """
        decrypted_block = []
        
        for i, char in enumerate(block):
            if char in self.alphabet:
                shift_alphabet = self.alphabets[ord(key[i % len(key)]) % len(self.alphabet)]
                decrypted_block.append(self.alphabet[shift_alphabet.index(char)])
            else:
                decrypted_block.append(char)
                
        return ''.join(decrypted_block)
    
    def encode_key(self, key, master_key):
        """
        The function `encode_key` encodes a given key using a master key and a shift based on the master
        key's first character.
        
        :param key: The `key` parameter in the `encode_key` method is the original key that you want to
        encode. It is a string containing characters that you want to encode using a shift based on the
        `master_key`
        :param master_key: The `encode_key` method takes two parameters: `key` and `master_key`. The
        `key` parameter is the string that will be encoded, and the `master_key` parameter is used to
        determine the shift value for encoding the characters in the `key`
        :return: The `encode_key` method takes a `key` and a `master_key` as input parameters and
        encodes the `key` based on the `master_key`. It shifts each character in the `key` by a certain
        amount determined by the first character of the `master_key`. If a character in the `key` is in
        the alphabet defined in the class, it is shifted accordingly.
        """
        encoded_key = []
        shift = ord(master_key[0]) % len(self.alphabet)
        for char in key:
            if char in self.alphabet:
                new_char = self.alphabet[(self.alphabet.index(char) + shift) % len(self.alphabet)]
                encoded_key.append(new_char)
            else:
                encoded_key.append(char)
                
        return ''.join(encoded_key)
    
    def decode_key(self, encoded_key, master_key):
        """
        The `decode_key` function decodes an encoded key using a master key and a specific alphabet.
        
        :param encoded_key: The `encoded_key` parameter is the key that has been encoded and needs to be
        decoded using the `master_key`. The `decode_key` method takes the `encoded_key` and the
        `master_key` as input parameters and returns the decoded key. The decoding process involves
        shifting each character in the
        :param master_key: The `decode_key` method takes in an `encoded_key` and a `master_key` as
        parameters. The `master_key` is used to determine the shift value for decoding the
        `encoded_key`. The method then decodes the `encoded_key` using the shift value calculated from
        the `master
        :return: The `decode_key` method returns a decoded version of the `encoded_key` string using the
        `master_key` for shifting characters in the alphabet.
        """
        decoded_key = []
        shift = ord(master_key[0]) % len(self.alphabet)
        for char in encoded_key:
            if char in self.alphabet:
                new_char = self.alphabet[(self.alphabet.index(char) - shift) % len(self.alphabet)]
                decoded_key.append(new_char)
            else:
                decoded_key.append(char)
                
        return ''.join(decoded_key)
    
    def encrypt(self, message, key, master_key):
        """
        The function encrypts a message using a key and a master key, padding the message and encoding
        the key before encrypting it in blocks.
        
        :param message: The `message` parameter in the `encrypt` method is the text that you want to
        encrypt. It is the input data that you want to protect by converting it into a secret code using
        encryption techniques
        :param key: The `key` parameter in the `encrypt` method is used as a part of the encryption
        process. It is typically a secret value that is used to encrypt the message. In the context of
        the code snippet you provided, the `key` parameter is passed to the `encrypt_block` method along
        :param master_key: The `master_key` parameter is used as part of the encryption process to
        encode the key before encrypting the message. It is likely a secret key or passphrase that is
        used to derive the actual encryption key used in the encryption algorithm. This helps enhance
        the security of the encryption process by adding an additional
        :return: The `encrypt` method returns a tuple containing the encrypted message as a string with
        blocks separated by spaces, and the encoded key.
        """
        padded_message = self.padding(message)
        encoded_key = self.encode_key(key, master_key)
        
        encrypted_message =[]
        for i in range(0, len(padded_message), self.block_size):
            block = padded_message[i:i + self.block_size]
            encrypted_block = self.encrypt_block(block, key)
            encrypted_message.append(encrypted_block)
            
            
        return ' '.join(encrypted_message), encoded_key
    
    def decrypt(self, encrypted_message, encoded_key, master_key):
        """
        The function decrypts an encrypted message using a key decoded with a master key.
        
        :param encrypted_message: The `decrypt` method takes in three parameters: `encrypted_message`,
        `encoded_key`, and `master_key`. The `encrypted_message` parameter is the message that has been
        encrypted and needs to be decrypted. The `encoded_key` parameter is the key used to encrypt the
        message, encoded in a
        :param encoded_key: The `encoded_key` parameter is the key that has been encoded and needs to be
        decoded using the `master_key` before it can be used for decryption
        :param master_key: The `master_key` is a key used for decoding the `encoded_key` in order to
        obtain the actual key needed for decrypting the `encrypted_message`. It is a crucial piece of
        information required for decrypting the message successfully
        :return: the decrypted message after decrypting each block of the encrypted message using the
        provided key. The decrypted blocks are then joined together to form the final decrypted message,
        which is returned after removing any trailing 'x' characters.
        """
        key = self.decode_key(encoded_key, master_key)
        decrypted_message =[]
        blocks = encrypted_message.split()
                                
        for block in blocks:
            block = ''.join(block).rstrip('x')
            decrypted_block = self.decrypt_block(block, key)
            decrypted_message.append(decrypted_block)
            
            
        return ''.join(decrypted_message).rstrip('x')
    
    
def main():
    message = "hello world this is a custom example"
    key = "relations"
    master_key = "keypass"
    
    cipher = CustomCipher(block_size=5)
    
    # Encrypt the message
    encrypted_message, encoded_key = cipher.encrypt(message.replace(" ", ""), key, master_key)
    print("Encrypted Message:", encrypted_message)
    print("Encoded Key:", encoded_key)

    # Decrypt the message
    # encoded_key = cipher.encode_key(key, master_key) # uhodwlrqv
    # print("Decrypted Message:", encoded_key)
    decrypted_message = cipher.decrypt(message, encoded_key, master_key)
    print("Decrypted Message:", decrypted_message)
    
if __name__ == "__main__":
    main()