import string

"""
    1. Poly-alphabetic: has the ability to use multiple versions of a pre-defined alphabet 
    2. Blocked cipher: you need to encode parts of the message with equal length. Use padding if necessary. 
    3. Encoded key: You will need to also create a mechanism to encrypt and decrypt the key to the poly-alphabetic 
        cipher. You can add extra keys if that is needed. 
"""

class CustomCipher:
    
    def __init__(self, block_size=5) -> None:
        self.alphabet  = string.ascii_lowercase
        self.alphabets = [
            self.shift_alphabet(i) for i in range(len(self.alphabet))
        ]
        self.block_size = block_size
        
    def shift_alphabet(self, shift):
        return self.alphabet[shift:] + self.alphabet[:shift]
    
    def padding(self, message):
        padding_length =(self.block_size - len(message) % self.block_size) % self.block_size
        return message + 'x' * padding_length
    
    def encrypt_block(self, block, key):
        encrypted_block = []
        
        for i, char in enumerate(block):
            if char in self.alphabet:
                shift_alphabet = self.alphabets[ord(key[i % len(key)]) % len(self.alphabet)]
                encrypted_block.append(shift_alphabet[self.alphabet.index(char)])
            else:
                encrypted_block.append(char)
                
        return ''.join(encrypted_block)
    
    def decrypt_block(self, block, key):
        decrypted_block = []
        
        for i, char in enumerate(block):
            if char in self.alphabet:
                shift_alphabet = self.alphabets[ord(key[i % len(key)]) % len(self.alphabet)]
                decrypted_block.append(self.alphabet[shift_alphabet.index(char)])
            else:
                decrypted_block.append(char)
                
        return ''.join(decrypted_block)
    
    def encode_key(self, key, master_key):
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
        padded_message = self.padding(message)
        encoded_key = self.encode_key(key, master_key)
        
        encrypted_message =[]
        for i in range(0, len(padded_message), self.block_size):
            block = padded_message[i:i + self.block_size]
            encrypted_block = self.encrypt_block(block, key)
            encrypted_message.append(encrypted_block)
            
            
        return ' '.join(encrypted_message), encoded_key
    
    def decrypt(self, encrypted_message, encoded_key, master_key):
        key = self.decode_key(encoded_key, master_key)
        decrypted_message =[]
        blocks = encrypted_message.split()
                                
        for block in blocks:
            block = ''.join(block).rstrip('x')
            decrypted_block = self.decrypt_block(block, key)
            decrypted_message.append(decrypted_block)
            
            
        return ''.join(decrypted_message).rstrip('x')
    
    
def main():
    message = "te td fyvyzhy szh pqqpnetgp esp nlpdlc ntaspc hld le esp etxp, mfe te td wtvpwj ez slgp mppy cpldzylmwj dpnfcp, yze wplde mpnlfdp xzde zq nlpdlc'd pypxtpd hzfwo slgp mppy twwtepclep lyo zespcd hzfwo slgp lddfxpo esle esp xpddlrpd hpcp hcteepy ty ly fyvyzhy qzcptry wlyrflrp."
    key = "relationsrelationsrelationsrel"
    master_key = "keypass"
    
    cipher = CustomCipher(block_size=5)
    
    # Encrypt the message
    # encrypted_message, encoded_key = cipher.encrypt(message.replace(" ", ""), key, master_key)
    # print("Encrypted Message:", encrypted_message)
    # print("Encoded Key:", encoded_key)

    # Decrypt the message
    encoded_key = cipher.encode_key(key, master_key) # uhodwlrqv
    # print("Decrypted Message:", encoded_key)
    decrypted_message = cipher.decrypt(message, encoded_key, master_key)
    print("Decrypted Message:", decrypted_message)
    
if __name__ == "__main__":
    main()