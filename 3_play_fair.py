import re

class PlayFairEncrypt:
    
    def __init__(self, key):
        self.GRID_SIZE = 6  # Normally 5x5 but shifted to 6x6 matrix for letters and numbers
        self.ALPHA_NUM = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        self.KEY = self.create_matrix(key)

    def create_matrix(self, key):
        """
            Creates a 6x6 matrix based on the key, including A-Z and 0-9.
        """
        key = "".join(dict.fromkeys(key.upper()))  # Remove duplicates
        key = re.sub(r'[^A-Z0-9]', '', key)  # Retain only alphanumeric characters
        key += "".join([ch for ch in self.ALPHA_NUM if ch not in key])  # Fill with remaining characters

        # Create the 6x6 matrix
        key_matrix = [list(key[i:i+self.GRID_SIZE]) for i in range(0, len(key), self.GRID_SIZE)]
        return key_matrix

    def find_character_position(self, char):
        """
            Finds the row and column of a character in the key matrix.
        """
        for row in range(self.GRID_SIZE):
            if char in self.KEY[row]:
                return row, self.KEY[row].index(char)
        return None

    def pair_characters(self, text, pad_char='X'):
        """
            Prepares the text for encryption by pairing characters and adding padding if necessary.
        """
        text = re.sub(r'[^A-Z0-9]', '', text.upper())  # Remove non-alphanumeric characters
        text_pairs = []

        i = 0
        while i < len(text):
            char1 = text[i]
            char2 = text[i+1] if i+1 < len(text) else pad_char

            if char1 == char2:  # If the pair is the same, add padding
                text_pairs.append(char1 + pad_char)
                i += 1
            else:
                text_pairs.append(char1 + char2)
                i += 2

        # Add padding if last pair is a single character
        if len(text_pairs[-1]) == 1:
            text_pairs[-1] += pad_char

        return text_pairs

    def encrypt(self, plain_text):
        """
            Encrypts the plain_text using the Play Fair cipher rules.
        """
        text_pairs = self.pair_characters(plain_text)
        cipher_text = ""

        for pair in text_pairs:
            row1, col1 = self.find_character_position(pair[0])
            row2, col2 = self.find_character_position(pair[1])

            # Rule 1: Same row
            if row1 == row2:
                cipher_text += self.KEY[row1][(col1 + 1) % self.GRID_SIZE]
                cipher_text += self.KEY[row2][(col2 + 1) % self.GRID_SIZE]
            # Rule 2: Same column
            elif col1 == col2:
                cipher_text += self.KEY[(row1 + 1) % self.GRID_SIZE][col1]
                cipher_text += self.KEY[(row2 + 1) % self.GRID_SIZE][col2]
            # Rule 3: Rectangle swap
            else:
                cipher_text += self.KEY[row1][col2]
                cipher_text += self.KEY[row2][col1]

        return cipher_text
    
    def decrypt(self, cipher_text):
        """
            Decrypts the cipher_text using the Play Fair cipher rules.
        """
        text_pairs = self.pair_characters(cipher_text)
        plain_text = ""

        for pair in text_pairs:
            row1, col1 = self.find_character_position(pair[0])
            row2, col2 = self.find_character_position(pair[1])

            # Rule 1: Same row
            if row1 == row2:
                plain_text += self.KEY[row1][(col1 - 1) % self.GRID_SIZE]
                plain_text += self.KEY[row2][(col2 - 1) % self.GRID_SIZE]
            # Rule 2: Same column
            elif col1 == col2:
                plain_text += self.KEY[(row1 - 1) % self.GRID_SIZE][col1]
                plain_text += self.KEY[(row2 - 1) % self.GRID_SIZE][col2]
            # Rule 3: Rectangle swap
            else:
                plain_text += self.KEY[row1][col2]
                plain_text += self.KEY[row2][col1]

        return plain_text.rstrip('X')  # Remove padding character from plain_text


def main():
    # Encryption
    key = input("Enter the key (alphanumeric): ").strip()    
    cipher = PlayFairEncrypt(key)
    
    user_action = input("Do you want to Encrypt or Decrypt (E/D): ").upper()
    
    if user_action == 'E':
        plain_text = input("Enter the plaintext to encrypt: ").strip()   
        encrypted_text = cipher.encrypt(plain_text)   
        print(f"Encrypted text: {encrypted_text}")
    elif user_action == 'D':  
        cipher_text = input("Enter the cipher_text to decrypt: ").strip()
        decrypted_text = cipher.decrypt(cipher_text)
        print(f"Decrypted text: {decrypted_text}")
    else:
        print("Invalid Input")

if __name__ == '__main__':
    main()