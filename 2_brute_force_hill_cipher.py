from typing import LiteralString
import numpy as np
from itertools import product


class BruteForceHillCipher:
    
    def __init__(self) -> None:
        self.ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        self.MODULUS = 26
        self.COMMON_ENGLISH = 'ETAOINSHRDLCUMWFGYPBVKJXQZ'

    
    def multiplicative_inverse(self, a: int) ->(int | None):
        """
            The function `multiplicative_inverse(a)` calculates the modular multiplicative inverse of `a` modulo `MODULOS`.
            
            :param a: The parameter `a` in the `multiplicative_inverse` function represents the number for which we want to
            find the modular multiplicative inverse

            :return: The function `multiplicative_inverse(a)` returns the modular multiplicative inverse of `a`.
            If a modular multiplicative inverse exists, it returns that value. Otherwise, it returns `None`.
        """
        for x in range(1, self.MODULUS):
            if(a * x) % self.MODULUS == 1:
                return x
        return None
        
    def can_invert_matrix(self, matrix) -> bool:
        """
            The function `can_invert_matrix(matrix)` checks if a matrix is invertible by calculating its determinant and
            finding its modular inverse.
            
            :param matrix: The `matrix` parameter should be a 2D array
            
            :return: The function `can_invert_matrix(matrix)` returns a boolean value indicating whether the input
            matrix is invertible or not. If the modular inverse exists, it returns `True`, indicating that the matrix is invertible. Otherwise, `False`
        """
        print('Testing Possible Values...')
        det = int(np.round(np.linalg.det(matrix))) % self.MODULUS
        return self.multiplicative_inverse(det) is not None

    def invert_matrix(self, matrix):
        """
            The function `invert_matrix(matrix)` calculates the modular inverse of a matrix with respect to a given
            modulus.
            
            :param matrix: The `matrix` parameter should be a 2D array
            
            :return: The function `invert_matrix` returns the inverse of the input matrix.
        """
        det = int(np.round(np.linalg.det(matrix))) % self.MODULUS
        inv_det = self.multiplicative_inverse(det)
        if inv_det is None:
            return None  # Not invertible

        inv_matrix = np.array([[matrix[1, 1], -matrix[0, 1]], [-matrix[1, 0], matrix[0, 0]]])
        inv_matrix = (inv_matrix * inv_det) % self.MODULUS
        return inv_matrix.astype(int)

    def decrypt(self, cipher_text, key_matrix) -> LiteralString:
        """
            The `decrypt(cipher_text, key_matrix)` function takes a cipher_text and a key_matrix, converts the cipher_text to numerical
            values, reshapes it into pairs for decryption, applies matrix decryption using modular inverse, and
            converts the decrypted numbers back to letters to return the plaintext.
            
            :param cipher_text: This is the inputted ciphered message to be decrypted 
            
            :param key_matrix: The `key_matrix` parameter in the `decrypt` function is a matrix used for
            decryption. It is used to reverse the encryption process and convert the cipher_text back to
            plaintext. 
            
            :return: The function `decrypt` returns the decrypted plaintext obtained by applying matrix decryption to the given cipher_text using the provided key_matrix.
        """
        # Convert message to numerical values
        cipher_text_number = [self.ALPHABET.index(char) for char in cipher_text if char in self.ALPHABET]
        
        # Reshape to pairs for decryption
        pairs = [cipher_text_number[i:i + 2] for i in range(0, len(cipher_text_number), 2)]
        
        # Apply matrix decryption
        plain_text_number = []
        for pair in pairs:
            if len(pair) < 2:  # Padding if message length is odd
                pair.append(0)
            decrypted_pair = np.dot(self.invert_matrix(key_matrix), pair) % self.MODULUS
            plain_text_number.extend(decrypted_pair)

        # Convert numbers back to letters
        plaintext = ''.join(self.ALPHABET[int(num)] for num in plain_text_number)
        return plaintext

    def text_count(self, text) -> int:
        """
            The function `text_count(text)` calculates a score for a given text based on the frequency of common
            English letters.
            
            :param text: The text input and calculates a score based on the frequency of common English letters in the text. 
            
            :return: The function `text_count` returns the sum of the counts of the six most common English letters (E, T, A, O, I, N) in the input text.
        """
        # Simple scoring based on common English letters
        return sum(text.count(i) for i in self.COMMON_ENGLISH[:6])

    def brute_force_hill_cipher_with_no_matrix(self, message) :
        """
            The function `brute_force_hill_cipher` attempts to decrypt a message using a brute force approach
            by trying all possible 2x2 matrices as keys and selecting the one with the highest score based on a
            scoring function.
            
            :param message: It seems like the code snippet you provided is attempting to perform a
            brute-force attack on a Hill cipher with a 2x2 key matrix. The function `brute_force_hill_cipher` is
            trying different key matrices to decrypt the given message and find the one that produces the
            highest score for the
        """
        
        best_score = 0
        best_plaintext = ""
        best_key = None
                
        # Generate all 2x2 matrices with entries from 0 to 25
        for a, b, c, d in product(range(self.MODULUS), repeat=4):
            key_matrix = np.array([[a, b], [c, d]])
            
            # Check if matrix is invertible mod 26
            if self.can_invert_matrix(key_matrix):
                # Try decrypting with this matrix
                plaintext = self.decrypt(message, key_matrix)
                score = self.text_count(plaintext)

                # Update the best result if this score is higher
                if score > best_score:
                    best_score = score
                    best_plaintext = plaintext
                    best_key = key_matrix
                    
        return best_plaintext.rstrip('X'), best_key
    
    def brute_force_hill_cipher_with_matrix(self, message, matrix) :
        """
        The function `brute_force_hill_cipher_with_matrix` decrypts a message using a matrix if the
        matrix is a NumPy array.
        
        :param message: The `message` parameter in the `brute_force_hill_cipher_with_matrix` function
        represents the encrypted message that you want to decrypt using the Hill cipher algorithm
        
        :param matrix: The `matrix` parameter in the `brute_force_hill_cipher_with_matrix` function is
        expected to be a NumPy array. The function checks if the `matrix` input is a NumPy array using
        the `isinstance(matrix, np.ndarray)`.
        
        :return: If the `matrix` parameter is an instance of a NumPy array (`np.ndarray`), the function
        will return the decrypted message after applying the Hill cipher decryption with the provided
        matrix. The decrypted message will have any trailing 'X' characters removed before being
        returned.
        """
        best_plaintext = ""
        
        if isinstance(matrix, np.ndarray):      
            best_plaintext = self.decrypt(message, matrix).rstrip('X')
            return best_plaintext
        else:
            return None
                 

def main():
    cipher = BruteForceHillCipher()
    
    try:
      message = input("What is the message to decrypt: ")
      
      if message:
        has_matrix = input("Do you have the matrix? Enter 'Y' for yes and 'N' for no: ").strip().upper()
        if has_matrix == 'Y':
            user_input = input("Input 2x2 matrix using format a, b, c, d: ")
            matrix_values = [int(val) for val in user_input.split(',')]
            
            if len(matrix_values) == 4:
                possible_keys = np.array(matrix_values).reshape(2,2)

                if cipher.can_invert_matrix(possible_keys):
                    
                    plain_text = cipher.brute_force_hill_cipher_with_matrix(message, possible_keys) 
            
                    if plain_text:              
                        print(plain_text)
                else:
                    print("Keys Error")
                
            else:
                print('Invalid Length')
        elif has_matrix == 'N':
            plain_text = cipher.brute_force_hill_cipher_with_no_matrix(message)
            if plain_text is None:
                print("Decryption Error")
                exit()
                                
            print(plain_text)
        else:
            print("Option Error")
            exit()

      else:
          print("Message not detected")
          exit()
                    
    except KeyboardInterrupt:
      print('Something went wrong')
    finally:
      print('Program Ends')
    
# print("Best plaintext:", best_plaintext)
# print("Best key matrix:\n", best_key)

# Example message
# message = "AVHRFTNGRNHIXWCKZCFYFBJWBMRTTXTCIQLTHBDHNFOITKRNHICNCMVXDPFKZUZHHDEGCJRL"


if __name__ == '__main__':
    main()