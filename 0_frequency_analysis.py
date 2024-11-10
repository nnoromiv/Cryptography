from collections import Counter

class FrequencyAnalysis:
    
    def __init__(self) -> None:
        self.FREQUENT_LETTERS = "ETAOINSHRLDCUMWFGYPBVKJXQZ"
        self.SUBSTITUTION_DICTIONARY = {
            'J': 'E', 'W': 'R', 'Q': 'L', 'Y': 'T', 'D': 'Y', 
            'R': 'M', 'U': 'P', 'G': 'B', 'Z': 'U', 'V': 'Q', 
            'E': 'Z', 'P': 'K', 'M': 'H', 'S': 'N', 'H': 'C', 
            'T': 'O', 'K': 'F', 'I': 'D', 'X': 'S', 'F': 'A', 
            'L': 'G', 'N': 'I'
        }
        
    def create_substitution_dictionary(self, cipher_text):
        # Clean the cipher text for analysis (ignore spaces, periods)
        message = cipher_text.upper().replace(" ", "").replace(".", "").replace("\n", "")
        
        # Count letter frequency from the message        
        message_frequent_letter_count = Counter(message)
        
        # Sort letters from highest frequency
        sorted_letters = [
            pair[0] for pair in message_frequent_letter_count.most_common() if pair[0].isalpha()
        ]
        
        print(message_frequent_letter_count)
        
        # Create initial substitution dictionary based on frequency analysis
        self.SUBSTITUTION_DICTIONARY = {
            cipher_letter: english_letter for cipher_letter, english_letter in zip(sorted_letters, self.FREQUENT_LETTERS)
        }
        print("Initial Substitution Dictionary:", self.SUBSTITUTION_DICTIONARY)
        
    def decrypt(self, cipher_text):
        # Ensure the substitution dictionary is created before decryption
        if not self.SUBSTITUTION_DICTIONARY:
            self.create_substitution_dictionary(cipher_text)
        
        # Decrypt the message using the current substitution dictionary
        decrypted_message = ''.join(
            self.SUBSTITUTION_DICTIONARY.get(char, char) if char.isalpha() else char 
            for char in cipher_text.upper()
        )
        
        return decrypted_message
    
    def update_substitution(self, inputted_cipher, new_mapped_letter):
        """
            Update the substitution dictionary by mapping `inputted_cipher` to `new_mapped_letter`.
        """
        # Remove any existing mapping to new_mapped_letter to prevent duplicates
        for key, value in list(self.SUBSTITUTION_DICTIONARY.items()):
            if value == new_mapped_letter:
                del self.SUBSTITUTION_DICTIONARY[key]

        # Update substitution dictionary with the new mapping
        self.SUBSTITUTION_DICTIONARY[inputted_cipher] = new_mapped_letter
        
        return self.SUBSTITUTION_DICTIONARY

def main():
    freq_analysis = FrequencyAnalysis()
    message = """
        Ymj vjgz kwtrs jshwdu tkqi xjwj ymj qfed itl.
        Ymnx xjshjshj htqj wjqi hq ymj Jshqtz fqtgjw. 
        Ktqjwdj fsiqnsj rw xjwi ns jshjfyjw qn ymj wjxtqj jshwduj.
        Rjfsyj ns jshj. 
        Wj xjshj fsyj jshwdu ns ltw. 
        Wj qjqi uwj rj xjshfwi 10000 hpudsi sj rjshxj
        """
        # THE QEBU FROMN ENCRYP OFLD SERE THE LAZY DOG.
        # THIS SENCENCE COLE RELD CL THE ENCLOU ALOBER.
        # FOLERYE ANDLINE MR SERD IN ENCEATER LI THE RESOLE ENCRYPE.
        # MEANTE IN ENCE.
        # RE SENCE ANTE ENCRYP IN GOR.
        # RE LELD PRE ME SENCARD 10000 CKPYND NE MENCSE

    # Initial decryption based on frequency analysis
    result = freq_analysis.decrypt(message)
    print("\nDecrypted message after frequency analysis:\n", result)
    
    # Interactive loop for manual adjustments
    while True:
        inputted_cipher = input("Enter the cipher letter you'd like to change (or 'exit' to stop): ").upper()
        if inputted_cipher == "exit":
            break
        
        new_mapped_letter = input(f"Enter the new English letter to map '{inputted_cipher}' to (or 'exit' to stop): ").upper()
        if new_mapped_letter == "exit":
            break
        
        # Update the substitution dictionary and print the newly decrypted message
        update = freq_analysis.update_substitution(inputted_cipher, new_mapped_letter)
        print(update)
        result = freq_analysis.decrypt(message)
        print("\nUpdated Decrypted Message:\n", result)

if __name__ == "__main__":
    main()