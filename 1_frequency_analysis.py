from collections import Counter

class FrequencyAnalysis:
    
    def __init__(self) -> None:
        self.FREQUENT_LETTERS = "ETAOINSHRLDCUMWFGYPBVKJXQZ"
        self.ALPHABET_COUNT = 26

    def ceaser_cipher(self, cipher_text, shift):
        """Applies a Caesar shift to the cipher_text with the given shift amount."""
        
        result = []
        for char in cipher_text:
            if char.isalpha():
                base = ord('A') if char.isupper() else ord('a')
                new_char = chr((ord(char) - base + shift) % self.ALPHABET_COUNT + base)
                result.append(new_char)
            else:
                result.append(char)
                
        return ''.join(result)

    def frequency_analysis(self, cipher_text):
        """Calculates a score based on how closely cipher_text matches typical English frequencies."""
        # Count letter occurrences and find most common letters
        
        counts = Counter(filter(str.isalpha, cipher_text.upper()))
        common_letters = [item[0] for item in counts.most_common()]

        # Calculate score based on matching with English frequency order
        score = sum(1 for letter, common_letter in zip(common_letters, self.FREQUENT_LETTERS) if letter == common_letter)
        return score

    def brute_force_frequency_analysis(self, cipher_text):
        """Attempts all Caesar shifts and scores each decryption based on letter frequency."""
       
        best_shift = 0
        best_score = 0
        best_decryption = cipher_text

        print("Attempting all possible Caesar shifts...\n")
        
        for shift in range(self.ALPHABET_COUNT):
            decrypted_text = self.ceaser_cipher(cipher_text, shift)
            score = self.frequency_analysis(decrypted_text)
            
            print(f"Shift {shift}: {decrypted_text} - (Score: {score}) \n")
            
            if score > best_score:
                best_score = score
                best_shift = shift
                best_decryption = decrypted_text

        return best_shift, best_decryption
    
def main():
    cipher = FrequencyAnalysis()
    
    message = """Ymj vjgz kwtrs jshwdu tkqi xjwj ymj qfed itl.
        Ymnx xjshjshj htqj wjqi hq ymj Jshqtz fqtgjw. 
        Ktqjwdj fsiqnsj rw xjwi ns jshjfyjw qn ymj wjxtqj jshwduj.
        Rjfsyj ns jshj. 
        Wj xjshj fsyj jshwdu ns ltw. 
        Wj qjqi uwj rj xjshfwi 10000 hpudsi sj rjshxj"""
    
    try:
      best_shift, best_decryption = cipher.brute_force_frequency_analysis(message)
      print("\nBest Shift:", best_shift)
      
      print("\nFinal Decrypted Text:")
      print(best_decryption)

    except KeyboardInterrupt:
      print('Something went wrong')
    finally:
      print('Program End')
      
      
if __name__ == "__main__":
    main()
