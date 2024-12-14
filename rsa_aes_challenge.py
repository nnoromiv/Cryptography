from Crypto.Util.Padding import pad, unpad
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256, HMAC
from Crypto.Protocol.KDF import HKDF
from Crypto.Random import get_random_bytes

# The `GenerateRSAKeys` class generates RSA key pairs for a sender and recipient.
class GenerateRSAKeys:
    def __init__(self):
        """
        The function initializes two RSA key pairs, one for the sender and one for the recipient, each with
        a key length of 3072 bits.
        Increase key size for better security
        """
        self.sender = RSA.generate(3072)
        self.recipient = RSA.generate(3072)
        
    def generate_keys(self):
        """
        The function `generate_keys` returns the public keys of the sender and recipient along with their
        corresponding objects.
        :return: The `generate_keys` method is returning the sender's public key, sender object, recipient's
        public key, and recipient object.
        """
        sender_public_key = self.sender.publickey()
        recipient_public_key = self.recipient.publickey()
        
        return sender_public_key, self.sender, recipient_public_key, self.recipient
    

class GenerateAESKeys:
    def __init__(self):
        pass

    def create_aes_key(self, key_size, seed=""):
        """
        The function `create_aes_key` generates a random AES key of the specified size (192-bit or 256-bit).
        
        :param key_size: The `key_size` parameter specifies the size of the AES key to be generated. It
        should be either 24 bytes for a 192-bit key or 32 bytes for a 256-bit key
        :return: The `create_aes_key` function returns a randomly generated AES key of the specified key
        size (either 24 bytes for 192-bit or 32 bytes for 256-bit).
        """
        if key_size not in [24, 32]:
            raise ValueError("GenerateAESKeys, Invalid key size. Use 24 (192 bits) or 32 (256 bits).")
        
        if seed == "":
            seed = get_random_bytes(16)
            
        return seed, HKDF(seed, key_size, b"", SHA256)

    def create_aes_rounds(self, rounds_number):
        """
        The function `create_aes_rounds` determines the number of AES rounds based on the key size provided.
        
        :param rounds_number: The `rounds_number` parameter represents the number of rounds in the AES
        encryption algorithm. It is used to determine the number of rounds based on the key size provided.
        If the key size is 192 bits, the function will return 12 rounds, and if the key size is 256 bits
        :return: The function `create_aes_rounds` returns the number of rounds based on the input
        `rounds_number`. If `rounds_number` is 24, it returns 12 which corresponds to a 192-bit key. If
        `rounds_number` is 32, it returns 14 which corresponds to a 256-bit key. If the input
        `rounds_number` is neither 24
        """
        if rounds_number == 24:  # 192-bit key
            return 12
        elif rounds_number == 32:  # 256-bit key
            return 14
        else:
            raise ValueError("GenerateAESKeys, Invalid key size. Use 24 (192 bits) or 32 (256 bits).")
        
class Communication:
    
    print("Creating an Authenticated Session....")
    rsa_keys = GenerateRSAKeys()
    sender_public_key, sender_private_key, recipient_public_key, recipient_private_key = rsa_keys.generate_keys()
    
    key_size = int(input("Set key size. Use 24 (192 bits) or 32 (256 bits).: "))
    
    if key_size not in [24, 32]:
        raise ValueError("Communication, Invalid key size. Use 24 (192 bits) or 32 (256 bits).")

    
    print("Creating a Confidential Session....")
    aes_keys = GenerateAESKeys()
    
    # Step 1: Sender generates an AES session key
    seed, aes_key = aes_keys.create_aes_key(key_size)
    aes_round = aes_keys.create_aes_rounds(key_size)
    print(f"Using AES with {aes_round} rounds.")

    # Step 2: Encrypt the AES session key using Recipient's RSA public key
    cipher_rsa = PKCS1_OAEP.new(recipient_public_key)
    encrypted_seed = cipher_rsa.encrypt(seed)
    print("Sender has encrypted the AES session key.")
    
    # Step 3: Sender encrypts a message using AES in CBC mode
    message = input("Sender's Message: ").encode('utf-8')
    information_validator = get_random_bytes(16)
    # MODE_GCM Has a block size of 128 bits 
    cipher_aes = AES.new(aes_key, AES.MODE_CBC, information_validator)
    padded_message = pad(message, AES.block_size)
    cipher_text = cipher_aes.encrypt(padded_message)
    print("Message encrypted and sent  using AES-CBC.")
    
    
    # Step 4: Recipient decrypts the AES session key
    cipher_rsa = PKCS1_OAEP.new(recipient_private_key)
    decrypted_seed = cipher_rsa.decrypt(encrypted_seed)
    seed, decrypted_aes_key = aes_keys.create_aes_key(key_size, decrypted_seed)
    print("Recipient has decrypted the AES session key.")


    # Step 5: Recipient decrypts the message
    cipher_aes = AES.new(decrypted_aes_key, AES.MODE_CBC, information_validator)
    padded_decrypted_message = cipher_aes.decrypt(cipher_text)
    decrypted_message = unpad(padded_decrypted_message, AES.block_size)
    print(f"Message decrypted by Recipient. {decrypted_message.decode('utf-8')} using AES-CBC.")

    
    print("Authenticating message....")

    # Step 1: Sender signs the message
    signed_message = SHA256.new(message)
    signature = pkcs1_15.new(sender_private_key).sign(signed_message)
    print("Sender has signed the message.")

    # Step 2: Recipient computes an HMAC for the message and verifies the signature
    hmac_key = get_random_bytes(32)
    hmac = HMAC.new(hmac_key, message, SHA256).digest()
    signed_message = SHA256.new(message)
    
    # These `try-except` blocks are used for error handling and verification in the code snippet provided.
    try:
        pkcs1_15.new(sender_public_key).verify(signed_message, signature)
        print("Recipient has verified the signature: Valid.")
    except (ValueError, TypeError):
        print("Recipient has verified the signature: Invalid.")
        
    try:
        HMAC.new(hmac_key, message, SHA256).verify(hmac)
        print("HMAC Verification: Valid.")
    except ValueError:
        print("HMAC Verification: Invalid.")
        
def main():
    Communication()
    
if __name__ == '__main__':
    main()
