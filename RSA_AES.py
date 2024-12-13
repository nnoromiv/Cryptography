from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes

# RSA Key Generation for both users
key_a = RSA.generate(2048)
key_b = RSA.generate(2048)

public_key_a = key_a.publickey()
private_key_a = key_a

public_key_b = key_b.publickey()
private_key_b = key_b

# Function to generate an AES key with customizable size
def generate_aes_key(key_size):
    if key_size not in [24, 32]:  # 24 bytes for 192-bit, 32 bytes for 256-bit
        raise ValueError("Invalid key size. Use 192-bit (24 bytes) or 256-bit (32 bytes).")
    return get_random_bytes(key_size)

# Function to select AES rounds based on key size
def get_aes_rounds(key_size):
    if key_size == 24:  # 192-bit key
        return 12
    elif key_size == 32:  # 256-bit key
        return 14
    else:
        raise ValueError("Invalid key size. Use 192-bit (24 bytes) or 256-bit (32 bytes).")

# Confidentiality: Key Exchange and Secure Communication
# Step 1: User A generates an AES session key
key_size = 32  # Change to 24 for 192-bit key
aes_key = generate_aes_key(key_size)
aes_rounds = get_aes_rounds(key_size)
print(f"Using AES with {aes_rounds} rounds.")

# Step 2: Encrypt the AES session key using User B's RSA public key
cipher_rsa = PKCS1_OAEP.new(public_key_b)
encrypted_aes_key = cipher_rsa.encrypt(aes_key)
print("User A has encrypted the AES session key.")

# Step 3: User B decrypts the AES session key
cipher_rsa = PKCS1_OAEP.new(private_key_b)
decrypted_aes_key = cipher_rsa.decrypt(encrypted_aes_key)
print("User B has decrypted the AES session key.")

# Step 4: User A encrypts a message using AES
message = b"This is a confidential message."
cipher_aes = AES.new(aes_key, AES.MODE_GCM)
ciphertext, tag = cipher_aes.encrypt_and_digest(message)
nonce = cipher_aes.nonce
print("User A has encrypted the message.")

# Step 5: User B decrypts the message
cipher_aes = AES.new(decrypted_aes_key, AES.MODE_GCM, nonce=nonce)
decrypted_message = cipher_aes.decrypt_and_verify(ciphertext, tag)
print("User B has decrypted the message.")

# Authentication: Digital Signature
# Step 1: User A signs the message
hash_obj = SHA256.new(message)
signature = pkcs1_15.new(private_key_a).sign(hash_obj)
print("User A has signed the message.")

# Step 2: User B verifies the signature
hash_obj = SHA256.new(message)
try:
    pkcs1_15.new(public_key_a).verify(hash_obj, signature)
    signature_verification = "Signature is valid."
    print("User B has verified the signature: Valid.")
except (ValueError, TypeError):
    signature_verification = "Signature is invalid."
    print("User B has verified the signature: Invalid.")

# Output the results
print("\nConfidentiality:")
print("Original Message:", message)
print("Decrypted Message:", decrypted_message)
print()
print("Authentication:")
print(signature_verification)
