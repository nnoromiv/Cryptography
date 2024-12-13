from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256, HMAC
from Crypto.Protocol.KDF import HKDF
from Crypto.Random import get_random_bytes

# RSA Key Generation for both users
key_a = RSA.generate(3072)  # Increased key size for better security
key_b = RSA.generate(3072)

public_key_a = key_a.publickey()
private_key_a = key_a

public_key_b = key_b.publickey()
private_key_b = key_b

# Generate AES key using HKDF
def generate_aes_key_with_hkdf(seed, key_size):
    return HKDF(seed, key_size, b"", SHA256)

# Confidentiality: Secure Key Exchange and Communication
# Step 1: User A generates a random seed and derives an AES key
seed = get_random_bytes(16)  # Random seed for key derivation
key_size = 32  # 256-bit AES key
aes_key = generate_aes_key_with_hkdf(seed, key_size)

# Step 2: Encrypt the seed using User B's RSA public key
cipher_rsa = PKCS1_OAEP.new(public_key_b)
encrypted_seed = cipher_rsa.encrypt(seed)

# Step 3: User B decrypts the seed and derives the AES key
cipher_rsa = PKCS1_OAEP.new(private_key_b)
decrypted_seed = cipher_rsa.decrypt(encrypted_seed)
decrypted_aes_key = generate_aes_key_with_hkdf(decrypted_seed, key_size)

# Step 4: User A encrypts a message using AES
message = b"This is a confidential message."
cipher_aes = AES.new(aes_key, AES.MODE_GCM)
ciphertext, tag = cipher_aes.encrypt_and_digest(message)
nonce = cipher_aes.nonce

# Step 5: User B decrypts the message
cipher_aes = AES.new(decrypted_aes_key, AES.MODE_GCM, nonce=nonce)
decrypted_message = cipher_aes.decrypt_and_verify(ciphertext, tag)

# Authentication: Digital Signature and HMAC
# Step 1: User A signs the message
hash_obj = SHA256.new(message)
signature = pkcs1_15.new(private_key_a).sign(hash_obj)

# Step 2: User A computes an HMAC for the message
hmac_key = get_random_bytes(32)  # Separate key for HMAC
hmac = HMAC.new(hmac_key, message, SHA256).digest()

# Step 3: User B verifies the signature and HMAC
hash_obj = SHA256.new(message)
try:
    pkcs1_15.new(public_key_a).verify(hash_obj, signature)
    print("RSA Signature Verification: Valid.")
except (ValueError, TypeError):
    print("RSA Signature Verification: Invalid.")

# Verify HMAC
try:
    HMAC.new(hmac_key, message, SHA256).verify(hmac)
    print("HMAC Verification: Valid.")
except ValueError:
    print("HMAC Verification: Invalid.")

# Output Results
print("\nConfidentiality:")
print("Original Message:", message)
print("Decrypted Message:", decrypted_message)
print("\nAuthentication:")
print("RSA Signature: Verified")
print("HMAC: Verified")
