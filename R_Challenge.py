from Crypto.Util.Padding import pad, unpad

# Step 4: User A encrypts a message using AES in CBC mode
iv = get_random_bytes(16)  # Generate a random IV
cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv)
padded_message = pad(message, AES.block_size)  # Pad the message to be a multiple of the block size
ciphertext = cipher_aes.encrypt(padded_message)
print("User A has encrypted the message using AES-CBC.")

# Step 5: User B decrypts the message using AES in CBC mode
cipher_aes = AES.new(decrypted_aes_key, AES.MODE_CBC, iv)
padded_decrypted_message = cipher_aes.decrypt(ciphertext)
decrypted_message = unpad(padded_decrypted_message, AES.block_size)  # Remove padding
print("User B has decrypted the message using AES-CBC.")
