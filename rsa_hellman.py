import random

# Function to generate a list of primes up to a given limit
def get_primes(limit):
    primes = []
    for num in range(2, limit + 1):
        is_prime = True
        for i in range(2, int(num ** 0.5) + 1):
            if num % i == 0:
                is_prime = False
                break
        if is_prime:
            primes.append(num)
    return primes

# Function to calculate Euler's Totient (φ(r))
def euler_totient(p, q):
    return (p - 1) * (q - 1)

# Function to find the modular inverse of e modulo φ(r)
def mod_inverse(e, phi_r):
    for d in range(2, 1000000000):
        if (e * d) % phi_r == 1:
            return d
    return None

# RSA Key Generation
p = 0
q = 0
r = 257  # Modulus (n = p * q)

# Step 1: Generate primes p and q
primes = get_primes(256)
while r > 256:
    p = random.choice(primes)  # Select random prime p
    q = random.choice([prime for prime in primes if prime != p])  # Select a different prime q
    r = p * q  # Calculate modulus r

print("##################################################\n")
print(f"RSA(r) = {r}")  # Print RSA modulus (n = p * q)

# Step 2: Calculate Euler's Totient φ(r)
e = euler_totient(p, q)
print("Euler's Totient = ", e)

# Step 3: Select public key 'e'
# Public key should be a number relatively prime to Euler's totient (e < φ(r) and gcd(e, φ(r)) == 1)
pub_key = 0
for prime in primes:
    if 1 < prime < e and e % prime != 0:
        pub_key = prime
        break

print("##################################################\n")
print("Public Key: ", pub_key)  # Print public key

# Step 4: Calculate private key 'd'
priv_key = mod_inverse(pub_key, e)
print("##################################################\n")
print("Private Key: ", priv_key)  # Print private key

# Step 5: Encrypt and Decrypt a message ('A')
print("##################################################\n")
print("Converting 'A' to its ASCII value")
ascii_value = ord("A")
print("ASCII value of 'A' is:", ascii_value)

# Encrypt the message
print("Attempting to encrypt 'A'")
m = ascii_value
cipher_text = (m ** pub_key) % r
print(f"({m} ** {pub_key}) % {r} = {cipher_text}")
c = cipher_text

# Decrypt the message
decrypt_text = (c ** priv_key) % r
print(f"({c} ** {priv_key}) % {r} = {decrypt_text}")
decrypted_char = chr(decrypt_text)
print("Decrypted letter becomes ASCII:", decrypt_text)
print("Decrypted letter is:", decrypted_char)
print("##################################################\n")
