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

# Function to simulate Diffie-Hellman Key Exchange with MITM attack
def diffie_hellman_mitm():
    print("Starting Diffie-Hellman Key Exchange with Man-in-the-Middle attack...")
    
    # Step 1: Generate primes for Diffie-Hellman (same as before)
    primes = get_primes(256)
    p = random.choice(primes)
    g = random.choice([prime for prime in primes if prime != p])
    print("Public values: p =", p, "g =", g)

    # Alice chooses private key a, Bob chooses private key b
    a = int(input("Enter Alice's private key (a): "))
    b = int(input("Enter Bob's private key (b): "))
    
    # Alice computes A = g^a mod p
    A = (g ** a) % p
    print("Alice sends A =", A)

    # Attacker intercepts A and sends a fake A' to Bob
    # Charlie intercepts and manipulates the message (Attacker does not need Alice's real private key)
    A_fake = (g ** (random.randint(1, 100))) % p  # Attacker generates his own fake A'
    print("Attacker intercepts A and sends fake A' =", A_fake)

    # Bob computes B = g^b mod p
    B = (g ** b) % p
    print("Bob sends B =", B)

    # Attacker intercepts B and sends a fake B' to Alice
    B_fake = (g ** (random.randint(1, 100))) % p  # Attacker generates his own fake B'
    print("Attacker intercepts B and sends fake B' =", B_fake)

    # Alice computes the shared key using fake B'
    shared_key_a = (B_fake ** a) % p
    print("Alice computes shared key using fake B' =", shared_key_a)

    # Bob computes the shared key using fake A'
    shared_key_b = (A_fake ** b) % p
    print("Bob computes shared key using fake A' =", shared_key_b)

    # Attacker has access to both keys
    shared_key_attacker = (A_fake ** (random.randint(1, 100))) % p
    print("Attacker computes shared key using fake A' and fake B' =", shared_key_attacker)

    print("\nMITM Attack completed: Alice and Bob believe they have a shared key, but the attacker can intercept everything.")

# RSA Encryption with MITM
def rsa_mitm():
    print("\nStarting RSA Encryption with Man-in-the-Middle attack...")

    # Step 1: Generate RSA keys for Alice and Bob
    p = 61  # Example small prime
    q = 53  # Example small prime
    r = p * q  # Modulus (n = p * q)
    e = 17  # Public exponent (chosen for simplicity)

    # Calculate Euler's Totient (φ(r))
    phi_r = euler_totient(p, q)

    # Step 2: Attacker intercepts public keys
    pub_key_alice = e
    priv_key_alice = mod_inverse(pub_key_alice, phi_r)
    print(f"Alice's public key: {pub_key_alice}, private key: {priv_key_alice}")

    # The attacker intercepts and sends their own public key to Bob
    pub_key_attacker = e  # The attacker can use the same public key to confuse both parties
    print(f"Attacker's public key: {pub_key_attacker}")

    # Step 3: Bob sends encrypted message to Alice
    message = "Hello Alice!"
    m = ord(message[0])  # Encrypt the first character 'H'
    cipher_text = (m ** pub_key_attacker) % r
    print(f"Bob encrypts 'H' to {cipher_text} using attacker's public key")

    # Step 4: Attacker decrypts the message using their private key
    priv_key_attacker = mod_inverse(pub_key_attacker, phi_r)
    decrypted_text = chr((cipher_text ** priv_key_attacker) % r)
    print(f"Attacker decrypts the message: {decrypted_text}")

    print("\nRSA MITM Attack completed: The attacker intercepts and decrypts the message.")

# Simulate the MITM attack
diffie_hellman_mitm()
rsa_mitm()
