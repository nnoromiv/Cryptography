# Importing necessary functions
def get_prime_numbers():
    # Function to generate a list of prime numbers
    # (You can implement a prime-checking function or use a list of primes for simplicity)
    primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29]  # Sample list of primes
    return primes

def calculate_mod_exp(base, exp, mod):
    # Calculate (base^exp) % mod
    return pow(base, exp, mod)

# Get a vector of prime numbers
primes = get_prime_numbers()

# Set 'g' to one of the primes
g = primes[0]  # Picking the first prime (you can choose any)

# Set 'p' to another prime, different from 'g'
p = primes[1]  # Picking the second prime (you can choose any prime different from 'g')

print("Shared g value:", g)
print("Shared p value:", p)

# Get hidden values a and b from the user and ensure they are integers
a = int(input("Enter a hidden integer value a: "))  # Get value for 'a'
b = int(input("Enter a hidden integer value b: "))  # Get value for 'b'

# Calculate A and B based on the Diffie-Hellman formula
A = calculate_mod_exp(g, a, p)  # A = g^a mod p
B = calculate_mod_exp(g, b, p)  # B = g^b mod p

print("##################################################\n")
print("Calculation of shared key with a:\n")

# Print the assigned value of a
print("a assigned value:", a)

# Actual Calculation of A
print(f"{g}^{a} mod {p} = {A} = A")

# Print received B value
print("Received \"B\" value:", B)

# Calculate shared key 'a' using the received B value
shared_key_a = calculate_mod_exp(B, a, p)  # Shared key for 'a' = B^a mod p
print(f"{B}^{a} mod {p} = {shared_key_a}")
print("Shared Key Calculated from \"a\" is:", shared_key_a)

print("\n##################################################\n")
print("Calculation of shared key with b:\n")

# Print the assigned value of b
print("b assigned value:", b)

# Actual Calculation of B
print(f"{g}^{b} mod {p} = {B} = B")

# Print received A value
print("Received \"A\" value:", A)

# Calculate shared key 'b' using the received A value
shared_key_b = calculate_mod_exp(A, b, p)  # Shared key for 'b' = A^b mod p
print(f"{A}^{b} mod {p} = {shared_key_b}")
print("Shared Key Calculated from \"b\" is:", shared_key_b)

print("\n##################################################\n")
