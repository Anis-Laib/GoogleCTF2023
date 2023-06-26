from functools import reduce
from math import gcd
from Crypto.Util.number import isPrime, long_to_bytes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

# Read candidate numbers from file
with open('dump.txt', 'r') as f:
    candidates = f.read().splitlines()

# Convert candidates to integers
known = [int(i) for i in candidates]

# Extended Euclidean Algorithm
def egcd(a, b):
    if a == 0:
        return b, 0, 1
    else:
        g, x, y = egcd(b % a, a)
        return g, y - (b // a) * x, x

# Modular inverse using Extended Euclidean Algorithm
def modinv(b, n):
    g, x, _ = egcd(b, n)
    if g == 1:
        return x % n

# Function to crack the modulus 'm'
def crack_m(outs):
    diffs = [s1 - s0 for s0, s1 in zip(outs, outs[1:])]
    zeros = [t2 * t0 - t1 * t1 for t0, t1, t2 in zip(diffs, diffs[1:], diffs[2:])]
    m = abs(reduce(gcd, zeros))
    return m

# Crack the modulus 'm'
m = crack_m(known)

# Function to crack the multiplier 'a'
def crack_a(outs, m):
    a = (outs[2] - outs[1]) * modinv(outs[1] - outs[0], m) % m
    return a

# Crack the multiplier 'a'
a = crack_a(known, m)

# Function to crack the increment 'c'
def crack_c(outs, m, a):
    c = (outs[1] - outs[0] * a) % m
    return c

# Crack the increment 'c'
c = crack_c(known, m, a)

# Linear Congruential Generator (LCG) class
class LCG:
    lcg_m = a
    lcg_c = c
    lcg_n = m

    def __init__(self, lcg_s):
        self.state = lcg_s

    def next(self):
        self.state = (self.state * self.lcg_m + self.lcg_c) % self.lcg_n
        return self.state

# Set the seed value for LCG
seed = 211286818345627549183608678726370412218029639873054513839005340650674982169404937862395980568550063504804783328450267566224937880641772833325018028629959635
lcg = LCG(seed)
primes_arr = []

primes_n = 1
while True:
    for i in range(8):
        while True:
            prime_candidate = lcg.next()
            # Check if the candidate number is prime
            if not isPrime(prime_candidate):
                continue
            # Check if the candidate number has a bit length of 512
            elif prime_candidate.bit_length() != 512:
                continue
            else:
                primes_n *= prime_candidate
                primes_arr.append(prime_candidate)
                break

    # Check if the product of primes exceeds the bit length of 4096
    if primes_n.bit_length() > 4096:
        print("bit length", primes_n.bit_length())
        primes_arr.clear()
        primes_n = 1
        continue
    else:
        break

n = 1
for j in primes_arr:
    n *= j

# Calculate Euler's totient function (phi)
phi = 1
for k in primes_arr:
    phi *= (k - 1)

# Load public key from file
with open("public.pem", "rb") as pub_file:
    public_key = serialization.load_pem_public_key(pub_file.read(), backend=default_backend())

# Get the public exponent 'e'
e = public_key.public_numbers().e

# Calculate the private exponent 'd'
d = pow(e, -1, phi)

# Read the encrypted content from file
with open("flag.txt", "rb") as flag_file:
    content = flag_file.read()
    _enc = int.from_bytes(content, "little")

# Decrypt the encrypted content
flag_b = pow(_enc, d, n)

# Convert the decrypted content to bytes
flag = long_to_bytes(flag_b)

# Print the flag
print(flag.decode())