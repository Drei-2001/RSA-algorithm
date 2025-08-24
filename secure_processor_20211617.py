import random
import math
import base64
import hashlib  # Add this import for SHA-256

# # https://www.geeksforgeeks.org/python-program-to-check-whether-a-number-is-prime-or-not/
# def prime(n):
#     # Check if a number is prime
#     if n <= 1:
#         return False
#     if n <= 3:
#         return True
#     if n % 2 == 0:
#         return False
    
#     # Check only up to square root of n
#     for i in range(3, int(math.sqrt(n)) + 1, 2):
#         if n % i == 0:
#             return False
#     return True

# https://www.geeksforgeeks.org/python-program-to-check-whether-a-number-is-prime-or-not/
def miller_rabin(n, k=5):
    # Miller-Rabin Primality test
    if n <= 1:
        return False
    if n <= 3:
        return True
    if n % 2 == 0:
        return False

    # Write n as d*2^r + 1
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    # Witness loop
    for _ in range(k):
        a = random.randint(2, n - 2)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def generate_prime(bits):
    # Generate a random prime number of specified bits
    while True:
        n = random.getrandbits(bits)
        n |= (1 << bits - 1) | 1  # Ensure the number is odd and has the right bit length
        if miller_rabin(n):
            return n

#from affine cipher
def gcd(a, b):
    # Find Greatest Common Divisor using Euclidean algorithm
    # Example: gcd(48, 18) = 6
    while b != 0:
        temp = b
        b = a % b
        a = temp
    return a

def mod_inverse(e, phi):
    # Calculate modular multiplicative inverse using pow()
    return pow(e, -1, phi)

def generate_keys():
    # Generate RSA key pair
    # Generate two large prime numbers
    p = generate_prime(512)
    q = generate_prime(512)
    
    # Calculate n and Euler's totient
    n = p * q
    euler = (p - 1) * (q - 1)
    
    # Choose public exponent e
    e = 65537  
    
    # Calculate private exponent d
    d = mod_inverse(e, euler)
    
    # Save keys
    public_key = (n, e)
    private_key = (n, d)
    
    # Save keys to files
    with open("public.pem", "w") as f:
        f.write(f"{n},{e}")
    
    with open("private.pem", "w") as f:
        f.write(f"{n},{d}")
    
    print("Key pair generated and saved successfully!")

def encrypt_document(input_file, public_key_file, output_file):
    # Encrypt a file using RSA
    # Read the document as bytes
    with open(input_file, "rb") as f:
        data = f.read()
    
    # Read the public key
    with open(public_key_file, "r") as f:
        n, e = map(int, f.read().split(','))    
    
    # Convert data to integer
    data_int = int.from_bytes(data, byteorder='big')
    
    # Encrypt: c = m^e mod n
    encrypted = pow(data_int, e, n)
    
    # Save the encrypted data
    with open(output_file, "wb") as f:
        f.write(encrypted.to_bytes((encrypted.bit_length() + 7) // 8, byteorder='big'))
    
    print(f"Document encrypted and saved to {output_file}")

def decrypt_document(input_file, private_key_file):
    # Read the encrypted data
    with open(input_file, "rb") as f:
        encrypted_data = f.read()
    
    # Read the private key
    with open(private_key_file, "r") as f:
        n, d = map(int, f.read().split(','))
    
    # Convert encrypted data to integer
    encrypted_int = int.from_bytes(encrypted_data, byteorder='big')
    
    # Decrypt: m = c^d mod n
    decrypted_int = pow(encrypted_int, d, n)
    
    # Convert back to bytes
    decrypted_data = decrypted_int.to_bytes((decrypted_int.bit_length() + 7) // 8, byteorder='big')
    
    print("Decrypted message:")
    print(decrypted_data.decode())

def sign_document(input_file, private_key_file, signature_file):
    # Sign a document using RSA
    # Read the document
    with open(input_file, "rb") as f:
        data = f.read()
    
    # Read the private key
    with open(private_key_file, "r") as f:
        n, d = map(int, f.read().split(','))
    
    # Create SHA-256 hash of the document
    hash_obj = hashlib.sha256(data)
    # gets the raw bytes of SHA-256, modulo it with n,  then converts them to integer 
    hash_value = int.from_bytes(hash_obj.digest(), byteorder='big') % n
    
    # Sign: s = h^d mod n
    signature = pow(hash_value, d, n)
    
    # Save the signature
    with open(signature_file, "wb") as f:
        f.write(signature.to_bytes((signature.bit_length() + 7) // 8, byteorder='big'))
    
    print(f"Document signed and signature saved to {signature_file}")

def verify_sign(input_file, signature_file, public_key_file):
    # Verify a document signature using RSA
    # Read the document
    with open(input_file, "rb") as f:
        data = f.read()
    
    # Read the signature
    with open(signature_file, "rb") as f:
        signature = int.from_bytes(f.read(), byteorder='big')
    
    # Read the public key
    with open(public_key_file, "r") as f:
        n, e = map(int, f.read().split(','))
    
    # Create SHA-256 hash of the document
    hash_obj = hashlib.sha256(data)
    # gets the raw bytes of SHA-256, modulo it with n,  then converts them to integer 
    hash_value = int.from_bytes(hash_obj.digest(), byteorder='big') % n
    
    # Verify: h = s^e mod n
    verified_hash = pow(signature, e, n)
    
    if hash_value == verified_hash:
        print("Signature verification successful!")
    else:
        print("Signature verification failed!") 