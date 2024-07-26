from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
import hashlib

# Function to find a private key such that the public key ends with 0x00, 0x01, 0x01
def find_private_key_with_specific_public_end(existing_key):
    
    curve = ec.SECP384R1()
    while True:
        # Generate a private key
        private_key = ec.generate_private_key(curve)

        private_numbers = private_key.private_numbers()
        private_value = private_numbers.private_value
        if private_value in existing_key:
            continue
        else:
            existing_key.add(private_value)

        # Derive the public key
        public_key = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint
        )

        # Check the last bytes of the public key
        last_three_bytes = public_key[-3:]
        formatted_bytes = ' '.join(f'0x{byte:02x}' for byte in last_three_bytes)
        print(formatted_bytes)
        if formatted_bytes == '0x00 0x01 0x01':
            return private_key, public_key
        


existing_key = set()

# Find the private key
private_key, public_key = find_private_key_with_specific_public_end(existing_key)

# Output the private key and public key
private_numbers = private_key.private_numbers()
private_value = private_numbers.private_value

print("Private Key (integer):", private_value)
print("Private Key (hex):", hex(private_value))
print("Public Key (hex):", public_key.hex())
