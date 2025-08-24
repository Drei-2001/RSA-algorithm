import os
from secure_processor_20211617 import (
    generate_keys,
    encrypt_document,
    decrypt_document,
    sign_document,
    verify_sign
)

def main():
        
    try:
         # Generate key pair
        generate_keys()
        print("\nGenerated key pair")
        
        # Test encryption and decryption
        encrypt_document("confidential_message.txt", "public.pem", "secure message.enc")
        print("\nEncrypted document")
        
        print("\nDecrypting document:")
        decrypt_document("secure message.enc", "private.pem")
        
        # Test signing and verification
        sign_document("confidential_message.txt", "private.pem", "digital signature.sig")
        print("\nSigned document")
        
        print("\nVerifying signature:")
        verify_sign("confidential_message.txt", "digital signature.sig", "public.pem")
        
    except Exception as e:
        print(f"An error occurred: {str(e)}")

if __name__ == "__main__":
    main() 