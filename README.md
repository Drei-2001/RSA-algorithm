HOW IT WORKS

run test.py (python test.py)
test.py does multiple things:
  - generate_keys(): generate two keys for the RSA key pairs
  - encrypt_document(input_file,public_key_file, output_file); opens the confidential_message.txt, encrypts it using the formula c = m^e mod n, and then outputs it into secure message.enc
  - decrypt_document(input_file, private_key_file); opens the ecrypted file (secure message.enc, decrypts it with the formula m = c^d mod n and then prints it
  - sign_document(input_file, private_key_file, signature_file); signs the document by using the formula s = h^d mod n
  - verify_sign(input_file, signature_file, public_key_file); verify the signature using the formula h = s^e mod n
