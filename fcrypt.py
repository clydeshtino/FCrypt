from Cryptodome.Cipher import PKCS1_OAEP
from Cryptodome.PublicKey import RSA
import argparse

def encrypt_file(recipient_key, input_file, output_file):
    try:
        # Open public key file with binary mode
        with open(recipient_key, "rb") as public_key_file:
            # Importing the key from file
            public_key = RSA.import_key(public_key_file.read())

        # Initialize a new PKCS1_OAEP cipher object with the recipient's public key
        cipher = PKCS1_OAEP.new(public_key)
        with open(input_file, "rb") as in_file, open(output_file, "wb") as out_file:
            while True:
                # Reading 128 bytes at a time
                chunk = in_file.read(128)  
                if not chunk:
                    break
                # Encrypt the chunk utilizing our cipher and writing to our output file
                encrypted_chunk = cipher.encrypt(chunk)
                out_file.write(encrypted_chunk)

        print("Encryption Successful.")
    except Exception as e:
        print(f"Encryption failed: {str(e)}")

def decrypt_file(recipient_key, input_file, output_file):
    try:
        # Opening private key file in binary mode
        with open(recipient_key, "rb") as private_key_file:
            # Importing the key from file
            private_key = RSA.import_key(private_key_file.read())

        # Initialize a new PKCS1_OAEP cipher object with the recipient's private key
        cipher = PKCS1_OAEP.new(private_key) 
        with open(input_file, "rb") as in_file, open(output_file, "wb") as out_file:
            while True:
                # Reading 256 bytes at a time
                chunk = in_file.read(256)
                if not chunk:
                    break
                decrypted_chunk = cipher.decrypt(chunk)
                out_file.write(decrypted_chunk)

        print("Decryption Successful.")
    except Exception as e:
        print(f"Decryption failed: {str(e)}")


def main(): # Utilizing argument parsing with descriptions
    parser = argparse.ArgumentParser(description="PGP Encryption/Decryption")
    # Option arguments for encrypting and decryptings
    parser.add_argument("--encrypt", action="store_true", help="Perform encryption")
    parser.add_argument("--decrypt", action="store_true", help="Perform decryption")
    # Positional arguments for key, input/output files
    parser.add_argument("recipient_key", help="Recipient's public or private key file")
    parser.add_argument("input_file", help="Input file")
    parser.add_argument("output_file", help="Output file")
    # Parsing command line arguments
    args = parser.parse_args()
    # if elif to ensure flags are set
    if args.encrypt:
        encrypt_file(args.recipient_key, args.input_file, args.output_file)
    elif args.decrypt:
        decrypt_file(args.recipient_key, args.input_file, args.output_file)
    else:
        print("Please specify either --encrypt or --decrypt.")

if __name__ == "__main__":
    main()