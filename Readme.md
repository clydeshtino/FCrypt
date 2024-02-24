# FCrypt: File Encryption
# By: Clyde Shtino

## About 
This is a simple python script with the goal of encrypting a file given at the command line while being secure by using PGP (Pretty Good Privacy), along with the RSA Algorithm with PKCS1_OAEP padding.

# RSA (Rivest-Shamir-Adleman)
The python script utilizes the RSA algorithm to encrypt an decrypt files while being secure. RSA is an asymettric cryptographic algorithm used for secure data transmission. It requires the use of public and private key in order to encrypt and decrypt sucessfully. In the case of fcrypt, the public key is used for encryption in the encrypt_file function and the private key is used for decrypting in the decrypt_file function.


# PKCS1_OAEP Padding
PKCS Optimal Asymmetric Encryption Padding (OAEP) is a padding scheme to works along RSA to secure encryption. The task of the padding is to add randomness to the input data before encrypting, thus enhacning security against attacks. We utilize the Cryptodome library of python in order to implement this pading. Regarding the code, the PKCSI_OAEP.new() function creates a cipher object with RSA keys and the padding scheme for encrypting and decrypting.

# Encryption
In order to encrypt, the input file is read in chunks. Each chunk is then encrypting using the RSA public key of the recipient with the padding scheme, and the encrypted chunks are wrritten to the output file as a result.

# Decryption
Now regarding decryption, the file is also once again read in chunks, but this time each chunk is decrypted using the private key of the recipient and then the chunks are written to the output file. 