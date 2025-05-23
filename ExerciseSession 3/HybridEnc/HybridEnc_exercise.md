Hybrid encryption
=================

Write a program that implements RSA key pair generation, as well as hybrid encryption and decryption of files.

The key pair generation part should generate a new 2048-bit RSA key pair, and then save the exported public key in a file and the exported key pair in another file, both in PEM format. As the key pair contains the private key, this latter file should be password protected.

The encryption part should do the following:
- read the content of an input file
- read and import an RSA public key from a PEM file
- generate a random AES key and encrypt the padded input with AES in CBC mode
- encrypt the AES key with RSA-OAEP using the public key
- save the encrypted AES key, the IV of the CBC mode, and the encrypted input into an output file (use base64 encoding and a json structure to store the different elements, and dump the json out into the output file)

The decryption part should do the following:
- read the content of an input file
- parse the input and find the encrypted AES key, the IV, and the encrypted payload (read in the json structure and decode its elements with base64)
- read and import an RSA key pair from a PEM file
- decrypt the AES key with RSA_OAEP using the private key of the imported key pair
- decrypt the payload with AES in CBC mode using the decoded AES key and the IV
- unpad the payload and save the result

In addition, implement optional RSA signature generation and verificatio too. The signature should be generated on the encrypted AES key, the IV, and encrypted payload using an RSA private key (key pair), if such a key is given. When decoding an encrypted file, signature verification should happen first, if the file conatins a signature.

We started to write this Python application, and you find what we have so far in `hybrid_skeleton.py`. Your task is to complete the program. Some test files are also provided for your help (a test public key, a test key pair, some text input and output, etc). The password for the file `test_keypair.pem` is 'crysys'.


