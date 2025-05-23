Filling the gap
===============

A program uses the following PRNG to generate cryptographic parameters (such as keys, IVs, etc.):
 
             X_i
              |
        +-----+
        |     |
        |     |
   T_i ----->(+)--->[ MD5 ]---+---> output_i = MD5(X_i + T_i)
        |                     |
        |                     |
        +--->(+)<-------------+
              |
              |
             X_(i+1) = X_i + output_i

where
- X_i is the 16-byte internal state of the PRNG when the i-th output is generated
- T_i is some random input (e.g., disk access time, network delays, etc.) collected from the computer and used in the generation of the i-th output
- the hash function MD5 is used to generate the output, so the output is 16 bytes long
- the (+) operator denotes XOR (as usual).

We know that the program generated a 16-byte AES key K and a 16-byte IV by two consecutive invocations to this PRNG. Then, it encrypted a file using AES in CBC mode with IV and key K. We obtained this encrypted file `ciphertext.crypt` (provided in your handout folder). The  file begins with the 16-byte IV in clear, and the rest is the encrypted content. ISO-7816 style padding was used.

Finally, we also managed to obtain from a backup disk the PRNG’s saved internal state X_i when the key K was generated, and the state X_(i+2) after the generation of the IV (printed as hex strings):

      X_i     =  b5562ff25e66e602eae4dbd61b2d5e8b
      X_(i+2) =  9d6f86e273de3f3905bc068defea0571

With all this information, can you decode the encrypted file? For convenience, we also provided a CBC decoding script `aes_cbc_dec.py` in the handout folder (use the -h option to figure out how to use it). 
