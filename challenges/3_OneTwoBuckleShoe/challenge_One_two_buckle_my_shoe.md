One, Two, Buckle My Shoe
========================

You managed to obtain two versions of a sensitive document from a competitor research laboratory:

    LabProfile-v1.crypt
    LabProfile-v1.1.crypt

Unfortunately, the files are encrypted, but with the help of an old friend who happens to know someone at the competitor, you succeeded to obtain the program that was used to produce the encrypted files:

    aes_ctr.py

You look into the program code. Damn! The key is not hard coded... But, fortunately, you realize that the programmer who developed this program made a mistake. Should have read more carefully about the use of AES in counter mode!

Can you exploit the mistake and recover the FLAG (line marked with 'FLAG:') hidden in the documents?


