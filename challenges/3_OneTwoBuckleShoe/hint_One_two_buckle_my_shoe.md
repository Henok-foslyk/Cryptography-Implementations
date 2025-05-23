Hints for challenge One, Two, Buckle My Shoe
============================================

Look into the program that was used to produce the encrypted files. You can observe that AES was used in CTR mode. Open the two crypted files with a hex editor. You can observe that the beginning (first 128 bytes) of the two files are identical. This may suggest that the CTR mode encryption was not initialized properly, and the two files were encrypted with the same sequence of counters. Can you confrim this by inspecting the source code?

You can also see from the sizes of the encrypted files that version 1 is 16 bytes longer than version 1.1. So you may have the idea that the plaintexts corresponding to the two encrypted versions are almost the same, but 16 bytes might have been deleted after the first 128 bytes in version 1.1.

Let's put together what we suspect: (1) the two files were probably encrypted with the same key stream (i.e., the output of AES on the same sequence of counters) and (2) the two plaintexts are probably identical but one block (of 16 bytes) was deleted from version 1.1 after the 8th block (128 bytes). When two ciphertexts are produced using the same key stream in CTR mode, the first idea is to XOR them together, because if we do that, then the key stream cancels out and we obtain the XOR sum of the two plaintexts (i.e., `(X + K) + (X' + K) = X + X'`), which may reveal some of the real content. Let's give it a try! 

XORing together the first 128 bytes of the two encrypted messages obviously results in 0s. However, when we XOR together the 9th blocks, we get something interesting:

        35 9C 82 30 0C 60 1E 07 3E F5 D4 34 37 6C EE F7
    XOR 56 CE DB 43 55 13 1E 6B 7F B7 D8 34 55 39 AA B6
        -----------------------------------------------
        63 52 59 73 59 73 00 6c 41 42 0c 00 62 55 44 41

which is the ASCII representation of 
	
    c R Y s Y s ? l A B ? ? b U D A

This looks like the text 'CrySyS Lab...' XORed with spaces (sequence of hex `20` characters), because we know that the XOR difference between the ASCII codes of small and capital letters is exactly hex `20`!

So let's XOR it with `20 20 20 ...`

        63 52 59 73 59 73 00 6c 41 42 0c 00 62 55 44 41
    XOR 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20
        -----------------------------------------------
        43 72 79 53 79 53 20 4c 61 62 2c 20 42 75 64 61

which is the ASCII representation of 

    C r y S y S   L a b ,   B u d a

Great! So the 9th block in version 1 was a sequence of spaces and the 9th block in version 1.1 is 'CrySyS Lab, Buda'. It's no surprise that those spaces were deleted from version 1. But more importantly, we managed to recover one useful plaintext block 'CrySyS Lab, Buda'! 

Let's make it a bit more formal. Let us denote the plaintext blocks of version 1 by `m[1..8] m[9] m[10] m[11] ...` We suspect that the plaintext blocks of version 1.1 are `m[1..8] m[10] m[11] ...`, as we assumed that version 1.1 was obtained by deleting one block from version 1 after the 8th block. When we XORed together the 9th ciphertext blocks, we actually computed the XOR sum of the 9th plaintext blocks of the two versions, i.e., `m[9]` from version 1 and `m[10]` from version 1.1, which resulted in `m[9] + m[10]`. We figured out that `m[9]` is just a sequence of spaces (hex `20` characters) and `m[10]` is the text 'CrySyS Lab, Buda'. Now, if we XOR together the 10th ciphertext blocks, we get the XOR sum of `m[10]` from version 1 and `m[11]` from version 1.1, i.e., `m[10] + m[11]`. Since we already know `m[10]`, we can compute `m[11]`. Let's do this:

           10th block from v1: 57 D3 82 E3 B3 16 43 E4 26 84 54 F3 FE C3 49 2B
    XOR  10th block from v1.1: 64 C4 88 C4 C0 4F 37 C0 22 C6 14 B2 DE D9 5F 2B
                               -----------------------------------------------
                  m[10]+m[11]: 33 17 0A 27 73 59 74 24 04 42 40 41 20 1A 16 00
    XOR                 m[10]: 43 72 79 53 79 53 20 4C 61 62 2C 20 42 75 64 61
                               -----------------------------------------------
                        m[11]: 70 65 73 74 0A 0A 54 68 65 20 6C 61 62 6F 72 61

which is the ASCII representation of 

    p e s t     T h e   l a b o r a

We are on the right track! Let's XOR together the 11th ciphertext blocks to obtain `m[11] + m[12]`. Since we already know `m[11]`, we can compute `m[12]`. Can you continue from here?

