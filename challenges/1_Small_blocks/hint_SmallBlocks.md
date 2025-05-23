Hints for challenge Small blocks
================================

The block length of our cipher is just 1 byte and we use it in CBC mode. We know that short blocks are not desirable in this case, because we can observe indentical blocks in a ciphertext of reasonable length with high probability. When identical blocks are found in the ciphertext, information about the corresponding plaintext blocks is leaked. 

More specifically, let’s assume that we have two encrypted blocks:
	Y_i = E_K(X_i + Y_(i-1))
	Y_j = E_K(X_j + Y_(j-1))
that happen to be equal:
	Y_i = Y_j

This means that 
	D_K(Y_i) = D_K(Y_j) 
which means that
	X_i + Y_(i-1) = X_j + Y_(j-1)
or equivalently
	X_i + X_j = Y_(i-1) + Y_(j-1) 

Now, if X_i is known to the attacker (by whatever means, e.g., it's public data), then X_j is also disclosed:
	X_j = Y_(i-1) + Y_(j-1) + X_i 
	
That's what you can use to solve this challenge...

First, align the plaintext and the ciphertext to see which blocks belong to each other:

   50 6c 65 61 73 65 2c 20 66 69 6c 6c 20 74 68 65    Please, fill the
d0 96 0e f4 9d e0 ec 1d 52 73 87 48 af 20 a9 1c c4 

   20 66 6f 72 6d 20 62 65 6c 6f 77 20 77 69 74 68     form below with
   98 61 66 fe 4d 67 78 2d 21 1b aa 54 b1 84 f1 fa 

   20 79 6f 75 72 20 64 61 74 61 2e 20 4d 61 6b 65     your data. Make
   36 d6 bd 68 87 47 b1 5a 7f 58 88 f8 a7 77 9f 0e 

   ...


You will observe that there are identical blocks in the ciphertext, and in particular some of the ciphertext blocks that correspond to the missing part of the plaintext appear elsewhere in the ciphertext. You can compute the corresponding missing plaintext blocks!

Please note that there may be characters in the missing part of the plaintext that you cannot recover. So some guess work will be needed at the very end.



