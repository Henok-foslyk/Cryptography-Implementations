Hints for challenge "Filling the gap"
=====================================

This is what we know:

                  X_i
                   |
             +-----+
             |     |
             |     |
        T_i ----->(+)--->[ MD5 ]---+---> output_i = K
             |                     |
             |                     |
             +--->(+)<-------------+
                   |
                   | X_(i+1)
                   |
             +-----+
             |     |
             |     |
    T_(i+1) ----->(+)--->[ MD5 ]---+---> output_(i+1) = IV
             |                     |
             |                     |
             +--->(+)<-------------+
                   |
                   |
                  X_(i+2)

where X_i and X_(i+2) are given, and IV can be obtained from the encrypted file (first 16 bytes). 

Use the figure above to figure out how to compute X_(i+1) first, and then K. Once you have K, you can decode the file with the given script.
