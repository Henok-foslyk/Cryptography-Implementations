Meet Natasha
============

NataSHA is a block cipher that has a 6-round Feistel structure and its round function is based on the SHA-1 hash function. The block size of NataSHA is 40 bytes and its key length is 48 bits (6 bytes). The encryption operation is illustrated in the figure below, where | means concatenation of byte strings and (+) denotes the XOR operation:

`X = L0|R0`

```
     L0                    R0
     |                     |
     |     +-----+         |
     |     |     |<--- K0  |
    (+)<---| SHA |<--------+
     |     |     |<--- K0  |
     |     +-----+         |
     |                     |
     |         +-----+     |
     |  K1 --->|     |     |
     +-------->| SHA |--->(+)
     |  K1 --->|     |     |
     |         +-----+     |
     |                     |
     |     +-----+         |
     |     |     |<--- K2  |
    (+)<---| SHA |<--------+
     |     |     |<--- K2  |
     |     +-----+         |
     |                     |
     |         +-----+     |
     |  K3 --->|     |     |
     +-------->| SHA |--->(+)
     |  K3 --->|     |     |
     |         +-----+     |
     |                     |
     |     +-----+         |
     |     |     |<--- K4  |
    (+)<---| SHA |<--------+
     |     |     |<--- K4  |
     |     +-----+         |
     |                     |
     |         +-----+     |
     |  K5 --->|     |     |
     +-------->| SHA |--->(+)
     |  K5 --->|     |     |
     |         +-----+     |
     |                     |
     L6                    R6
```

`Y = R6|L6`

So, the input block `X` is first divided into 2 halves, `L0` and `R0`, 20 bytes each. The right half `R0` is hashed together with the first byte `K0` of the key (see figure), the result `SHA(K0|R0|K0)` is XORed with the left half `L0`, and then the two halves are swapped. This makes up one round. The same operation is repeated in the remaining 5 rounds, except that the swap of the two halves is omitted at the end of the last round, and each round uses the next byte from the key, i.e., `K1`, `K2`, ... `K5`. We obtain the output `Y` by concatenating the two halves at the end.

A Python implementation of this 6-round NataSHA block cipher is provided for your convenience in `natasha.py`. It is written in Python 3 and it uses the SHA-1 implementation and string XORing from the PyCryptodome package as a dependence. 

A 2-block plaintext was encrypted in ECB mode (i.e., the 2 blocks were encrypted independently, one after the other) with an unknown key, and the resulting ciphertext in hex format is:

    ae055b48d8fa60bc337ff846ee88fe33c7e026a5ea54dbb59814c68265540cef1c183ef746553686
    8c4febe7e2f0a6d43110d37576535b8518eaa4b7ce3ac3722816062755aa8b5ed82eadf76e8af6f5

We somehow learned that the first plaintext block in ASCII is (without apostrophes):

    'Meet_NataSHA_which_is_not_a_SHA_although'

What could be the second block?
