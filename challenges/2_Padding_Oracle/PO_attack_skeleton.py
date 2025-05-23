from oracle import oracle

PADDING_ERROR = True
PADDING_OK = False

__TODO_1__ = b'\x00'
__TODO_2__ = b'\x00'
__TODO_3__ = 0
__TODO_4__ = 0
__TODO_5__ = 0

# This is the ciphertext block that we want to break
Y_hex = '5f8043943189c3a3c3e6bd0d2237f73f'
Y = bytes.fromhex(Y_hex)

# We always send a message of 2 blocks to the oracle:
# - the first block is a block R that we control
# - the second block is the ciphertext block Y we want to break

# We change the last byte of the controlled block R until we get correct padding
# (the other bytes of the controlled block can be anything, for instance, all bytes can be 0)

R = b'\x00' * 16 # recall that the AES block size is 16 bytes
while oracle(R + Y) == PADDING_ERROR: 
    r = (R[-1]+1).to_bytes(1, 'big') # value of the last byte of R is incremented
    R = R[:-1]+r                     # and we put it back into the controlled block R

# At this point, we know that the padding was correct when sending in R+Y
# However, we don't know the length of the resulting padding...
# So we determine the padding length here

for i in range(16): # We will change every byte in R, until we get a padding error again
    S = R[:i] + b'\xFF' + R[i+1: ]  # We implement the byte change by simply setting the i-th byte of R to FF
    if oracle(S+Y) == PADDING_ERROR: # When we get an error, the just modified byte must be the first padding byte
        plen = 16-i                  # so essentially we can determine the padding length plen
        break

# Once we know the padding length, we also know the padding itself encounterd by the oracle
# as we know that the padding scheme used is x80 x00 x00 ... 
# From the controlled block and the known padding bytes, we can compute the last bytes of the plaintext

P = b'\x80' + b'\x00'*(plen-1)                  # this is the padding P seen by the oracle
X = b''
for i in range(plen):                           # We XOR the padding P to the last bytes of the controlled block R
    X += (P[i]^R[-plen+i]).to_bytes(1, 'big')   # and this gives the last bytes of the plaintext X

# We determine the remaining missing bytes iteratively...
while plen < 16: # In each iteration, we will determine 1 more byte out of the missing (16 - plen) bytes
    R = R[:16-plen] + (R[16-plen]^0x80).to_bytes(1, 'big') + R[16-plen+1:]  # We set byte 16-plen of R such that 
                                                                            # in the resulting padding byte 16-plen be x00
    while oracle(R + Y) == PADDING_ERROR:
        r = (R[16-plen-1]+1).to_bytes(1, 'big')     # Then we increment byte 16-plen-1 of R 
        R = R[:16-plen-1] + r + R[16-plen:]         # until we get a correct padding again
        
    X = (r[0] ^ 0x80).to_bytes(1, 'big') + X  # This allows for determining a new byte of X
    plen += 1

# We are done: we decoded the entire plaintext block X
print("Plaintext block recovered: " + X.hex() + " (ASCII: " + X.decode('ascii') + ")")
