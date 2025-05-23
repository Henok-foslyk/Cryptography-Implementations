import sys, getopt
from Crypto.Cipher import AES
from Crypto.Util import Padding

key_hex = ''
inputfile = ''
outputfile = ''

try:
    opts, args = getopt.getopt(sys.argv[1:],'hk:i:o:')
except getopt.GetoptError:
    print('Usage: aes_cbc_dec.py -k <key in hex> -i <inputfile> -o <outputfile>')
    sys.exit(2)

for opt, arg in opts:
    if opt == '-h':
        print('Usage: aes_cbc_dec.py -k <key in hex> -i <inputfile> -o <outputfile>')
        sys.exit()
    elif opt == '-k':
        key_hex = arg
    elif opt == '-i':
        inputfile = arg
    elif opt == '-o':
        outputfile = arg

if len(key_hex) != 32:
    print('Error: Key must be 16 bytes long.')
    sys.exit(2)

if len(inputfile) == 0:
    print('Error: Name of input file is missing.')
    sys.exit(2)

if len(outputfile) == 0:
    print('Error: Name of output file is missing.')
    sys.exit(2)

# decryption
print('Decrypting...', end='')

# read the IV into IV and the ciphertext from the input file
ifile = open(inputfile, 'rb')
iv = ifile.read(AES.block_size)
ct = ifile.read()
ifile.close()

# create AES cipher object
cipher = AES.new(bytes.fromhex(key_hex), AES.MODE_CBC, iv)	
	
# decrypt the ciphertext and remove padding
ppt = cipher.decrypt(ct)
pt = Padding.unpad(ppt, AES.block_size, style='iso7816')
	
# write out the plaintext into the output file
ofile = open(outputfile, "wb")
ofile.write(pt)
ofile.close()
	
print('Done.')

