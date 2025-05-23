import sys, getopt
from Crypto.Hash import MD5
from Crypto.Util.strxor import strxor

statefile = "prngstate.txt"
prnginput = ""

try:
    opts, args = getopt.getopt(sys.argv[1:],'hi:')
except getopt.GetoptError:
    print("Usage: prng.py -i <16-byte input string>")
    sys.exit(2)

for opt, arg in opts:
    if opt == '-h':
        print("Usage: prng.py -i <16-byte input string>")
        sys.exit()
    elif opt == '-i':
        prnginput = arg.encode('ascii')

if len(prnginput) != 16:
    print("Error: Input length is not 16 bytes.")
    sys.exit(2)

# read the content of the state file
ifile = open(statefile, 'r')
line = ifile.readline()
prngstate = bytes.fromhex(line[len("prngstate: "):len("prngstate: ")+32])
ifile.close()

# compute output and next state
H = MD5.new()
H.update(strxor(prnginput, prngstate))
prngoutput = H.digest()
prngstate = strxor(prngstate, prngoutput)

# save state
ofile = open(statefile, 'w')
ofile.write("prngstate: " + prngstate.hex())
ofile.close()

#print output
print(prngoutput.hex())
