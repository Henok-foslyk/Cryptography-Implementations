import sys, getopt, getpass
import json
from base64 import b64encode, b64decode
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Signature import PKCS1_PSS
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Util import Padding
from Crypto import Random

# ------ UTILS ------

def save_publickey(pubkey, pubkeyfile):
    with open(pubkeyfile, 'wb') as f:
        f.write(pubkey.export_key(format='PEM'))

def load_publickey(pubkeyfile):
    with open(pubkeyfile, 'rb') as f:
        pubkeystr = f.read()
    try:
        return RSA.import_key(pubkeystr)
    except ValueError:
        print('Error: Cannot import public key from file ' + pubkeyfile)
        sys.exit(1)

def save_keypair(keypair, privkeyfile):
    # passphrase = input('Enter a passphrase to protect the saved private key: ')
    passphrase = getpass.getpass('Enter a passphrase to protect the saved private key: ')
    with open(privkeyfile, 'wb') as f:
        f.write(keypair.export_key(format='PEM', passphrase=passphrase))

def load_keypair(privkeyfile):
    #passphrase = input('Enter a passphrase to decode the saved private key: ')
    passphrase = getpass.getpass('Enter a passphrase to decode the saved private key: ')
    with open(privkeyfile, 'rb') as f:
        keypairstr = f.read()
    try:
        return RSA.import_key(keypairstr, passphrase=passphrase)
    except ValueError:
        print('Error: Cannot import private key from file ' + privkeyfile)
        sys.exit(1)

# ----------------------------------
# processing command line parameters
# ----------------------------------

operation = ''
pubkeyfile = ''
privkeyfile = ''
inputfile = ''
outputfile = ''
sign = False

try:
    opts, args = getopt.getopt(sys.argv[1:], 'hkedp:s:i:o:')
except getopt.GetoptError:
    print('Usage:')
    print('  - RSA key pair generation:')
    print('    hybrid.py -k -p <pubkeyfile> -s <privkeyfile>')
    print('  - encryption with optional signature generation:')
    print('    hybrid.py -e -p <pubkeyfile> [-s <privkeyfile>] -i <inputfile> -o <outputfile>')
    print('  - decryption with optional signature verification:')
    print('    hybrid.py -d -s <privkeyfile> [-p <pubkeyfile>] -i <inputfile> -o <outputfile>')
    sys.exit(1)

for opt, arg in opts:
    if opt == '-h':
        print('Usage:')
        print('  - RSA key pair generation:')
        print('    hybrid.py -k -p <pubkeyfile> -s <privkeyfile>')
        print('  - encryption with optional signature generation:')
        print('    hybrid.py -e -p <pubkeyfile> [-s <privkeyfile>] -i <inputfile> -o <outputfile>')
        print('  - decryption with optional signature verification:')
        print('    hybrid.py -d -s <privkeyfile> [-p <pubkeyfile>] -i <inputfile> -o <outputfile>')
        sys.exit(0)
    elif opt == '-k':
        operation = 'kpg'
    elif opt == '-e':
        operation = 'enc'    
    elif opt == '-d':
        operation = 'dec'    
    elif opt == '-p':
        pubkeyfile = arg
    elif opt == '-s':
        privkeyfile = arg
    elif opt == '-i':
        inputfile = arg
    elif opt == '-o':
        outputfile = arg

if not operation:
    print('Error: Operation must be -k (for key pair generation) or -e (for encryption) or -d (for decryption).')
    sys.exit(1)
    
if (not pubkeyfile) and (operation == 'enc' or operation == 'kpg'):
    print('Error: Name of the public key file is missing.')
    sys.exit(1)

if (not privkeyfile) and (operation == 'dec' or operation == 'kpg'):
    print('Error: Name of the private key file is missing.')
    sys.exit(1)

if (not inputfile) and (operation == 'enc' or operation == 'dec'):
    print('Error: Name of input file is missing.')
    sys.exit(1)

if (not outputfile) and (operation == 'enc' or operation == 'dec'):
    print('Error: Name of output file is missing.')
    sys.exit(1)

if (operation == 'enc') and privkeyfile: 
    sign = True

# -------------------
# key pair generation
# -------------------

if operation == 'kpg': 
    print('Generating a new 2048-bit RSA key pair...')
    #TODO: Generate a new 2048-bit RSA key pair
    keypair = RSA.generate(2048)

    #TODO: Save the public part of the key pair in pubkeyfile
    save_publickey(keypair.publickey(), pubkeyfile)

    #Save the entire key pair in privkeyfile
    save_keypair(keypair, privkeyfile)
    print('Done.')

# ----------
# encryption
# ----------

elif operation == 'enc': 
    print('Encrypting...')

    #TODO: Load the public key from pubkeyfile and 
    #      create an RSA cipher object
    pubkey = load_publickey(pubkeyfile)
    RSAcipher =  PKCS1_OAEP.new(pubkey)

    #TODO: Generate a random symmetric key and create an AES cipher object in CBC mode
    symkey = generate_random_bytes(32)
    AEScipher = AES.new(symkey, AES.MODE_CBC)

    #TODO: Store the IV of the AES cipher object in a variable (you'll need it later) 
    iv = AEScipher.iv

    # read the plaintext from the input file
    with open(inputfile, 'rb') as f: 
        plaintext = f.read()

    #TODO: Apply PKCS7 padding on the plaintext (we want to use AES)
    padded_plaintext = Padding.pad(plaintext, AES.block_size, style='pkcs7')
	
    #TODO: Encrypt the padded plaintext with the AES cipher
    ciphertext = AEScipher.encrypt(padded_plaintext)

    #TODO: Encrypt the AES key with the RSA cipher
    encsymkey = RSAcipher.encrypt(symkey)

    # compute signature if needed
    #TODO: Inspect the code to understand how to generate a signature... 
    if sign:
        keypair = load_keypair(privkeyfile)
        signer = PKCS1_PSS.new(keypair)
        hashfn = SHA256.new()
        hashfn.update(encsymkey+iv+ciphertext)
        signature = signer.sign(hashfn)

    # create a dictionary to store the encrypted AES key, the IV, the ciphertext, and the signature
    hybrid_struct = {}
    hybrid_struct['ENCRYPTED AES KEY'] = b64encode(encsymkey).decode('ascii')
    hybrid_struct['IV FOR CBC MODE'] = b64encode(iv).decode('ascii')
    hybrid_struct['CIPHERTEXT'] = b64encode(ciphertext).decode('ascii')
    if sign: hybrid_struct['SIGNATURE'] = b64encode(signature).decode('ascii')

    # write out the dictionary in json format
    with open(outputfile, 'w') as f:
        f.write(json.dumps(hybrid_struct))

    print('Done.')

# ----------
# decryption
# ----------

elif operation == 'dec':
    print('Decrypting...')

    # read and parse the input
    #TODO: Inspect the code to understand how the different parts of the ciphertext
    #      are recognized and decoded from the json structure... 

    encsymkey = b''
    iv = b''
    ciphertext = b''
    signature = b''
    sign = False

    with open(inputfile, 'r') as f: 
        hybrid_struct = json.loads(f.read())

    if 'ENCRYPTED AES KEY' in hybrid_struct:
        encsymkey = b64decode(hybrid_struct['ENCRYPTED AES KEY'].encode('ascii'))
    if 'IV FOR CBC MODE' in hybrid_struct:
        iv = b64decode(hybrid_struct['IV FOR CBC MODE'].encode('ascii'))
    if 'CIPHERTEXT' in hybrid_struct:
        ciphertext = b64decode(hybrid_struct['CIPHERTEXT'].encode('ascii'))
    if 'SIGNATURE' in hybrid_struct:
        signature = b64decode(hybrid_struct['SIGNATURE'].encode('ascii'))
        sign = True

    if (not encsymkey) or (not iv) or (not ciphertext):
        print('Error: Could not parse content of input file ' + inputfile)
        sys.exit(1)

    if sign and (not pubkeyfile):
        print('Error: Public key file is missing, signature cannot be verified.')
        sys.exit(1)

    # verify signature if needed...
    if sign:
        pubkey = load_publickey(pubkeyfile)
        verifier = PKCS1_PSS.new(pubkey)
        h = SHA256.new()
        h.update(encsymkey+iv+ciphertext)
        if verifier.verify(h, signature):
            print('Signature is valid')

        #TODO: Write the signature verification code here...
        #      - load the public key from pubkeyfile
        #      - create an RSA PSS verifier object
        #      - create a SHA256 object
        #      - hash encsymkey+iv+ciphertext with SHA256
        #      - call the verify function of the verifier object in a try clause
        #      - if the signature is valid, then print a success message and go on
        #      - if the signature is invalid, then print and error message, and then  
        #        ask the user if he/she wants to continue nevertheless
        #if ...
        else:
            print('Signature verification is failed.')
            yn = input('Do you want to continue (y/n)? ')
            if yn != 'y': 
                sys.exit(1)

    #TODO:Load the private key (key pair) from privkeyfile and 
    #     create the RSA cipher object
    keypair = load_keypair(privkeyfile)
    RSAcipher = PKCS1_OAEP.new(keypair)

    #TODO: decrypt the AES key with RSAcipher
    try:
        symkey = RSAcipher.decrypt(encsymkey)
    except ValueError:
        print('Error: Decryption of AES key is failed.')
        sys.exit(1)

    # TODO: create the AES cipher object
    AEScipher = AES.new(symkey, AES.MODE_CBC, iv)
    
    #TODO: Decrypt the ciphertext and remove padding
    try:
        padded_plaintext = AEScipher.decrypt(ciphertext)
        plaintext = Padding.unpad(padded_plaintext, AES.block_size, style="pkcs7")
    except ValueError:
        print('Error: Decryption of the ciphertext is failed.')
        sys.exit(1)

    # write out the plaintext into the output file
    with open(outputfile, 'wb') as f:
        f.write(plaintext)
	
    print('Done.')
