from Crypto.Cipher import AES
from Crypto.Hash import SHA256, HMAC
from Crypto.Util import Padding

statefile = 'sndstate.txt'
inputfile = 'payload_to_send.txt'
outputfile = 'message.bin' 

# read the content of the state file
with open(statefile, 'rt') as sf:
    enckey = bytes.fromhex(sf.readline()[len("enckey: "):len("enckey: ")+32]) # type should be byte string
    mackey = bytes.fromhex(sf.readline()[len("mackey: "):len("mackey: ")+32]) # type should be byte string
    sndsqn = int(sf.readline()[len("sndsqn: "):], base=10) # type should be integer

# read the content of the input file into payload
with open(inputfile, 'rb') as inf:
    payload = inf.read()

# pad the payload using the ISO 7816 padding scheme
padded_payload = Padding.pad(payload, AES.block_size, style='iso7816')

# compute payload_length and padding_length
payload_length = len(payload)
padding_length = len(padded_payload) - payload_length

# set mac_length to 32 bytes
#    as SHA256 hash value is 32 bytes long
mac_length = 32  

# set header length to 9 bytes
#    version: 2 bytes
#    type:    1 btye
#    length:  2 btyes
#    sqn:     4 bytes
header_length = 9

# set iv_length to the AES block size
iv_length = AES.block_size

# compute message length...
msg_length = header_length + iv_length + payload_length + padding_length + mac_length

# create header
header_version_field = b'\x03\x06'                            # protocol version 3.6
header_type_field = b'\x01'                                   # message type 1
header_length_field = msg_length.to_bytes(2, byteorder='big') # message length (encoded on 2 bytes)
header_sqn_field = (sndsqn + 1).to_bytes(4, byteorder='big')  # next message sequence number (encoded on 4 bytes)
header = header_version_field + header_type_field + header_length_field + header_sqn_field 

# create an AES cipher in CBC mode
ENC = AES.new(enckey, AES.MODE_CBC)
iv = ENC.iv

# encrypt the padded payload
encrypted_payload = ENC.encrypt(padded_payload)

# create a MAC function using HMAC with SHA256
MAC = HMAC.new(mackey, digestmod=SHA256)

# compute the mac on the header, iv, and encrypted payload
MAC.update(header + iv + encrypted_payload)
mac = MAC.digest()

# write out the header, iv, encrypted payload, and the mac
with open(outputfile, 'wb') as outf:
    outf.write(header + iv + encrypted_payload + mac)

# save state
state =  "enckey: " + enckey.hex() + '\n'
state += "mackey: " + mackey.hex() + '\n'
state += "sndsqn: " + str(sndsqn + 1)
with open(statefile, 'wt') as sf:
    sf.write(state)
