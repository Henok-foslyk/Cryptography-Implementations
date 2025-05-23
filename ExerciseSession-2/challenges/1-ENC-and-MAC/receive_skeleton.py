import sys
from Crypto.Cipher import AES
from Crypto.Hash import SHA256, HMAC
from Crypto.Util import Padding

statefile = 'rcvstate.txt'
inputfile = 'message.bin' 
outputfile = 'payload_received.txt'

# TODO: read the content of the state file
with open(statefile, 'rt') as sf:
    enckey = bytes.fromhex(sf.readline()[len("enckey: "):len("enckey: ")+32]) # type should be byte string
    mackey = bytes.fromhex(sf.readline()[len("mackey: "):len("mackey: ")+32]) # type should be byte string
    rcvsqn = int(sf.readline()[len("rcvsqn: "):], base=10) # type should be integer


# read the content of the input file into variable msg
with open(inputfile, 'rb') as inf:
    msg = inf.read()

# TODO: set the header_length, iv_length, and mac_length
header_length = 9
iv_length = 16
mac_length = 32

# parse the message msg
header = msg[0:header_length]
iv = msg[header_length:header_length+iv_length]
mac = msg[-mac_length:]
encrypted_payload = msg[header_length+iv_length:-mac_length]    # encrypted payload is between iv and mac

# TODO: parse the header
header_version_field = header[0:2]  # version is encoded on 2 bytes 
header_type_field = header[2:3]     # type is encoded on 1 byte 
header_length_field = header[3:5]   # msg length is encoded on 2 bytes 
header_sqn_field = header[5:9]      # msg sqn is encoded on 4 bytes 

print("Message header:")
print("   - protocol version: " + header_version_field.hex() + " (" + str(header_version_field[0]) + "." + str(header_version_field[1]) + ")")
print("   - message type: " + header_type_field.hex() + " (" + str(int.from_bytes(header_type_field, byteorder='big')) + ")")
print("   - message length: " + header_length_field.hex() + " (" + str(int.from_bytes(header_length_field, byteorder='big')) + ")")
print("   - message sequence number: " + header_sqn_field.hex() + " (" + str(int.from_bytes(header_sqn_field, byteorder='big')) + ")")

# TODO: check the msg length
if len(msg) != header_length + iv_length + len(encrypted_payload) + mac_length:
    print("Warning: Message length value in header is wrong!")
    print("Processing is continued nevertheless...")

# TODO: check the sequence number
print("Expecting sequence number " + str(rcvsqn + 1) + " or larger...")
sndsqn = int(header_sqn_field.hex())
if (sndsqn < rcvsqn):
    print("Error: Message sequence number is too old!")
    print("Processing completed.")
    sys.exit(1)    
print("Sequence number verification is successful.")

# TODO: verify the mac
print("MAC verification is being performed...")
MAC = HMAC.new(mackey, digestmod=SHA256)
MAC.update(header + iv + encrypted_payload)
computed_mac = MAC.digest()
print("MAC value received: " + mac.hex())
print("MAC value computed: " + computed_mac.hex())
if (mac != computed_mac):
    print("Error: MAC verification failed!")
    print("Processing completed.")
    sys.exit(1)
print("MAC verified correctly.")

# TODO: decrypt the encrypted payload and remove padding
print("Decryption is attempted...")
ENC = AES.new(enckey, AES.MODE_CBC)
try:
    padded_payload = ENC.decrypt(encrypted_payload)
    payload = Padding.unpad(padded_payload, AES.block_size, style='iso7816')
except Exception as e:
    print("Error: Decryption failed!")
    print("Processing completed.")
    sys.exit(1)
print("Decryption was successful.")

# write the payload out
with open(outputfile, 'wb') as outf:
    outf.write(payload)
print("Payload is saved to " + outputfile)

# TODO: save state
state =  "enckey: " + enckey.hex() + '\n'
state += "mackey: " + mackey.hex() + '\n'
state += "rcvsqn: " + str(rcvsqn )
with open(statefile, 'wt') as sf:
    sf.write(state)
print("Receiving state is saved.")
print("Processing completed.")
