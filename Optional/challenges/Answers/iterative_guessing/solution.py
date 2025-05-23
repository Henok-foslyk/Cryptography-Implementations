import datetime
from Crypto.Cipher import AES
from Crypto.Hash import MD5, SHA256, HMAC
from Crypto.Util.strxor import strxor

def prng_generate(state, timestamp_bytes):
    h = MD5.new()
    h.update(strxor(state, timestamp_bytes))
    output = h.digest()
    new_state = strxor(state, output)
    return output, new_state

def generate_candidate_timestamps(base_time, window_minutes=10):
    candidates = []
    base_dt = datetime.datetime.strptime(base_time, "%Y%m%d%H%M%S")
    
    for delta in range(-window_minutes * 60,0):
        candidate_dt = base_dt + datetime.timedelta(seconds=delta)
        for centisecond in range(0, 100): 
            timestamp_str = candidate_dt.strftime("%Y%m%d%H%M%S") + f"{centisecond:02d}"
            candidates.append(timestamp_str.encode('ascii'))
    
    return candidates

def parse_message(file_path):
    with open(file_path, 'rb') as f:
        msg = f.read()
    header = msg[:9]
    iv = msg[9:25]
    mac = msg[-32:]
    encrypted_payload = msg[25:-32]

    return header, iv, encrypted_payload, mac

def verify_mac(mackey, header, iv, encrypted_payload, mac):
    """Verify the MAC using HMAC and SHA256."""
    h = HMAC.new(mackey, digestmod=SHA256)
    h.update(header)
    h.update(iv)
    h.update(encrypted_payload)
    try:
        h.verify(mac)  # This will raise an exception if the MAC does not match
        return True, mackey.hex()
    except ValueError:
        return False, "mackey NOT found"
    

def decrypt_payload(enckey, iv, encrypted_payload):
    cipher = AES.new(enckey, AES.MODE_CBC, iv)
    decrypted = cipher.decrypt(encrypted_payload)
    if b'\x80' in decrypted:
        decrypted = decrypted.rstrip(b'\x00')
        if decrypted.endswith(b'\x80'):
            decrypted = decrypted[:-1]
    return decrypted

if __name__ == "__main__":
    initial_state = bytes.fromhex("b5562ff25e66e602eae4dbd61b2d5e8b")
    message_file = "message.bin"
    header, iv, encrypted_payload, mac = parse_message(message_file)

    base_time = "20220319121000"  # March 19, 2022, 12:10:00:00 PM
    candidate_timestamps = generate_candidate_timestamps(base_time)

    for candidate in candidate_timestamps:
        mackey, new_state = prng_generate(initial_state, candidate)
        mac_verified, mackey_val = verify_mac(mackey, header, iv, encrypted_payload, mac)
        if mac_verified:
            mac_timestamp_bytes = candidate
            break
    mac_timestamp_str = mac_timestamp_bytes.decode()
    mackey, new_state = prng_generate(initial_state, mac_timestamp_bytes)

    start_dt = datetime.datetime.strptime("20220319120923", "%Y%m%d%H%M%S")

    for sec_offset in range(0, 38): 
        current_time = start_dt + datetime.timedelta(seconds=sec_offset)
        for cc in range(0, 100):
            timestamp_str = current_time.strftime("%Y%m%d%H%M%S") + f"{cc:02d}"
            if timestamp_str <= mac_timestamp_str:
                continue 
            enc_timestamp_bytes = timestamp_str.encode('ascii')
            enckey, _ = prng_generate(new_state, enc_timestamp_bytes)
            decrypted = decrypt_payload(enckey, iv, encrypted_payload)
            if b"FLAG" in decrypted:
                print(decrypted.decode())
                break
